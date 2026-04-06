import hashlib
import html
import hmac
import io
import json
import os
import zipfile
from pathlib import Path
from threading import Lock

import qrcode
from PIL import Image, ImageDraw, ImageFont
from flask import (
    Flask,
    Response,
    jsonify,
    redirect,
    request,
    send_file,
    send_from_directory,
    session,
    url_for,
)


APP_ROOT = Path(__file__).resolve().parent


def load_dotenv_file(dotenv_path, override=True):
    if not dotenv_path.exists():
        return

    for raw_line in dotenv_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        if override or key not in os.environ:
            os.environ[key] = value


def normalize_domain(value):
    cleaned = (value or "").strip().rstrip("/")
    if cleaned and "://" not in cleaned:
        return f"http://{cleaned}"
    return cleaned


def configured_data_root():
    raw_path = (os.getenv("DATA_DIR") or "").strip()
    if not raw_path:
        return APP_ROOT
    return Path(raw_path).expanduser().resolve()


load_dotenv_file(APP_ROOT / ".env")

app = Flask(__name__, static_folder="static", static_url_path="/static")

SECRET_KEY = os.getenv("QR_SECRET", "replace-this-with-a-long-secret-key")
SUPERADMIN_PASSWORD = "22012004"
SUPERADMIN_SESSION_KEY = "superadmin_logged_in"
QR_256_KEY_ENV = "QR_256_KEY"
CIPHER_CODE_LENGTH = 64
DATA_ROOT = configured_data_root()
STATE_FILE = DATA_ROOT / "qr_state.json"
OUTPUT_ROOT = DATA_ROOT / "generated_qr"
MANIFEST_FILE = OUTPUT_ROOT / "manifest.json"
STATE_LOCK = Lock()
TOKEN_VERSION = "1"

app.secret_key = hashlib.sha256(f"{SECRET_KEY}-session".encode("utf-8")).hexdigest()


def configured_domain_name():
    load_dotenv_file(APP_ROOT / ".env", override=True)
    return normalize_domain(os.getenv("DOMAIN_NAME", ""))


def current_cipher_code():
    load_dotenv_file(APP_ROOT / ".env", override=True)
    return str(os.getenv(QR_256_KEY_ENV, "")).strip()


def cipher_key_error():
    return f"{QR_256_KEY_ENV} must be exactly {CIPHER_CODE_LENGTH} characters in .env"


def empty_state():
    return {
        "total_qr": 0,
        "true_count": 0,
        "next_serial": 1,
        "output_dir": str(OUTPUT_ROOT.resolve()),
        "manifest_file": str(MANIFEST_FILE.resolve()),
    }


def read_json_file(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def load_manifest():
    manifest = read_json_file(MANIFEST_FILE)
    return manifest if isinstance(manifest, list) else []


def save_manifest(items):
    MANIFEST_FILE.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST_FILE.write_text(json.dumps(items, indent=2), encoding="utf-8")


def normalize_state(state):
    baseline = empty_state()
    if not isinstance(state, dict):
        return baseline

    total_qr = int(state.get("total_qr", 0) or 0)
    true_count = int(state.get("true_count", 0) or 0)
    true_count = max(true_count, 0)
    total_qr = max(total_qr, 0)

    manifest = load_manifest()
    if manifest:
        manifest_total = len(manifest)
        total_qr = max(total_qr, manifest_total)
        max_serial = 0
        for item in manifest:
            if isinstance(item, dict):
                max_serial = max(max_serial, int(item.get("serial", 0) or 0))
        next_serial = max_serial + 1 if max_serial > 0 else total_qr + 1
    else:
        next_serial = int(state.get("next_serial", 0) or 0)
        if next_serial <= 0:
            next_serial = total_qr + 1

    normalized = {
        "total_qr": total_qr,
        "true_count": min(true_count, total_qr) if total_qr > 0 else true_count,
        "next_serial": max(next_serial, 1),
        "output_dir": str(OUTPUT_ROOT.resolve()),
        "manifest_file": str(MANIFEST_FILE.resolve()),
    }
    return normalized


def load_state():
    raw = read_json_file(STATE_FILE) if STATE_FILE.exists() else {}
    state = normalize_state(raw)
    save_state(state)
    return state


def save_state(state):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(normalize_state(state), indent=2), encoding="utf-8")


def build_keystream(secret, length):
    seed = hashlib.sha256(secret.encode("utf-8")).digest()
    stream = bytearray()
    counter = 0
    while len(stream) < length:
        block = hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        stream.extend(block)
        counter += 1
    return bytes(stream[:length])


def xor_bytes(data, key):
    return bytes(left ^ right for left, right in zip(data, key))


def create_token(serial):
    code = current_cipher_code()
    if len(code) != CIPHER_CODE_LENGTH:
        raise ValueError(cipher_key_error())

    plain = f"{TOKEN_VERSION}|{serial:08d}|{code}".encode("utf-8")
    key_stream = build_keystream(code, len(plain))
    return xor_bytes(plain, key_stream).hex()


def decode_token(token_hex):
    code = current_cipher_code()
    if len(code) != CIPHER_CODE_LENGTH:
        return None

    try:
        cipher_bytes = bytes.fromhex(token_hex)
    except ValueError:
        return None

    key_stream = build_keystream(code, len(cipher_bytes))
    try:
        plain = xor_bytes(cipher_bytes, key_stream).decode("utf-8")
    except UnicodeDecodeError:
        return None

    parts = plain.split("|", 2)
    if len(parts) != 3:
        return None

    version, serial_text, plain_code = parts
    if version != TOKEN_VERSION:
        return None
    if not serial_text.isdigit():
        return None
    if not hmac.compare_digest(plain_code, code):
        return None

    serial = int(serial_text)
    if serial <= 0:
        return None

    return {"serial": serial}


def qr_image_with_serial(claim_url, serial):
    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=8,
        border=2,
    )
    qr.add_data(claim_url)
    qr.make(fit=True)

    qr_image = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    saffron = (255, 153, 51)
    green = (19, 136, 8)
    navy = (11, 44, 84)

    def pick_font(size):
        for name in ("arialbd.ttf", "DejaVuSans-Bold.ttf", "arial.ttf", "DejaVuSans.ttf"):
            try:
                return ImageFont.truetype(name, size=size)
            except OSError:
                continue
        return ImageFont.load_default()

    def text_size(drawer, value, font):
        try:
            left, top, right, bottom = drawer.textbbox((0, 0), value, font=font)
            return right - left, bottom - top
        except AttributeError:
            return drawer.textsize(value, font=font)

    serial_label = f"S.No {serial:04d}"
    serial_font_size = max(int(qr_image.height * 0.14), 26)
    serial_font = pick_font(serial_font_size)

    top_band_h = max(int(qr_image.height * 0.16), 44)
    bottom_band_h = top_band_h
    middle_h = qr_image.height + 30
    left_panel_w = max(int(qr_image.width * 1.08), 320)
    right_panel_w = qr_image.width + 56

    card_w = left_panel_w + right_panel_w
    card_h = top_band_h + middle_h + bottom_band_h

    canvas = Image.new("RGB", (card_w, card_h), "white")
    draw = ImageDraw.Draw(canvas)

    draw.rectangle([(0, 0), (card_w, top_band_h)], fill=saffron)
    draw.rectangle([(0, card_h - bottom_band_h), (card_w, card_h)], fill=green)

    middle_top = top_band_h
    middle_bottom = card_h - bottom_band_h

    divider_x = left_panel_w
    for y in range(middle_top + 8, middle_bottom - 8, 12):
        draw.line([(divider_x, y), (divider_x, y + 6)], fill=(170, 177, 186), width=2)

    stripe_x = 24
    draw.rectangle([(stripe_x, middle_top + 10), (stripe_x + 10, middle_bottom - 10)], fill=saffron)
    draw.rectangle([(stripe_x + 20, middle_top + 10), (stripe_x + 30, middle_bottom - 10)], fill=green)

    serial_w, serial_h = text_size(draw, serial_label, serial_font)
    text_x = stripe_x + 56
    available_w = max(divider_x - text_x - 20, 40)
    if serial_w > available_w:
        serial_font = pick_font(max(int(serial_font_size * available_w / serial_w), 18))
        serial_w, serial_h = text_size(draw, serial_label, serial_font)

    text_x = text_x + max((available_w - serial_w) // 2, 0)
    text_y = middle_top + max((middle_h - serial_h) // 2, 0)
    draw.text((text_x, text_y), serial_label, fill=navy, font=serial_font)

    qr_x = left_panel_w + (right_panel_w - qr_image.width) // 2
    qr_y = middle_top + (middle_h - qr_image.height) // 2
    canvas.paste(qr_image, (qr_x, qr_y))
    return canvas


def current_base_url():
    configured = configured_domain_name()
    if configured:
        return configured

    payload = request.get_json(silent=True) or {}
    requested = payload.get("base_url") or request.form.get("base_url") or request.args.get("base_url")
    if requested:
        return normalize_domain(requested)
    return request.host_url.rstrip("/")


def current_count(explicit_count=None):
    if explicit_count is not None:
        return explicit_count

    payload = request.get_json(silent=True) or {}
    raw_count = payload.get("count") or request.form.get("count") or request.args.get("count")
    if raw_count is None:
        raise ValueError("count is required")
    return int(raw_count)


def scan_payload(success, state, message, serial=None):
    total = int(state.get("total_qr", 0) or 0)
    count = int(state.get("true_count", 0) or 0)
    return jsonify(
        {
            "true": success,
            "count": count,
            "total": total,
            "remaining": max(total - count, 0),
            "over": total > 0 and count >= total,
            "message": message,
            "serial": serial,
        }
    )


def build_claim_page(token_hex):
    post_url = f"/s/{token_hex}"
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>QR Scan</title>
  <style>
    body {{
      font-family: monospace;
      max-width: 720px;
      margin: 40px auto;
      padding: 0 16px;
      line-height: 1.5;
    }}
    pre {{
      white-space: pre-wrap;
      word-break: break-word;
      background: #f4f4f4;
      border-radius: 12px;
      padding: 16px;
    }}
  </style>
</head>
<body>
  <h1>Checking QR...</h1>
  <pre id="result">Submitting empty POST request...</pre>
  <script>
    fetch({json.dumps(post_url)}, {{ method: "POST" }})
      .then((response) => response.json())
      .then((data) => {{
        document.getElementById("result").textContent = JSON.stringify(data, null, 2);
      }})
      .catch((error) => {{
        document.getElementById("result").textContent = JSON.stringify(
          {{ true: false, message: String(error) }},
          null,
          2
        );
      }});
  </script>
</body>
</html>"""


def serve_frontend_index():
    index_file = Path(app.static_folder) / "index.html"
    if index_file.exists():
        return send_from_directory(app.static_folder, "index.html")
    return None


def is_superadmin_authenticated():
    return bool(session.get(SUPERADMIN_SESSION_KEY))


def build_superadmin_login_page(next_path="/superadmin", error_message=""):
    safe_next = str(next_path or "/superadmin")
    if not safe_next.startswith("/superadmin"):
        safe_next = "/superadmin"

    safe_next_query = html.escape(safe_next, quote=True)
    safe_error = html.escape(error_message or "", quote=False)
    error_block = f'<p class="error">{safe_error}</p>' if safe_error else ""

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Superadmin Login</title>
  <style>
    :root {{
      --ink: #11233a;
      --muted: #4b5d73;
      --line: rgba(20, 34, 55, 0.16);
      --card: rgba(255, 255, 255, 0.92);
      --accent: #0b75b7;
      --bg1: #fff6dd;
      --bg2: #e3f3ff;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      padding: 20px;
      color: var(--ink);
      font-family: "Avenir Next", "Segoe UI", sans-serif;
      background:
        radial-gradient(80% 60% at 0% 0%, #fff5d3 0%, transparent 65%),
        radial-gradient(70% 80% at 100% 100%, #d9eeff 0%, transparent 70%),
        linear-gradient(155deg, var(--bg1), var(--bg2));
    }}
    .card {{
      width: min(430px, 100%);
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 18px;
      padding: 18px;
      box-shadow: 0 14px 26px rgba(19, 47, 74, 0.09);
    }}
    h1 {{
      margin: 0 0 8px;
      font-size: 1.4rem;
      line-height: 1.2;
    }}
    p {{
      margin: 0 0 12px;
      color: var(--muted);
    }}
    label {{
      display: block;
      font-size: 0.87rem;
      color: var(--muted);
      margin-bottom: 7px;
    }}
    input {{
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 11px 12px;
      font: inherit;
      color: var(--ink);
      margin-bottom: 10px;
    }}
    button {{
      width: 100%;
      border: 0;
      border-radius: 12px;
      padding: 11px 14px;
      color: #fff;
      font: inherit;
      font-weight: 700;
      background: linear-gradient(120deg, var(--accent), #1d92cf);
      cursor: pointer;
    }}
    .error {{
      color: #ad2e2c;
      background: #ffeceb;
      border: 1px solid #f1b0ad;
      border-radius: 10px;
      padding: 9px 10px;
      margin-bottom: 10px;
    }}
  </style>
</head>
<body>
  <form class="card" method="post" action="/superadmin?next={safe_next_query}">
    <h1>Superadmin Login</h1>
    <p>Enter password to open the dashboard.</p>
    {error_block}
    <label for="password">Password</label>
    <input id="password" name="password" type="password" autocomplete="current-password" required autofocus />
    <button type="submit">Open Dashboard</button>
  </form>
</body>
</html>"""


@app.after_request
def disable_api_caching(response):
    if request.path.startswith(
        (
            "/generate",
            "/status",
            "/scan",
            "/s",
            "/c",
            "/claim",
            "/manifest.json",
            "/qr/",
            "/download.zip",
            "/superadmin",
        )
    ):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


@app.get("/")
def index():
    frontend = serve_frontend_index()
    if frontend is not None:
        return frontend

    state = load_state()
    return jsonify(
        {
            "message": "Flask QR local one-time scan service",
            "generate_examples": [
                "GET /generate/10",
                "POST /generate with JSON: {\"count\": 10}",
            ],
            "domain_name": configured_domain_name(),
            "status_url": "/status",
            "count": state.get("true_count", 0),
            "total": state.get("total_qr", 0),
            "over": state.get("total_qr", 0) > 0 and state.get("true_count", 0) >= state.get("total_qr", 0),
            "output_dir": state.get("output_dir"),
            "manifest_file": state.get("manifest_file"),
        }
    )


@app.route("/superadmin", methods=["GET", "POST"])
def superadmin():
    requested_next = request.args.get("next", "/superadmin")

    if request.method == "POST":
        payload = request.get_json(silent=True) or {}
        password = (request.form.get("password") or payload.get("password") or "").strip()

        if hmac.compare_digest(password, SUPERADMIN_PASSWORD):
            session[SUPERADMIN_SESSION_KEY] = True
            safe_next = requested_next if str(requested_next).startswith("/superadmin") else "/superadmin"
            return redirect(safe_next)

        return (
            Response(
                build_superadmin_login_page(
                    next_path=requested_next,
                    error_message="Wrong password",
                ),
                mimetype="text/html",
            ),
            401,
        )

    if not is_superadmin_authenticated():
        return Response(
            build_superadmin_login_page(next_path=requested_next),
            mimetype="text/html",
        )

    frontend = serve_frontend_index()
    if frontend is not None:
        return frontend
    return jsonify({"true": False, "message": "frontend not built"}), 404


@app.get("/superadmin/logout")
def superadmin_logout():
    session.pop(SUPERADMIN_SESSION_KEY, None)
    return redirect(url_for("superadmin"))


@app.get("/superadmin/<path:path>")
def superadmin_spa(path):
    if not is_superadmin_authenticated():
        return redirect(url_for("superadmin", next=f"/superadmin/{path}"))

    frontend = serve_frontend_index()
    if frontend is not None:
        return frontend
    return jsonify({"true": False, "message": "frontend not built"}), 404


@app.route("/generate", methods=["POST"])
@app.route("/generate/<int:count>", methods=["GET"])
def generate(count=None):
    try:
        count = current_count(count)
    except ValueError as exc:
        return jsonify({"true": False, "message": str(exc)}), 400

    if count <= 0:
        return jsonify({"true": False, "message": "count must be greater than 0"}), 400

    if len(current_cipher_code()) != CIPHER_CODE_LENGTH:
        return jsonify({"true": False, "message": cipher_key_error()}), 400

    base_url = current_base_url()
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)

    with STATE_LOCK:
        state = load_state()
        manifest = load_manifest()
        start_serial = int(state.get("next_serial", 1) or 1)

        items = []
        for offset in range(count):
            serial = start_serial + offset
            token_hex = create_token(serial)
            claim_url = f"{base_url}/c/{token_hex}"
            image_url = f"{base_url}/qr/{serial}.png"
            image_path = OUTPUT_ROOT / f"qr_{serial:04d}.png"
            qr_image_with_serial(claim_url, serial).save(image_path)

            item = {
                "serial": serial,
                "hex": token_hex,
                "claim_url": claim_url,
                "image_url": image_url,
                "file": str(image_path.resolve()),
            }
            manifest.append(item)
            items.append(item)

        save_manifest(manifest)
        state["total_qr"] = len(manifest)
        state["next_serial"] = start_serial + count
        state["output_dir"] = str(OUTPUT_ROOT.resolve())
        state["manifest_file"] = str(MANIFEST_FILE.resolve())
        save_state(state)

        return jsonify(
            {
                "true": True,
                "generated": count,
                "start_serial": start_serial,
                "end_serial": start_serial + count - 1,
                "count": state["true_count"],
                "total_qr": state["total_qr"],
                "over": state["total_qr"] > 0 and state["true_count"] >= state["total_qr"],
                "domain_name": base_url,
                "output_dir": state["output_dir"],
                "manifest_file": state["manifest_file"],
                "download_url": f"{base_url}/download.zip",
                "manifest_url": f"{base_url}/manifest.json",
                "items": items,
            }
        )


@app.get("/manifest.json")
def manifest_file():
    if not MANIFEST_FILE.exists():
        return jsonify({"true": False, "message": "manifest not found"}), 404
    return send_file(MANIFEST_FILE, mimetype="application/json")


@app.get("/qr/<int:serial>.png")
def qr_image(serial):
    if serial <= 0:
        return jsonify({"true": False, "message": "invalid serial"}), 400

    image_path = OUTPUT_ROOT / f"qr_{serial:04d}.png"
    if not image_path.exists():
        return jsonify({"true": False, "message": "qr image not found"}), 404
    return send_file(image_path, mimetype="image/png")


@app.get("/download.zip")
def download_zip():
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for image_path in sorted(OUTPUT_ROOT.glob("qr_*.png")):
            zf.write(image_path, arcname=image_path.name)
        if MANIFEST_FILE.exists():
            zf.write(MANIFEST_FILE, arcname="manifest.json")

    archive.seek(0)
    return send_file(
        archive,
        mimetype="application/zip",
        as_attachment=True,
        download_name="generated_qr.zip",
    )


@app.get("/c/<token_hex>")
@app.get("/claim/<token_hex>")
def claim_qr(token_hex):
    frontend = serve_frontend_index()
    if frontend is not None:
        return frontend
    return Response(build_claim_page(token_hex), mimetype="text/html")


@app.post("/s/<token_hex>")
@app.post("/scan/<token_hex>")
def scan_qr(token_hex):
    with STATE_LOCK:
        state = load_state()
        payload = decode_token(token_hex)

        if not payload:
            return scan_payload(False, state, "invalid token")

        serial = int(payload.get("serial", 0) or 0)
        if serial <= 0 or serial > int(state.get("total_qr", 0) or 0):
            return scan_payload(False, state, "serial not generated", serial=serial)

        state["true_count"] = int(state.get("true_count", 0) or 0) + 1
        save_state(state)
        return scan_payload(True, state, "accepted", serial=serial)


@app.get("/status")
def status():
    state = load_state()
    total = int(state.get("total_qr", 0) or 0)
    count = int(state.get("true_count", 0) or 0)

    return jsonify(
        {
            "domain_name": configured_domain_name() or request.host_url.rstrip("/"),
            "total_qr": total,
            "true_count": count,
            "remaining": max(total - count, 0),
            "over": total > 0 and count >= total,
            "output_dir": state.get("output_dir"),
            "manifest_file": state.get("manifest_file"),
        }
    )


if __name__ == "__main__":
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    app.run(host="0.0.0.0", port=5000, debug=False)

import hashlib
import html
import hmac
import io
import json
import os
import secrets
import zipfile
from datetime import datetime, timezone
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


def configured_data_root():
    raw_path = (os.getenv("DATA_DIR") or "").strip()
    if not raw_path:
        return APP_ROOT
    return Path(raw_path).expanduser().resolve()


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


load_dotenv_file(APP_ROOT / ".env")

app = Flask(__name__, static_folder="static", static_url_path="/static")

SECRET_KEY = os.getenv("QR_SECRET", "replace-this-with-a-long-secret-key")
SUPERADMIN_PASSWORD = "22012004"
SUPERADMIN_SESSION_KEY = "superadmin_logged_in"
DATA_ROOT = configured_data_root()
STATE_FILE = DATA_ROOT / "qr_state.json"
OUTPUT_ROOT = DATA_ROOT / "generated_qr"
STATE_LOCK = Lock()
TOKEN_VERSION = 1
BATCH_ID_BYTES = 4
SERIAL_BYTES = 4
NONCE_BYTES = 4
MAC_BYTES = 8
app.secret_key = hashlib.sha256(f"{SECRET_KEY}-session".encode("utf-8")).hexdigest()


def configured_domain_name():
    # Reload .env so edits (like IP/domain changes) are reflected without stale values.
    load_dotenv_file(APP_ROOT / ".env", override=True)
    return normalize_domain(os.getenv("DOMAIN_NAME", ""))


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def empty_state():
    return {
        "active_batch_id": None,
        "total_qr": 0,
        "true_count": 0,
        "used_token_hashes": [],
        "generated_at": None,
        "updated_at": None,
        "output_dir": None,
        "manifest_file": None,
    }


def read_json_file(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def batch_scan_state_file(batch_id):
    return OUTPUT_ROOT / batch_id / "scan_state.json"


def save_batch_scan_state(batch_id, state):
    scan_state = {
        "true_count": int(state.get("true_count", 0) or 0),
        "used_token_hashes": list(state.get("used_token_hashes", [])),
        "updated_at": state.get("updated_at"),
    }
    scan_file = batch_scan_state_file(batch_id)
    scan_file.parent.mkdir(parents=True, exist_ok=True)
    scan_file.write_text(json.dumps(scan_state, indent=2), encoding="utf-8")


def latest_batch_state():
    if not OUTPUT_ROOT.exists():
        return empty_state()

    candidates = []
    for batch_dir in OUTPUT_ROOT.iterdir():
        if not batch_dir.is_dir():
            continue

        batch_id = batch_dir.name
        if len(batch_id) != BATCH_ID_BYTES * 2:
            continue

        try:
            bytes.fromhex(batch_id)
        except ValueError:
            continue

        candidates.append(batch_dir)

    if not candidates:
        return empty_state()

    latest = max(candidates, key=lambda path: path.stat().st_mtime)
    batch_id = latest.name
    manifest_file = latest / "manifest.json"
    manifest_items = read_json_file(manifest_file)
    total_qr = len(manifest_items) if isinstance(manifest_items, list) else 0

    scan_data = read_json_file(batch_scan_state_file(batch_id)) or {}
    used_token_hashes = scan_data.get("used_token_hashes", [])
    if not isinstance(used_token_hashes, list):
        used_token_hashes = []

    true_count = int(scan_data.get("true_count", len(used_token_hashes)) or 0)
    true_count = max(true_count, len(used_token_hashes))

    generated_at = datetime.fromtimestamp(
        manifest_file.stat().st_mtime if manifest_file.exists() else latest.stat().st_mtime,
        tz=timezone.utc,
    ).isoformat()
    updated_at = scan_data.get("updated_at") or generated_at

    return {
        "active_batch_id": batch_id,
        "total_qr": total_qr,
        "true_count": true_count,
        "used_token_hashes": used_token_hashes,
        "generated_at": generated_at,
        "updated_at": updated_at,
        "output_dir": str(latest.resolve()),
        "manifest_file": str(manifest_file.resolve()),
    }


def load_state():
    if STATE_FILE.exists():
        state = read_json_file(STATE_FILE)
        if isinstance(state, dict):
            return state

    recovered_state = latest_batch_state()
    if recovered_state.get("active_batch_id"):
        save_state(recovered_state)
    return recovered_state


def save_state(state):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")


def resolve_batch_dir(batch_id):
    if len(batch_id) != BATCH_ID_BYTES * 2:
        return None

    try:
        bytes.fromhex(batch_id)
    except ValueError:
        return None

    output_root = OUTPUT_ROOT.resolve()
    batch_dir = (OUTPUT_ROOT / batch_id).resolve()

    if output_root not in batch_dir.parents:
        return None
    if not batch_dir.exists() or not batch_dir.is_dir():
        return None
    return batch_dir


def token_fingerprint(token_hex):
    return hashlib.sha256(token_hex.encode("utf-8")).hexdigest()


def create_token(batch_id, serial):
    body = b"".join(
        [
            TOKEN_VERSION.to_bytes(1, "big"),
            bytes.fromhex(batch_id),
            serial.to_bytes(SERIAL_BYTES, "big"),
            secrets.token_bytes(NONCE_BYTES),
        ]
    )
    mac = hmac.new(SECRET_KEY.encode("utf-8"), body, hashlib.sha256).digest()[:MAC_BYTES]
    return (body + mac).hex()


def decode_token(token_hex):
    try:
        raw = bytes.fromhex(token_hex)
    except ValueError:
        return None

    expected_length = 1 + BATCH_ID_BYTES + SERIAL_BYTES + NONCE_BYTES + MAC_BYTES
    if len(raw) != expected_length or raw[0] != TOKEN_VERSION:
        return None

    body = raw[:-MAC_BYTES]
    given_mac = raw[-MAC_BYTES:]
    expected_mac = hmac.new(SECRET_KEY.encode("utf-8"), body, hashlib.sha256).digest()[:MAC_BYTES]
    if not hmac.compare_digest(given_mac, expected_mac):
        return None

    return {
        "batch_id": raw[1 : 1 + BATCH_ID_BYTES].hex(),
        "serial": int.from_bytes(
            raw[1 + BATCH_ID_BYTES : 1 + BATCH_ID_BYTES + SERIAL_BYTES],
            "big",
        ),
    }


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

    def pick_font(size, bold=False):
        names = (
            ("arialbd.ttf", "DejaVuSans-Bold.ttf", "arial.ttf", "DejaVuSans.ttf")
            if bold
            else ("arial.ttf", "DejaVuSans.ttf", "arialbd.ttf", "DejaVuSans-Bold.ttf")
        )
        for name in names:
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

    title_font = pick_font(max(int(qr_image.height * 0.095), 18), bold=True)
    serial_font = pick_font(max(int(qr_image.height * 0.13), 22), bold=True)
    meta_font = pick_font(max(int(qr_image.height * 0.06), 13), bold=False)

    top_band_h = max(int(qr_image.height * 0.16), 44)
    bottom_band_h = top_band_h
    middle_h = qr_image.height + 30
    info_w = max(int(qr_image.width * 0.92), 275)
    qr_w = qr_image.width + 56

    card_w = info_w + qr_w
    card_h = top_band_h + middle_h + bottom_band_h

    canvas = Image.new("RGB", (card_w, card_h), "white")
    draw = ImageDraw.Draw(canvas)

    draw.rectangle([(0, 0), (card_w, top_band_h)], fill=saffron)
    draw.rectangle([(0, card_h - bottom_band_h), (card_w, card_h)], fill=green)

    middle_top = top_band_h
    middle_bottom = card_h - bottom_band_h

    divider_x = info_w
    for y in range(middle_top + 8, middle_bottom - 8, 12):
        draw.line([(divider_x, y), (divider_x, y + 6)], fill=(170, 177, 186), width=2)

    title = "BOARDING PASS"
    subtitle = "QR ACCESS"
    serial_label = f"S.No {serial:04d}"
    meta_text = "ONE-TIME VALID SCAN"

    stripe_x = 18
    text_left = 58
    _, title_h = text_size(draw, title, title_font)
    _, subtitle_h = text_size(draw, subtitle, meta_font)
    _, serial_h = text_size(draw, serial_label, serial_font)
    _, meta_h = text_size(draw, meta_text, meta_font)

    text_y = middle_top + max((middle_h - (title_h + subtitle_h + serial_h + meta_h + 22)) // 2, 8)
    draw.text((text_left, text_y), title, fill=navy, font=title_font)
    draw.text((text_left, text_y + title_h + 4), subtitle, fill=(63, 79, 99), font=meta_font)
    draw.text((text_left, text_y + title_h + subtitle_h + 12), serial_label, fill=navy, font=serial_font)
    draw.text(
        (text_left, text_y + title_h + subtitle_h + serial_h + 18),
        meta_text,
        fill=(63, 79, 99),
        font=meta_font,
    )

    draw.rectangle([(stripe_x, middle_top + 10), (stripe_x + 9, middle_bottom - 10)], fill=saffron)
    draw.rectangle([(stripe_x + 9, middle_top + 10), (stripe_x + 18, middle_bottom - 10)], fill="white")
    draw.rectangle([(stripe_x + 18, middle_top + 10), (stripe_x + 27, middle_bottom - 10)], fill=green)

    qr_x = info_w + (qr_w - qr_image.width) // 2
    qr_y = middle_top + (middle_h - qr_image.height) // 2
    canvas.paste(qr_image, (qr_x, qr_y))

    band_text = "INDIA"
    band_font = pick_font(max(int(top_band_h * 0.42), 16), bold=True)
    band_w, band_h = text_size(draw, band_text, band_font)
    draw.text(((card_w - band_w) // 2, (top_band_h - band_h) // 2), band_text, fill=navy, font=band_font)

    return canvas


def current_base_url():
    configured = configured_domain_name()
    if configured:
        return configured

    payload = request.get_json(silent=True) or {}
    requested = (
        payload.get("base_url")
        or request.form.get("base_url")
        or request.args.get("base_url")
    )
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
            "batch_id": state.get("active_batch_id"),
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


def available_batches():
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    items = []

    for entry in OUTPUT_ROOT.iterdir():
        if not entry.is_dir():
            continue

        batch_id = entry.name
        if len(batch_id) != BATCH_ID_BYTES * 2:
            continue

        try:
            bytes.fromhex(batch_id)
        except ValueError:
            continue

        total_qr = 0
        manifest_file = entry / "manifest.json"
        if manifest_file.exists():
            try:
                manifest_items = json.loads(manifest_file.read_text(encoding="utf-8"))
                if isinstance(manifest_items, list):
                    total_qr = len(manifest_items)
            except (OSError, json.JSONDecodeError):
                total_qr = 0

        updated_at = datetime.fromtimestamp(
            entry.stat().st_mtime,
            tz=timezone.utc,
        ).isoformat()
        items.append(
            {
                "batch_id": batch_id,
                "name": f"Batch {batch_id} ({total_qr})",
                "total_qr": total_qr,
                "updated_at": updated_at,
            }
        )

    items.sort(key=lambda batch: batch["updated_at"], reverse=True)
    return items


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
            "/batch",
            "/batches",
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
            "message": "Flask QR one-time scan service",
            "generate_examples": [
                "GET /generate/10",
                "POST /generate with JSON: {\"count\": 10}",
            ],
            "domain_name": configured_domain_name(),
            "status_url": "/status",
            "active_batch_id": state.get("active_batch_id"),
            "count": state.get("true_count", 0),
            "total": state.get("total_qr", 0),
            "over": state.get("total_qr", 0) > 0 and state.get("true_count", 0) >= state.get("total_qr", 0),
        }
    )


@app.route("/superadmin", methods=["GET", "POST"])
def superadmin():
    requested_next = request.args.get("next", "/superadmin")

    if request.method == "POST":
        payload = request.get_json(silent=True) or {}
        password = (
            request.form.get("password")
            or payload.get("password")
            or ""
        ).strip()

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


@app.get("/batches")
def batches():
    state = load_state()
    return jsonify(
        {
            "true": True,
            "active_batch_id": state.get("active_batch_id"),
            "items": available_batches(),
        }
    )


@app.route("/generate", methods=["POST"])
@app.route("/generate/<int:count>", methods=["GET"])
def generate(count=None):
    try:
        count = current_count(count)
    except ValueError as exc:
        return jsonify({"true": False, "message": str(exc)}), 400

    if count <= 0:
        return jsonify({"true": False, "message": "count must be greater than 0"}), 400

    base_url = current_base_url()
    batch_id = secrets.token_hex(BATCH_ID_BYTES)
    output_dir = OUTPUT_ROOT / batch_id
    output_dir.mkdir(parents=True, exist_ok=True)

    items = []
    for serial in range(1, count + 1):
        token_hex = create_token(batch_id, serial)
        claim_url = f"{base_url}/c/{token_hex}"
        image_url = f"{base_url}/batch/{batch_id}/qr/{serial}.png"
        image_path = output_dir / f"qr_{serial:04d}.png"
        qr_image_with_serial(claim_url, serial).save(image_path)

        items.append(
            {
                "serial": serial,
                "hex": token_hex,
                "claim_url": claim_url,
                "image_url": image_url,
                "file": str(image_path.resolve()),
            }
        )

    manifest_file = output_dir / "manifest.json"
    manifest_file.write_text(json.dumps(items, indent=2), encoding="utf-8")

    state = {
        "active_batch_id": batch_id,
        "total_qr": count,
        "true_count": 0,
        "used_token_hashes": [],
        "generated_at": utc_now(),
        "updated_at": utc_now(),
        "output_dir": str(output_dir.resolve()),
        "manifest_file": str(manifest_file.resolve()),
    }

    with STATE_LOCK:
        save_state(state)
        save_batch_scan_state(batch_id, state)

    return jsonify(
        {
            "true": True,
            "generated": count,
            "count": 0,
            "over": False,
            "generated_at": state["generated_at"],
            "domain_name": base_url,
            "batch_id": batch_id,
            "download_url": f"{base_url}/batch/{batch_id}/download.zip",
            "manifest_url": f"{base_url}/batch/{batch_id}/manifest.json",
            "output_dir": str(output_dir.resolve()),
            "manifest_file": str(manifest_file.resolve()),
            "items": items,
        }
    )


@app.get("/batch/<batch_id>/manifest.json")
def batch_manifest(batch_id):
    batch_dir = resolve_batch_dir(batch_id)
    if not batch_dir:
        return jsonify({"true": False, "message": "batch not found"}), 404

    manifest = batch_dir / "manifest.json"
    if not manifest.exists():
        return jsonify({"true": False, "message": "manifest not found"}), 404
    return send_file(manifest, mimetype="application/json")


@app.get("/batch/<batch_id>/qr/<int:serial>.png")
def batch_qr_image(batch_id, serial):
    batch_dir = resolve_batch_dir(batch_id)
    if not batch_dir:
        return jsonify({"true": False, "message": "batch not found"}), 404
    if serial <= 0:
        return jsonify({"true": False, "message": "invalid serial"}), 400

    image_path = batch_dir / f"qr_{serial:04d}.png"
    if not image_path.exists():
        return jsonify({"true": False, "message": "qr image not found"}), 404
    return send_file(image_path, mimetype="image/png")


@app.get("/batch/<batch_id>/download.zip")
def batch_download_zip(batch_id):
    batch_dir = resolve_batch_dir(batch_id)
    if not batch_dir:
        return jsonify({"true": False, "message": "batch not found"}), 404

    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for image_path in sorted(batch_dir.glob("qr_*.png")):
            zf.write(image_path, arcname=image_path.name)
        manifest = batch_dir / "manifest.json"
        if manifest.exists():
            zf.write(manifest, arcname="manifest.json")

    archive.seek(0)
    return send_file(
        archive,
        mimetype="application/zip",
        as_attachment=True,
        download_name=f"qr_batch_{batch_id}.zip",
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

        if not state.get("active_batch_id"):
            return scan_payload(False, state, "no active batch")

        payload = decode_token(token_hex)
        if not payload:
            return scan_payload(False, state, "invalid token")

        if payload.get("batch_id") != state.get("active_batch_id"):
            return scan_payload(False, state, "token is not from the active batch")

        used_token_hashes = set(state.get("used_token_hashes", []))
        fingerprint = token_fingerprint(token_hex)

        if fingerprint in used_token_hashes:
            return scan_payload(False, state, "already scanned", serial=payload.get("serial"))

        used_token_hashes.add(fingerprint)
        state["used_token_hashes"] = list(used_token_hashes)
        state["true_count"] = int(state.get("true_count", 0)) + 1
        state["updated_at"] = utc_now()
        save_state(state)
        if state.get("active_batch_id"):
            save_batch_scan_state(state["active_batch_id"], state)

        return scan_payload(True, state, "accepted", serial=payload.get("serial"))


@app.get("/status")
def status():
    state = load_state()
    total = int(state.get("total_qr", 0) or 0)
    count = int(state.get("true_count", 0) or 0)

    return jsonify(
        {
            "domain_name": configured_domain_name() or request.host_url.rstrip("/"),
            "active_batch_id": state.get("active_batch_id"),
            "total_qr": total,
            "true_count": count,
            "remaining": max(total - count, 0),
            "over": total > 0 and count >= total,
            "generated_at": state.get("generated_at"),
            "updated_at": state.get("updated_at"),
            "output_dir": state.get("output_dir"),
            "manifest_file": state.get("manifest_file"),
            "used_count": len(state.get("used_token_hashes", [])),
            "data_root": str(DATA_ROOT),
        }
    )


if __name__ == "__main__":
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    app.run(host="0.0.0.0", port=5000, debug=False)

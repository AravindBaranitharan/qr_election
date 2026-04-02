import hashlib
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
from flask import Flask, Response, jsonify, request, send_file, send_from_directory


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


load_dotenv_file(APP_ROOT / ".env")

app = Flask(__name__, static_folder="static", static_url_path="/static")

SECRET_KEY = os.getenv("QR_SECRET", "replace-this-with-a-long-secret-key")
STATE_FILE = APP_ROOT / "qr_state.json"
OUTPUT_ROOT = APP_ROOT / "generated_qr"
STATE_LOCK = Lock()
TOKEN_VERSION = 1
BATCH_ID_BYTES = 4
SERIAL_BYTES = 4
NONCE_BYTES = 4
MAC_BYTES = 8


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


def load_state():
    if not STATE_FILE.exists():
        return empty_state()

    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return empty_state()


def save_state(state):
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


@app.after_request
def disable_api_caching(response):
    if request.path.startswith(("/generate", "/status", "/scan", "/s", "/c", "/claim", "/batch")):
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

        qr = qrcode.QRCode(
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=8,
            border=2,
        )
        qr.add_data(claim_url)
        qr.make(fit=True)
        image = qr.make_image(fill_color="black", back_color="white")
        image.save(image_path)

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
        }
    )


if __name__ == "__main__":
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    app.run(host="0.0.0.0", port=5000, debug=False)

import hashlib
import html
import hmac
import io
import json
import os
import re
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock, Thread
from urllib.parse import parse_qs, urlparse

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

try:
    import psycopg2
    from psycopg2.extras import Json, RealDictCursor
except ImportError:
    psycopg2 = None
    Json = None
    RealDictCursor = None


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
DATABASE_SESSION_KEY = "database_route_logged_in"
QR_64_KEY_ENV = "QR_64_KEY"
CIPHER_CODE_LENGTH = 64
DATA_ROOT = configured_data_root()
STATE_FILE = DATA_ROOT / "qr_state.json"
OUTPUT_ROOT = DATA_ROOT / "generated_qr"
MANIFEST_FILE = OUTPUT_ROOT / "manifest.json"
SCAN_LOG_FILE = DATA_ROOT / "scan_logs.jsonl"
STATE_LOCK = Lock()
TOKEN_VERSION = "1"
STATE_OUTPUT_DIR = "generated_qr"
STATE_MANIFEST_PATH = "generated_qr/manifest.json"
DEFAULT_STATE_TABLE = "qr_state_store"

app.secret_key = hashlib.sha256(f"{SECRET_KEY}-session".encode("utf-8")).hexdigest()


def configured_domain_name():
    load_dotenv_file(APP_ROOT / ".env", override=True)
    return normalize_domain(os.getenv("DOMAIN_NAME", ""))


def current_cipher_code():
    load_dotenv_file(APP_ROOT / ".env", override=True)
    return str(os.getenv(QR_64_KEY_ENV, "")).strip()


def cipher_key_error():
    return f"{QR_64_KEY_ENV} must be exactly {CIPHER_CODE_LENGTH} characters in .env"


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def empty_state():
    return {
        "total_qr": 0,
        "true_count": 0,
        "scanned_serials": [],
        "next_serial": 1,
        "output_dir": STATE_OUTPUT_DIR,
        "manifest_file": STATE_MANIFEST_PATH,
    }


# State storage strategy:
# - Local/dev/test environments keep using qr_state.json (easy local workflow).
# - Production/Render environments switch to PostgreSQL for durable shared state.
def parse_bool(value):
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def parse_int(value, default):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def configured_database_route_password():
    raw = str(os.getenv("DB_ROUTE_PASSWORD", "")).strip()
    return raw or SUPERADMIN_PASSWORD


def configured_runtime_environment():
    return str(
        os.getenv("QR_ENV")
        or os.getenv("APP_ENV")
        or os.getenv("ENVIRONMENT")
        or os.getenv("FLASK_ENV")
        or os.getenv("PYTHON_ENV")
        or ("production" if parse_bool(os.getenv("RENDER")) else "local")
    ).strip().lower()


def is_local_environment():
    return configured_runtime_environment() in {"", "local", "development", "dev", "test"}


def configured_state_table_name():
    raw_name = str(os.getenv("QR_STATE_TABLE", DEFAULT_STATE_TABLE)).strip() or DEFAULT_STATE_TABLE
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", raw_name):
        return raw_name
    return DEFAULT_STATE_TABLE


def configured_state_backend():
    forced = str(os.getenv("QR_STATE_BACKEND", "")).strip().lower()
    if forced in {"json", "file"}:
        return "json", "forced by QR_STATE_BACKEND"
    if forced in {"db", "database", "postgres", "postgresql"}:
        return "database", "forced by QR_STATE_BACKEND"
    if parse_bool(os.getenv("RENDER")):
        return "database", "detected Render environment"
    if is_local_environment():
        return "json", "detected local environment"
    return "database", "detected production environment"


DATABASE_URL = str(os.getenv("DATABASE_URL", "")).strip()
DATABASE_SSLMODE = str(os.getenv("DB_SSLMODE", "require")).strip() or "require"
STATE_TABLE_NAME = configured_state_table_name()
STATE_BACKEND, STATE_BACKEND_REASON = configured_state_backend()
STATE_BACKEND_WARNINGS = []
if STATE_BACKEND == "database" and not DATABASE_URL:
    STATE_BACKEND_WARNINGS.append("DATABASE_URL is missing")
if STATE_BACKEND == "database" and psycopg2 is None:
    STATE_BACKEND_WARNINGS.append("psycopg2 is not installed")
USE_DATABASE_STATE = STATE_BACKEND == "database" and not STATE_BACKEND_WARNINGS
DB_ROUTE_PASSWORD = configured_database_route_password()
DB_PING_INTERVAL_SECONDS = max(10, min(parse_int(os.getenv("DB_PING_INTERVAL_SECONDS", 30), 30), 3600))
DB_HEALTH_LOCK = Lock()
DB_HEALTH_STATUS = {
    "connected": False,
    "message": "not checked yet",
    "checks": 0,
    "database_time": None,
    "latency_ms": None,
    "last_checked_at": None,
    "last_success_at": None,
}
DB_PING_THREAD = None


def read_json_file(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def append_scan_log(entry):
    SCAN_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with SCAN_LOG_FILE.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(entry, ensure_ascii=False) + "\n")


def load_scan_logs(limit=1200):
    if not SCAN_LOG_FILE.exists():
        return []

    lines = SCAN_LOG_FILE.read_text(encoding="utf-8").splitlines()
    entries = []
    for line in lines[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            entries.append(item)
    return entries


def build_scan_time_series(entries):
    buckets = {}

    for entry in entries:
        timestamp = str(entry.get("timestamp", "")).strip()
        if not timestamp:
            continue
        minute_key = timestamp[:16]

        current = buckets.setdefault(
            minute_key,
            {
                "time": minute_key.replace("T", " "),
                "accepted": 0,
                "rejected": 0,
                "total": 0,
            },
        )
        current["total"] += 1
        if bool(entry.get("accepted")):
            current["accepted"] += 1
        else:
            current["rejected"] += 1

    keys = sorted(buckets.keys())
    return [buckets[key] for key in keys]


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
    scanned_serials = state.get("scanned_serials", [])
    if not isinstance(scanned_serials, list):
        scanned_serials = []
    normalized_scanned = []
    seen_serials = set()
    for value in scanned_serials:
        try:
            serial = int(value)
        except (TypeError, ValueError):
            continue
        if serial <= 0 or serial in seen_serials:
            continue
        seen_serials.add(serial)
        normalized_scanned.append(serial)

    manifest = load_manifest()
    if manifest:
        manifest_total = len(manifest)
        total_qr = max(total_qr, manifest_total)
        max_serial = 0
        for item in manifest:
            if isinstance(item, dict):
                max_serial = max(max_serial, int(item.get("serial", 0) or 0))
        baseline_next_serial = max_serial + 1 if max_serial > 0 else total_qr + 1
        requested_next_serial = int(state.get("next_serial", 0) or 0)
        next_serial = max(baseline_next_serial, requested_next_serial)
    else:
        next_serial = int(state.get("next_serial", 0) or 0)
        if next_serial <= 0:
            next_serial = total_qr + 1

    filtered_scanned = [serial for serial in normalized_scanned if serial <= total_qr or total_qr <= 0]
    normalized = {
        "total_qr": total_qr,
        "true_count": min(len(filtered_scanned), total_qr) if total_qr > 0 else len(filtered_scanned),
        "scanned_serials": filtered_scanned,
        "next_serial": max(next_serial, 1),
        "output_dir": STATE_OUTPUT_DIR,
        "manifest_file": STATE_MANIFEST_PATH,
    }
    return normalized


def database_connection():
    if psycopg2 is None:
        raise RuntimeError("psycopg2 is not installed")
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is missing")

    connect_args = {"dsn": DATABASE_URL, "connect_timeout": 5}
    if "sslmode=" not in DATABASE_URL.lower():
        connect_args["sslmode"] = DATABASE_SSLMODE
    return psycopg2.connect(**connect_args)


def ensure_database_state_row():
    if not USE_DATABASE_STATE:
        return

    with database_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {STATE_TABLE_NAME} (
                    id SMALLINT PRIMARY KEY CHECK (id = 1),
                    total_qr INTEGER NOT NULL DEFAULT 0,
                    true_count INTEGER NOT NULL DEFAULT 0,
                    scanned_serials JSONB NOT NULL DEFAULT '[]'::jsonb,
                    next_serial INTEGER NOT NULL DEFAULT 1,
                    output_dir TEXT NOT NULL,
                    manifest_file TEXT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
            cursor.execute(
                f"""
                INSERT INTO {STATE_TABLE_NAME}
                    (id, total_qr, true_count, scanned_serials, next_serial, output_dir, manifest_file)
                VALUES (1, 0, 0, %s, 1, %s, %s)
                ON CONFLICT (id) DO NOTHING
                """,
                (Json([]), STATE_OUTPUT_DIR, STATE_MANIFEST_PATH),
            )


def load_state_from_file():
    raw = read_json_file(STATE_FILE) if STATE_FILE.exists() else {}
    state = normalize_state(raw)
    save_state_to_file(state)
    return state


def save_state_to_file(state):
    normalized = normalize_state(state)
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(normalized, indent=2), encoding="utf-8")
    return normalized


def load_state_from_database():
    ensure_database_state_row()

    with database_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                f"""
                SELECT total_qr, true_count, scanned_serials, next_serial, output_dir, manifest_file
                FROM {STATE_TABLE_NAME}
                WHERE id = 1
                """
            )
            row = cursor.fetchone() or {}
    return normalize_state(dict(row))


def save_state_to_database(state):
    normalized = normalize_state(state)
    ensure_database_state_row()

    with database_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                f"""
                INSERT INTO {STATE_TABLE_NAME}
                    (id, total_qr, true_count, scanned_serials, next_serial, output_dir, manifest_file, updated_at)
                VALUES
                    (1, %s, %s, %s, %s, %s, %s, NOW())
                ON CONFLICT (id) DO UPDATE SET
                    total_qr = EXCLUDED.total_qr,
                    true_count = EXCLUDED.true_count,
                    scanned_serials = EXCLUDED.scanned_serials,
                    next_serial = EXCLUDED.next_serial,
                    output_dir = EXCLUDED.output_dir,
                    manifest_file = EXCLUDED.manifest_file,
                    updated_at = NOW()
                """,
                (
                    int(normalized.get("total_qr", 0) or 0),
                    int(normalized.get("true_count", 0) or 0),
                    Json(normalized.get("scanned_serials", [])),
                    int(normalized.get("next_serial", 1) or 1),
                    str(normalized.get("output_dir", STATE_OUTPUT_DIR)),
                    str(normalized.get("manifest_file", STATE_MANIFEST_PATH)),
                ),
            )
    return normalized


def state_storage_mode():
    return "database" if USE_DATABASE_STATE else "json"


# Unified state access layer used by scan/generate/status APIs.
# This keeps all state management in one place while switching backend by environment.
def load_state():
    if USE_DATABASE_STATE:
        return load_state_from_database()
    return load_state_from_file()


def save_state(state):
    if USE_DATABASE_STATE:
        return save_state_to_database(state)
    return save_state_to_file(state)


def parsed_database_details():
    if not DATABASE_URL:
        return {
            "configured": False,
            "scheme": None,
            "host": None,
            "port": None,
            "database": None,
            "username": None,
            "has_password": False,
            "sslmode": DATABASE_SSLMODE,
        }

    parsed = urlparse(DATABASE_URL)
    query = parse_qs(parsed.query)
    sslmode = query.get("sslmode", [DATABASE_SSLMODE])[0]
    return {
        "configured": True,
        "scheme": parsed.scheme or "postgresql",
        "host": parsed.hostname,
        "port": parsed.port,
        "database": parsed.path.lstrip("/") or None,
        "username": parsed.username,
        "has_password": bool(parsed.password),
        "sslmode": sslmode,
    }


def is_database_authenticated():
    return bool(session.get(DATABASE_SESSION_KEY))


def build_database_login_page(error_message=""):
    safe_error = html.escape(error_message or "", quote=False)
    error_block = f'<p class="error">{safe_error}</p>' if safe_error else ""
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Database Access</title>
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
  <form class="card" method="post" action="/database">
    <h1>Database Route Lock</h1>
    <p>Enter password to access live database controls.</p>
    {error_block}
    <label for="password">Password</label>
    <input id="password" name="password" type="password" autocomplete="current-password" required autofocus />
    <button type="submit">Open Database</button>
  </form>
</body>
</html>"""


def normalize_serial_list(raw_value):
    if isinstance(raw_value, str):
        parts = [part.strip() for part in raw_value.split(",")]
        items = [part for part in parts if part]
    elif isinstance(raw_value, list):
        items = raw_value
    else:
        items = []

    serials = []
    seen = set()
    for value in items:
        try:
            serial = int(value)
        except (TypeError, ValueError):
            continue
        if serial <= 0 or serial in seen:
            continue
        seen.add(serial)
        serials.append(serial)
    return sorted(serials)


def apply_live_state_updates(base_state, payload):
    if not isinstance(base_state, dict):
        base_state = empty_state()
    if not isinstance(payload, dict):
        return base_state

    state = dict(base_state)
    if "total_qr" in payload:
        state["total_qr"] = max(parse_int(payload.get("total_qr"), state.get("total_qr", 0)), 0)
    if "next_serial" in payload:
        state["next_serial"] = max(parse_int(payload.get("next_serial"), state.get("next_serial", 1)), 1)

    scanned_set = set(normalize_serial_list(state.get("scanned_serials", [])))
    add_serials = normalize_serial_list(payload.get("add_serials"))
    remove_serials = normalize_serial_list(payload.get("remove_serials"))

    for serial in add_serials:
        scanned_set.add(serial)
    for serial in remove_serials:
        scanned_set.discard(serial)

    remove_range_start = parse_int(payload.get("remove_range_start"), 0)
    remove_range_end = parse_int(payload.get("remove_range_end"), 0)
    if remove_range_start > 0 and remove_range_end > 0:
        lower = min(remove_range_start, remove_range_end)
        upper = max(remove_range_start, remove_range_end)
        scanned_set = {serial for serial in scanned_set if not (lower <= serial <= upper)}

    state["scanned_serials"] = sorted(scanned_set)
    state["true_count"] = len(state["scanned_serials"])
    state["output_dir"] = STATE_OUTPUT_DIR
    state["manifest_file"] = STATE_MANIFEST_PATH
    return state


def perform_database_ping():
    if not DATABASE_URL:
        return {
            "connected": False,
            "message": "DATABASE_URL is missing",
            "database_time": None,
            "latency_ms": None,
            "checked_at": utc_now(),
        }
    if psycopg2 is None:
        return {
            "connected": False,
            "message": "psycopg2 is not installed",
            "database_time": None,
            "latency_ms": None,
            "checked_at": utc_now(),
        }

    started = time.perf_counter()
    try:
        with database_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT NOW()")
                row = cursor.fetchone() or [None]
        db_now = row[0].isoformat() if row[0] else None
        return {
            "connected": True,
            "message": "ok",
            "database_time": db_now,
            "latency_ms": round((time.perf_counter() - started) * 1000, 2),
            "checked_at": utc_now(),
        }
    except Exception as exc:
        return {
            "connected": False,
            "message": str(exc),
            "database_time": None,
            "latency_ms": round((time.perf_counter() - started) * 1000, 2),
            "checked_at": utc_now(),
        }


def update_database_health(status):
    with DB_HEALTH_LOCK:
        DB_HEALTH_STATUS["connected"] = bool(status.get("connected"))
        DB_HEALTH_STATUS["message"] = str(status.get("message") or "")
        DB_HEALTH_STATUS["database_time"] = status.get("database_time")
        DB_HEALTH_STATUS["latency_ms"] = status.get("latency_ms")
        DB_HEALTH_STATUS["last_checked_at"] = status.get("checked_at") or utc_now()
        DB_HEALTH_STATUS["checks"] = int(DB_HEALTH_STATUS.get("checks", 0) or 0) + 1
        if bool(status.get("connected")):
            DB_HEALTH_STATUS["last_success_at"] = DB_HEALTH_STATUS["last_checked_at"]


def current_database_health():
    with DB_HEALTH_LOCK:
        return dict(DB_HEALTH_STATUS)


def database_ping_worker():
    while True:
        update_database_health(perform_database_ping())
        time.sleep(DB_PING_INTERVAL_SECONDS)


def start_database_ping_worker():
    global DB_PING_THREAD
    if DB_PING_THREAD is not None and DB_PING_THREAD.is_alive():
        return
    DB_PING_THREAD = Thread(target=database_ping_worker, name="db-ping-worker", daemon=True)
    DB_PING_THREAD.start()


start_database_ping_worker()


def database_connection_probe():
    health = current_database_health()
    if int(health.get("checks", 0) or 0) <= 0:
        update_database_health(perform_database_ping())
        health = current_database_health()
    health["warnings"] = STATE_BACKEND_WARNINGS
    health["ping_interval_seconds"] = DB_PING_INTERVAL_SECONDS
    return health


def state_backend_report(state):
    scanned_serials = state.get("scanned_serials", []) if isinstance(state, dict) else []
    manifest = load_manifest()
    return {
        "true": True,
        "environment": {
            "name": configured_runtime_environment(),
            "local": is_local_environment(),
            "backend_reason": STATE_BACKEND_REASON,
        },
        "storage": {
            "mode": state_storage_mode(),
            "requested_backend": STATE_BACKEND,
            "warnings": STATE_BACKEND_WARNINGS,
            "table_name": STATE_TABLE_NAME,
            "state_file": str(STATE_FILE.resolve()),
            "manifest_file": str(MANIFEST_FILE.resolve()),
            "scan_log_file": str(SCAN_LOG_FILE.resolve()),
        },
        "database": {
            **parsed_database_details(),
            "connection": database_connection_probe(),
        },
        "state": state,
        "manifest_count": len(manifest),
        "scanned_serial_count": len(scanned_serials) if isinstance(scanned_serials, list) else 0,
        "updated_at": utc_now(),
    }


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


def qr_image_with_serial(qr_payload, serial):
    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=8,
        border=2,
    )
    qr.add_data(qr_payload)
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


def process_scan_token(token_hex):
    with STATE_LOCK:
        state = load_state()
        client_ip = (request.headers.get("X-Forwarded-For") or request.remote_addr or "").split(",")[0].strip()
        token_fingerprint = hashlib.sha256(token_hex.encode("utf-8")).hexdigest()[:20]
        payload = decode_token(token_hex)

        if not payload:
            append_scan_log(
                {
                    "timestamp": utc_now(),
                    "accepted": False,
                    "message": "invalid token",
                    "serial": None,
                    "count": int(state.get("true_count", 0) or 0),
                    "total": int(state.get("total_qr", 0) or 0),
                    "ip": client_ip,
                    "token": token_fingerprint,
                }
            )
            return scan_payload(False, state, "invalid token")

        serial = int(payload.get("serial", 0) or 0)
        total_qr = int(state.get("total_qr", 0) or 0)
        if serial <= 0 or serial > total_qr:
            append_scan_log(
                {
                    "timestamp": utc_now(),
                    "accepted": False,
                    "message": "serial not generated",
                    "serial": serial,
                    "count": int(state.get("true_count", 0) or 0),
                    "total": total_qr,
                    "ip": client_ip,
                    "token": token_fingerprint,
                }
            )
            return scan_payload(False, state, "serial not generated", serial=serial)

        scanned_serials = set()
        for value in state.get("scanned_serials", []):
            try:
                existing_serial = int(value)
            except (TypeError, ValueError):
                continue
            if existing_serial > 0:
                scanned_serials.add(existing_serial)
        if serial in scanned_serials:
            append_scan_log(
                {
                    "timestamp": utc_now(),
                    "accepted": False,
                    "message": "already scanned",
                    "serial": serial,
                    "count": int(state.get("true_count", 0) or 0),
                    "total": total_qr,
                    "ip": client_ip,
                    "token": token_fingerprint,
                }
            )
            return scan_payload(False, state, "already scanned", serial=serial)

        scanned_serials.add(serial)
        state["scanned_serials"] = sorted(scanned_serials)
        state["true_count"] = len(state["scanned_serials"])
        save_state(state)
        append_scan_log(
            {
                "timestamp": utc_now(),
                "accepted": True,
                "message": "accepted",
                "serial": serial,
                "count": int(state.get("true_count", 0) or 0),
                "total": total_qr,
                "ip": client_ip,
                "token": token_fingerprint,
            }
        )
        return scan_payload(True, state, "accepted", serial=serial)


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
    if not (safe_next.startswith("/superadmin") or safe_next.startswith("/database")):
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
            "/generate_qr_local",
            "/status",
            "/scan",
            "/scan_metrics",
            "/s",
            "/c",
            "/claim",
            "/manifest.json",
            "/qr_state.json",
            "/qr/",
            "/download.zip",
            "/superadmin",
            "/database",
            "/database_details",
            "/database_state_update",
        )
    ):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


@app.before_request
def ensure_background_workers():
    start_database_ping_worker()


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
                "GET /generate_qr_local/10",
                "POST /generate_qr_local with JSON: {\"count\": 10}",
            ],
            "domain_name": configured_domain_name(),
            "status_url": "/status",
            "state_storage": state_storage_mode(),
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
            safe_next_value = str(requested_next or "")
            safe_next = (
                safe_next_value
                if (safe_next_value.startswith("/superadmin") or safe_next_value.startswith("/database"))
                else "/superadmin"
            )
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
    session.pop(DATABASE_SESSION_KEY, None)
    return redirect(url_for("superadmin"))


@app.get("/superadmin/<path:path>")
def superadmin_spa(path):
    if not is_superadmin_authenticated():
        return redirect(url_for("superadmin", next=f"/superadmin/{path}"))

    frontend = serve_frontend_index()
    if frontend is not None:
        return frontend
    return jsonify({"true": False, "message": "frontend not built"}), 404


@app.route("/database", methods=["GET", "POST"])
def database_page():
    if not is_superadmin_authenticated():
        return redirect(url_for("superadmin", next="/database"))

    if request.method == "POST":
        payload = request.get_json(silent=True) or {}
        password = (request.form.get("password") or payload.get("password") or "").strip()
        if hmac.compare_digest(password, DB_ROUTE_PASSWORD):
            session[DATABASE_SESSION_KEY] = True
            return redirect(url_for("database_page"))
        return (
            Response(build_database_login_page(error_message="Wrong password"), mimetype="text/html"),
            401,
        )

    if not is_database_authenticated():
        return Response(build_database_login_page(), mimetype="text/html")

    frontend = serve_frontend_index()
    if frontend is not None:
        return frontend
    return jsonify({"true": False, "message": "frontend not built"}), 404


@app.get("/database/logout")
def database_logout():
    session.pop(DATABASE_SESSION_KEY, None)
    return redirect(url_for("database_page"))


@app.get("/database_details")
def database_details():
    if not is_superadmin_authenticated():
        return jsonify({"true": False, "message": "superadmin login required"}), 401
    if not is_database_authenticated():
        return jsonify({"true": False, "message": "database password required"}), 401

    with STATE_LOCK:
        state = load_state()
    return jsonify(state_backend_report(state))


@app.post("/database_state_update")
def database_state_update():
    if not is_superadmin_authenticated():
        return jsonify({"true": False, "message": "superadmin login required"}), 401
    if not is_database_authenticated():
        return jsonify({"true": False, "message": "database password required"}), 401

    payload = request.get_json(silent=True) or {}
    with STATE_LOCK:
        state = load_state()
        before_serials = set(normalize_serial_list(state.get("scanned_serials", [])))
        updated_state = apply_live_state_updates(state, payload)
        saved_state = save_state(updated_state)
        after_serials = set(normalize_serial_list(saved_state.get("scanned_serials", [])))
    return jsonify(
        {
            "true": True,
            "message": "state updated",
            "storage_mode": state_storage_mode(),
            "state": saved_state,
            "added_count": len(after_serials - before_serials),
            "removed_count": len(before_serials - after_serials),
        }
    )


@app.route("/generate_qr_local", methods=["POST"])
@app.route("/generate_qr_local/<int:count>", methods=["GET"])
@app.route("/generate", methods=["POST"])
@app.route("/generate/<int:count>", methods=["GET"])
def generate_qr_local(count=None):
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
            image_url = f"{base_url}/qr/{serial}.png"
            image_path = OUTPUT_ROOT / f"qr_{serial:04d}.png"
            qr_image_with_serial(token_hex, serial).save(image_path)

            item = {
                "serial": serial,
                "hex": token_hex,
                "image_url": image_url,
                "file": str(image_path.resolve()),
            }
            manifest.append(item)
            items.append(item)

        save_manifest(manifest)
        state["total_qr"] = len(manifest)
        state["next_serial"] = start_serial + count
        state["output_dir"] = STATE_OUTPUT_DIR
        state["manifest_file"] = STATE_MANIFEST_PATH
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


@app.get("/qr_state.json")
def qr_state_file():
    with STATE_LOCK:
        state = load_state()
    return jsonify(state)


@app.get("/scan_metrics")
def scan_metrics():
    entries = load_scan_logs(limit=1600)
    points = build_scan_time_series(entries)[-120:]
    return jsonify(
        {
            "true": True,
            "points": points,
            "total_events": len(entries),
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
    token_value = str(token_hex or "").strip().lower()
    return process_scan_token(token_value)


@app.post("/scan_hash")
def scan_hash():
    payload = request.get_json(silent=True) or {}
    token_value = (
        payload.get("hash")
        or payload.get("token")
        or request.form.get("hash")
        or request.form.get("token")
        or ""
    )
    token_value = str(token_value).strip().lower()
    if not token_value:
        with STATE_LOCK:
            state = load_state()
        return scan_payload(False, state, "hash is required")
    return process_scan_token(token_value)


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
            "state_storage": state_storage_mode(),
            "output_dir": state.get("output_dir"),
            "manifest_file": state.get("manifest_file"),
        }
    )


if __name__ == "__main__":
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    app.run(host="0.0.0.0", port=5000, debug=False)

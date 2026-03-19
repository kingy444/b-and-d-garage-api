"""
B&D Garage Door API Server — LAN app protocol (port 8989)
Exposes simple HTTP endpoints that Siri Shortcuts can call.

Endpoints:
  POST /open   -> opens garage door
  POST /close  -> closes garage door
  POST /stop   -> stops door mid-travel
  GET  /status -> returns door state
  GET  /health -> health check

Protocol flow:
  1. app/connect (port 8989) -> sessionId, sessionSecret
  2. app/res/action with {deviceId, action: {cmd: N}} -> open/close/stop
  3. app/res/devices/fetch with {deviceId} -> status (position, rate, door icon)

Crypto:
  - Encryption: AES-128-CBC, key=MD5(phoneSecret), IV=MD5(str(ts_ms))
  - phoneSig:   HMAC-SHA256(phoneSecret, str(ts)+":"+encrypted_data)
  - sessionSig: HMAC-SHA256(sessionSecret, str(ts)+":"+encrypted_data)
"""

import base64
import hashlib
import hmac as _hmac
import json
import logging
import os
import secrets
import ssl
import time
from contextlib import asynccontextmanager
from pathlib import Path

import requests
import urllib3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from fastapi import FastAPI, HTTPException, Security
from fastapi.security.api_key import APIKeyHeader
from requests.adapters import HTTPAdapter

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

HUB_IP     = os.environ.get("GARAGE_HUBIP", "")
LAN_8989   = f"https://{HUB_IP}:8989"
CREDS_FILE = Path("/creds/credentials.json")

APP_HEADERS = {
    "Content-Type": "application/json",
    "version":      "2.21.1",
    "app-version":  "1.2.3",
}

CMD_OPEN  = 2
CMD_CLOSE = 4
CMD_STOP  = 3

@asynccontextmanager
async def lifespan(application: FastAPI):
    if not HUB_IP:
        raise RuntimeError("GARAGE_HUBIP environment variable is not set")
    load_creds()
    try:
        _do_connect()
        log.info("Initial connect successful")
    except Exception as e:
        log.warning("Initial connect failed (will retry on first request): %s", e)
    yield


app = FastAPI(title="B&D Garage API", lifespan=lifespan)

# ── API key auth ───────────────────────────────────────────────────────────────

_API_KEY = os.environ.get("GARAGE_API_KEY", "")
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def _require_key(key: str = Security(_api_key_header)):
    if not _API_KEY:
        return  # no key configured → open (dev mode)
    if not key or not secrets.compare_digest(key, _API_KEY):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


# ── SSL adapter ───────────────────────────────────────────────────────────────

class LegacySSLAdapter(HTTPAdapter):
    def send(self, request, **kwargs):
        kwargs["verify"] = False
        return super().send(request, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1
        except AttributeError:
            pass
        try:
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        except ssl.SSLError:
            pass
        kwargs["ssl_context"] = ctx
        super().init_poolmanager(*args, **kwargs)


_lan = requests.Session()
_lan.mount("https://", LegacySSLAdapter())

# ── Credentials & session state ───────────────────────────────────────────────

_creds: dict = {}
_session_id:     str   = ""
_session_secret: str   = ""
_session_at:     float = 0.0
SESSION_TTL = 120  # re-connect after 2 minutes


_CRED_KEYS = ["phoneId", "phonePassword", "phoneSecret",
              "userPassword", "hubId", "actionDeviceId"]


def load_creds():
    """Load credentials from environment variables, falling back to credentials.json."""
    global _creds

    # Check if all required keys are present as env vars
    env_creds = {k: os.environ.get(f"GARAGE_{k.upper()}") for k in _CRED_KEYS}
    if all(env_creds.values()):
        _creds = env_creds
        log.info("Credentials loaded from environment — phoneId=%s actionDeviceId=%s",
                 _creds.get("phoneId"), _creds.get("actionDeviceId"))
        return

    # Fall back to credentials.json (local dev)
    if not CREDS_FILE.exists():
        missing = [k for k, v in env_creds.items() if not v]
        raise RuntimeError(
            f"No credentials found. Set env vars {['GARAGE_'+k.upper() for k in missing]} "
            f"or provide {CREDS_FILE}"
        )
    _creds = json.loads(CREDS_FILE.read_text())
    log.info("Credentials loaded from file — phoneId=%s actionDeviceId=%s",
             _creds.get("phoneId"), _creds.get("actionDeviceId"))


# ── Crypto helpers ────────────────────────────────────────────────────────────

def _aes128_enc(phone_secret: str, ts_ms: int, plaintext: str) -> str:
    key = hashlib.md5(phone_secret.encode()).digest()
    iv  = hashlib.md5(str(ts_ms).encode()).digest()
    padder = PKCS7(128).padder()
    padded = padder.update(plaintext.encode()) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return base64.b64encode(enc.update(padded) + enc.finalize()).decode()


def _hmac_b64(key: str, msg: str) -> str:
    return base64.b64encode(
        _hmac.new(key.encode(), msg.encode(), hashlib.sha256).digest()
    ).decode()


# ── Session management ────────────────────────────────────────────────────────

def _do_connect():
    """Call app/connect, wait for isAccessReady, update session globals."""
    global _session_id, _session_secret, _session_at
    r = _lan.post(f"{LAN_8989}/app/connect", timeout=10, json={
        "bsid":              _creds["hubId"],
        "phoneId":           _creds["phoneId"],
        "phonePassword":     _creds["phonePassword"],
        "userPassword":      _creds["userPassword"],
        "communicationType": 1,
    })
    if not r.ok:
        raise RuntimeError(f"app/connect failed: {r.status_code} {r.text[:100]}")
    conn = r.json()
    _session_id     = conn["sessionId"]
    _session_secret = conn["sessionSecret"]
    _session_at     = time.time()

    # Wait for isAccessReady
    data_field = conn.get("data", {})
    if isinstance(data_field, str):
        try:
            data_field = json.loads(data_field)
        except Exception:
            data_field = {}
    ua = data_field.get("userAccess", {})
    next_access = ua.get("nextAccess", 0)
    now_ms = int(time.time() * 1000)
    if next_access > now_ms:
        wait_s = (next_access - now_ms) / 1000.0 + 0.1
        log.info("Waiting %.2fs for isAccessReady...", wait_s)
        time.sleep(wait_s)

    log.info("app/connect OK — sessionId=%s...", _session_id[:12])


def _get_session():
    """Return (session_id, session_secret), reconnecting if needed."""
    global _session_id, _session_secret, _session_at
    if _session_id and (time.time() - _session_at) < SESSION_TTL:
        return _session_id, _session_secret
    _do_connect()
    return _session_id, _session_secret


# ── Hub requests ──────────────────────────────────────────────────────────────

def _post_encrypted(data_json: str, endpoint: str) -> list:
    """Encrypt data_json, sign with phoneSig+sessionSig, POST to endpoint.
    Returns list of message dicts from hub response."""
    phone_secret = _creds["phoneSecret"]

    for attempt in range(2):
        sid, ssec = _get_session()
        ts = int(time.time() * 1000)
        encrypted = _aes128_enc(phone_secret, ts, data_json)
        signing   = f"{ts}:{encrypted}"
        body = {
            "bsid":       _creds["hubId"],
            "sessionId":  sid,
            "time":       ts,
            "data":       encrypted,
            "processId":  "0",
            "sessionSig": _hmac_b64(ssec, signing),
            "phoneSig":   _hmac_b64(phone_secret, signing),
            "isEncrypted": True,
        }
        r = _lan.post(f"{LAN_8989}/{endpoint}", headers=APP_HEADERS, json=body, timeout=15)
        if r.status_code == 403 and attempt == 0:
            log.info("Session rejected (403), reconnecting...")
            global _session_id, _session_at
            _session_id = ""
            _session_at = 0
            continue
        if not r.ok:
            raise RuntimeError(f"{endpoint} HTTP {r.status_code}: {r.text[:100]}")
        return json.loads(r.json().get("messages", "[]"))

    raise RuntimeError(f"{endpoint} failed after reconnect")


# ── Device commands ───────────────────────────────────────────────────────────

def _send_command(cmd_code: int) -> dict:
    """Send open/close/stop command. Returns first message data dict."""
    action_dev = _creds.get("actionDeviceId")
    if not action_dev:
        raise HTTPException(status_code=500, detail="actionDeviceId not in credentials.json")

    data = json.dumps(
        {"deviceId": action_dev, "action": {"cmd": cmd_code}},
        separators=(",", ":"),
    )
    msgs = _post_encrypted(data, "app/res/action")
    log.info("Command cmd=%d -> %d messages", cmd_code, len(msgs))

    for m in msgs:
        ps = m.get("processState", -1)
        if ps == 1:
            # Process created — wait briefly and poll for result
            time.sleep(1.5)
            poll_msgs = _post_encrypted("", "app/res/messages")
            for pm in poll_msgs:
                if pm.get("processState") == 0:
                    try:
                        return json.loads(pm.get("data", "{}"))
                    except Exception:
                        return {"raw": pm.get("data", "")}
        elif ps == 0:
            try:
                return json.loads(m.get("data", "{}"))
            except Exception:
                return {"raw": m.get("data", "")}
        elif ps == -1:
            # Error
            try:
                err = json.loads(m.get("data", "{}"))
            except Exception:
                err = {"raw": m.get("data", "")}
            code = err.get("code", "?")
            desc = err.get("description", "unknown")
            raise HTTPException(status_code=502, detail=f"Hub error {code}: {desc}")

    return {"status": "sent", "messages": len(msgs)}


def _get_status() -> dict:
    """Get current door state via devices/fetch."""
    action_dev = _creds.get("actionDeviceId")
    if not action_dev:
        raise HTTPException(status_code=500, detail="actionDeviceId not in credentials.json")

    data = json.dumps({"deviceId": action_dev}, separators=(",", ":"))
    msgs = _post_encrypted(data, "app/res/devices/fetch")

    for m in msgs:
        if m.get("processState") == 0:
            try:
                payload = json.loads(m.get("data", "{}"))
                devices = payload.get("devices", [])
                if devices:
                    dev_obj = devices[0].get("device", {})
                    position = dev_obj.get("position", -1)
                    rate     = dev_obj.get("rate", 0)
                    door     = dev_obj.get("door", {})
                    # Determine state
                    if rate != 0:
                        state = "moving"
                    elif position == 0:
                        state = "closed"
                    elif position == 100:
                        state = "open"
                    else:
                        state = f"partial_{position}"
                    return {
                        "state":    state,
                        "position": position,
                        "rate":     rate,
                        "door":     door,
                        "name":     devices[0].get("name", ""),
                    }
            except Exception as e:
                log.warning("Failed to parse devices/fetch response: %s", e)

    return {"state": "unknown"}


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.post("/open")
def open_garage(_: None = Security(_require_key)):
    log.info("OPEN command requested")
    result = _send_command(CMD_OPEN)
    return {"command": "open", "result": result}


@app.post("/close")
def close_garage(_: None = Security(_require_key)):
    log.info("CLOSE command requested")
    result = _send_command(CMD_CLOSE)
    return {"command": "close", "result": result}


@app.post("/stop")
def stop_garage(_: None = Security(_require_key)):
    log.info("STOP command requested")
    result = _send_command(CMD_STOP)
    return {"command": "stop", "result": result}


@app.get("/status")
def get_status(_: None = Security(_require_key)):
    s = _get_status()
    # Return a flat, HA-friendly response
    return {
        "state":    s.get("state", "unknown"),   # closed / open / moving / partial_N / unknown
        "position": s.get("position", -1),        # 0–100
        "rate":     s.get("rate", 0),             # neg=closing, pos=opening, 0=stopped
    }


@app.get("/health")
def health():
    # Health is unauthenticated — safe to expose for uptime monitoring
    return {
        "status":        "ok",
        "session_age_s": round(time.time() - _session_at, 1) if _session_at else None,
    }

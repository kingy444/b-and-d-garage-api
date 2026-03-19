#!/usr/bin/env python3
"""
Full one-shot phone registration for B&D SmartDoorDevices hub.

Usage:
    python full_register.py <hub-ip> <activation_code> <user_password>

Steps:
    1. Extract hubId from hub TLS certificate
    2. Cloud register phone (app/remoteregister) with activation code
    3. LAN app/connect to get sessionSecret
    4. v3migrate (LAN) to register RSA key and get new phoneSecret + sdkPhonePassword
    5. sdk/auth to get session key
    6. setUserPassword to clear isPasswordExpired
    7. Discover devices to find actionDeviceId
    8. Write credentials.json and .env (ready for docker compose up -d)
"""
import base64
import hashlib
import hmac as _hmac
import json
import re
import secrets
import ssl
import sys
import time
import uuid
from pathlib import Path

import requests
import urllib3
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding as asym_padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from requests.adapters import HTTPAdapter

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Constants ──────────────────────────────────────────────────────────────────

CLOUD_BASE   = "https://version2.smartdoordevices.com"
CREDS_FILE   = Path("credentials.json")

# Set by main() from CLI argument — not hardcoded
LAN_8989 = ""
LAN_8991 = ""

# Fixed SDK phone password — stored in credentials.json so it's never lost
SDK_PHONE_PW = "GarageAPI2025stable"
PHONE_NAME   = "GarageAPI"
SDK_VERSION  = "3.7.0"

SDK_HEADERS = {
    "Content-Type": "application/json",
    "sdk": SDK_VERSION,
    "platform": "android",
}

# ── SSL adapter for legacy hub TLS ────────────────────────────────────────────

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


lan = requests.Session()
lan.mount("https://", LegacySSLAdapter())


# ── Hub discovery ──────────────────────────────────────────────────────────────

def hub_id_from_cert(hub_ip: str, port: int = 8989) -> str:
    """Extract hubId from the hub's TLS certificate Common Name."""
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
    with ssl.create_connection((hub_ip, port), timeout=10) as raw:
        with ctx.wrap_socket(raw) as ssock:
            cert_der = ssock.getpeercert(binary_form=True)
    from cryptography import x509
    cert    = x509.load_der_x509_certificate(cert_der)
    cn_list = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if not cn_list:
        raise RuntimeError("No CN found in hub TLS certificate")
    return cn_list[0].value


# ── Crypto helpers ─────────────────────────────────────────────────────────────

def aes256_enc(secret: str, iv_param: str, plaintext: str) -> str:
    """AES-256-CBC: key=SHA-256(secret), iv=SHA-256(iv_param)[:16]."""
    key = hashlib.sha256(secret.encode()).digest()
    iv  = hashlib.sha256(iv_param.encode()).digest()[:16]
    padder = PKCS7(128).padder()
    padded = padder.update(plaintext.encode()) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return base64.b64encode(enc.update(padded) + enc.finalize()).decode()


def aes256_dec(secret: str, iv_param: str, ciphertext_b64: str) -> str:
    """AES-256-CBC decrypt."""
    key = hashlib.sha256(secret.encode()).digest()
    iv  = hashlib.sha256(iv_param.encode()).digest()[:16]
    ct  = base64.b64decode(ciphertext_b64)
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = PKCS7(128).unpadder()
    return (unpadder.update(padded) + unpadder.finalize()).decode()


def aes256_dec_zeroiv(secret: str, ct_b64: str) -> str:
    """AES-256-CBC with zero IV — hub uses this for responses.
    Block 0 is garbled (unknown true IV); blocks 1+ are correct via CBC chaining."""
    key = hashlib.sha256(secret.encode()).digest()
    ct  = base64.b64decode(ct_b64)
    dec = Cipher(algorithms.AES(key), modes.CBC(b'\x00' * 16)).decryptor()
    pt  = dec.update(ct) + dec.finalize()
    # Remove PKCS7 padding
    pad = pt[-1]
    if 1 <= pad <= 16:
        pt = pt[:-pad]
    # Skip first 16 bytes (garbled block 0)
    return pt[16:].decode('utf-8', errors='replace')


def aes128_enc_md5(secret: str, ts_str: str, plaintext: str) -> str:
    """AES-128-CBC: key=MD5(secret), iv=MD5(ts_str). Used by v3migrate."""
    key = hashlib.md5(secret.encode()).digest()
    iv  = hashlib.md5(ts_str.encode()).digest()
    padder = PKCS7(128).padder()
    padded = padder.update(plaintext.encode()) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return base64.b64encode(enc.update(padded) + enc.finalize()).decode()


def aes128_dec_md5(secret: str, ts_str: str, ct_b64: str) -> str:
    """AES-128-CBC decrypt with MD5 key/iv. Used by v3migrate response."""
    key = hashlib.md5(secret.encode()).digest()
    iv  = hashlib.md5(ts_str.encode()).digest()
    ct  = base64.b64decode(ct_b64)
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = PKCS7(128).unpadder()
    return (unpadder.update(padded) + unpadder.finalize()).decode()


def hmac_b64(key: str, msg: str) -> str:
    return base64.b64encode(
        _hmac.new(key.encode(), msg.encode(), hashlib.sha256).digest()
    ).decode()


def rsa_sign(priv_key_b64: str, msg: str) -> str:
    """SHA512WithRSA sign using PKCS8 DER private key (base64)."""
    priv_key = serialization.load_der_private_key(base64.b64decode(priv_key_b64), password=None)
    return base64.b64encode(
        priv_key.sign(msg.encode(), asym_padding.PKCS1v15(), hashes.SHA512())
    ).decode()


def get_hub_ts() -> int:
    """Fetch hub mono timestamp (nanoseconds)."""
    try:
        r = lan.post(f"{LAN_8991}/sdk/info", headers=SDK_HEADERS, data="", timeout=10)
        if r.ok:
            mono = r.json().get("mono", 0)
            if mono > 0:
                return mono
    except Exception:
        pass
    return int(time.time() * 1000)


def send_sdk_message(hub_id: str, phone_id: str, phone_secret: str,
                     phone_key_b64: str, cmd: str, mac_key: str, ts: int) -> dict:
    """Build, sign, and send a sdk/message request."""
    req_id    = "req" + uuid.uuid4().hex[:12]
    encrypted = aes256_enc(phone_secret, str(ts), cmd)
    signing   = f"{hub_id}:{phone_id}:{ts}:{req_id}:{encrypted}"
    mac       = mac_key if mac_key == "NOKEY" else hmac_b64(mac_key, signing)
    sig       = rsa_sign(phone_key_b64, signing) if phone_key_b64 else None
    body = {
        "hubId":     hub_id,
        "phoneId":   phone_id,
        "requestId": req_id,
        "time":      ts,
        "request":   encrypted,
        "signature": sig,
        "mac":       mac,
    }
    r = lan.post(f"{LAN_8991}/sdk/message", headers=SDK_HEADERS, json=body, timeout=15)
    return r.json()


def action_device_id_from_parsed(data: dict) -> str | None:
    """Extract actionDeviceId from a parsed SDK response.

    Hub SDK responses include a 'devicePermissions' object whose keys are the
    actionDeviceId strings (e.g. {"cWepe5Rn": {"accessLevel": 3, ...}}).
    This was discovered during reverse engineering by decrypting sdk/auth and
    setUserPassword responses — the devicePermissions key is the value required
    for all app-protocol device operations.
    """
    perms = data.get("devicePermissions") or (data.get("data") or {}).get("devicePermissions")
    if isinstance(perms, dict) and perms:
        return next(iter(perms))
    return None


def parse_sdk_response(resp_json: dict, phone_secret: str, ts: int) -> dict:
    """Try to parse hub response (plain JSON, AES-decrypted, or zero-IV).
    Falls back to regex extraction when the first 16 bytes are garbled."""
    raw = resp_json.get("response", "")
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except Exception:
        pass
    try:
        return json.loads(aes256_dec(phone_secret, str(ts), raw))
    except Exception:
        pass

    # Try zero-IV decrypt; JSON parse may fail due to garbled first block,
    # but regex can still recover errorCode and devicePermissions.
    try:
        text = aes256_dec_zeroiv(phone_secret, raw)
    except Exception:
        return {"_raw": raw}

    try:
        return json.loads(text)
    except Exception:
        pass

    # Regex fallback — mirrors extract_session_key behaviour
    result: dict = {}
    m = re.search(r'"errorCode"\s*:\s*(-?\d+)', text)
    if m:
        result["errorCode"] = int(m.group(1))
    m = re.search(r'"state"\s*:\s*(-?\d+)', text)
    if m:
        result["state"] = int(m.group(1))
    m = re.search(r'"devicePermissions"\s*:\s*\{"([^"]+)"', text)
    if m:
        result["devicePermissions"] = {m.group(1): {}}
    return result if result else {"_raw": raw}


def extract_session_key(resp_json: dict, phone_secret: str) -> tuple[str | None, str | None]:
    """Extract session key (and actionDeviceId if present) from sdk/auth response.

    Returns (session_key, action_device_id) — either may be None.
    The actionDeviceId appears as a key in 'devicePermissions' in the decrypted
    response payload.
    """
    raw = resp_json.get("response", "")
    if not raw:
        return None, None

    def _scan(data: dict) -> tuple[str | None, str | None]:
        key = data.get("key") or (data.get("data") or {}).get("key")
        did = action_device_id_from_parsed(data)
        return (key or None), (did or None)

    # Try 1: unencrypted JSON
    try:
        k, d = _scan(json.loads(raw))
        if k:
            return k, d
    except Exception:
        pass

    # Try 2: zero-IV AES-256 decryption (hub SDK response format)
    # aes256_dec_zeroiv already skips the first garbled 16-byte block
    try:
        text = aes256_dec_zeroiv(phone_secret, raw)
    except Exception:
        return None, None

    # Try JSON parse on the decrypted text
    try:
        k, d = _scan(json.loads(text))
        if k:
            return k, d
    except Exception:
        pass

    # Regex fallback — works even when JSON is partially garbled
    m   = re.search(r'"key"\s*:\s*"([^"]+)"', text)
    d_m = re.search(r'"devicePermissions"\s*:\s*\{"([^"]+)"', text)
    if m:
        return m.group(1), (d_m.group(1) if d_m else None)

    return None, None


# ── Step 1: Cloud registration ─────────────────────────────────────────────────

def cloud_register(hub_id: str, activation_code: str, temp_password: str) -> dict:
    print(f"\n=== Step 1: Cloud register (code={activation_code}) ===")
    r = requests.post(f"{CLOUD_BASE}/app/remoteregister", verify=False, timeout=20, json={
        "bsid":                   hub_id,
        "remoteRegistrationCode": activation_code,
        "userPassword":           temp_password,
        "phoneName":              PHONE_NAME,
        "phoneModel":             PHONE_NAME,
    })
    print(f"  HTTP {r.status_code}: {r.text[:300]}")
    r.raise_for_status()
    reg = r.json()
    phone_id     = reg["phoneId"]
    phone_pw     = reg["phonePassword"]
    phone_secret = reg.get("phoneSecret", "")
    user_id      = str(reg.get("userId", ""))
    print(f"  phoneId:       {phone_id}")
    print(f"  phonePassword: {phone_pw}")
    print(f"  phoneSecret:   {phone_secret[:20]}..." if phone_secret else "  phoneSecret:   (none)")
    print(f"  userId:        {user_id}")
    return {"phoneId": phone_id, "phonePassword": phone_pw, "phoneSecret": phone_secret, "userId": user_id}


# ── Step 2: LAN app/connect ────────────────────────────────────────────────────

def lan_connect(hub_id: str, phone_id: str, phone_pw: str, user_pw: str) -> dict:
    print(f"\n=== Step 2: LAN app/connect ===")
    r = lan.post(f"{LAN_8989}/app/connect", timeout=10, json={
        "bsid":              hub_id,
        "phoneId":           phone_id,
        "phonePassword":     phone_pw,
        "userPassword":      user_pw,
        "communicationType": 3,
    })
    print(f"  HTTP {r.status_code}: {r.text[:300]}")
    if not r.ok:
        raise RuntimeError(f"LAN app/connect failed: {r.status_code} {r.text[:200]}")
    resp = r.json()
    session_id     = resp.get("sessionId", "")
    session_secret = resp.get("sessionSecret", "")
    data           = resp.get("data", {})
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except Exception:
            data = {}
    print(f"  sessionId:         {session_id}")
    print(f"  sessionSecret:     {session_secret[:20]}..." if session_secret else "  sessionSecret: (none)")
    print(f"  isPasswordExpired: {data.get('isPasswordExpired', '?')}")
    print(f"  communicationType: {resp.get('communicationType')}")
    return {"sessionId": session_id, "sessionSecret": session_secret, "data": data}


# ── Step 3: v3migrate ──────────────────────────────────────────────────────────

def v3migrate(hub_id: str, phone_id: str, phone_secret: str,
              phone_pw: str, user_pw: str, session_secret: str) -> dict:
    """Register RSA key with hub. Returns new phoneSecret and RSA private key."""
    print(f"\n=== Step 3: v3migrate (LAN) ===")

    # Generate RSA-2048 key pair
    rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_priv_der_b64 = base64.b64encode(
        rsa_priv.private_bytes(serialization.Encoding.DER,
                               serialization.PrivateFormat.PKCS8,
                               serialization.NoEncryption())
    ).decode()
    # Hub expects last 270 bytes of DER (raw RSA public key, not SubjectPublicKeyInfo header)
    rsa_pub_der = rsa_priv.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    rsa_pub_raw_b64 = base64.b64encode(rsa_pub_der[-270:]).decode()

    # Generate EC-P256 key pair for ECDH
    ec_priv = ec.generate_private_key(ec.SECP256R1())
    ec_pub_nums = ec_priv.public_key().public_numbers()
    # Hub expects raw uncompressed point: 04 || x (32 bytes) || y (32 bytes)
    ec_pub_raw_b64 = base64.b64encode(
        bytes([4]) + ec_pub_nums.x.to_bytes(32, "big") + ec_pub_nums.y.to_bytes(32, "big")
    ).decode()

    ts_ms = int(time.time() * 1000)

    # Build encrypted inner data
    inner_data = json.dumps({
        "phoneKey":                rsa_pub_raw_b64,
        "newPhoneSecretPhoneHalf": ec_pub_raw_b64,
        "newPhonePassword":        SDK_PHONE_PW,
    }, separators=(",", ":"))
    enc_data = aes128_enc_md5(phone_secret, str(ts_ms), inner_data)

    # RSA sign enc_data only
    signature = base64.b64encode(
        rsa_priv.sign(enc_data.encode(), asym_padding.PKCS1v15(), hashes.SHA512())
    ).decode()

    body = {
        "bsid":          hub_id,
        "phoneId":       phone_id,
        "phoneKey":      rsa_pub_raw_b64,
        "phonePassword": phone_pw,
        "userPassword":  user_pw,
        "data":          enc_data,
        "time":          ts_ms,
        "signature":     signature,
    }

    r = lan.post(f"{LAN_8989}/app/v3migrate", headers=SDK_HEADERS, json=body, timeout=20)
    print(f"  HTTP {r.status_code}: {r.text[:400]}")

    if not r.ok:
        raise RuntimeError(f"v3migrate failed: {r.status_code} {r.text[:300]}")

    resp = r.json()
    migration_b64 = resp.get("migrationData", "")

    new_phone_secret = phone_secret  # fallback if ECDH fails
    hub_key_b64 = ""

    if migration_b64:
        try:
            # Hub encrypts migrationData with AES-128, IV = MD5(phoneId)
            dec_text = aes128_dec_md5(phone_secret, resp.get("phoneId", phone_id), migration_b64)
            print(f"  Decrypted migrationData: {dec_text[:300]}")
            migration = json.loads(dec_text)

            hub_key_b64      = migration.get("newHubKey", "")
            hub_ec_half_b64  = migration.get("newPhoneSecretHubHalf", "")

            if hub_ec_half_b64:
                # Hub EC key is raw uncompressed (65 bytes starting with 04)
                _EC_HDR = bytes([0x30,0x59,0x30,0x13,0x06,0x07,0x2A,0x86,0x48,0xCE,
                                 0x3D,0x02,0x01,0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,
                                 0x03,0x01,0x07,0x03,0x42,0x00])
                hub_ec_pub   = serialization.load_der_public_key(
                    _EC_HDR + base64.b64decode(hub_ec_half_b64))
                shared_bytes = ec_priv.exchange(ec.ECDH(), hub_ec_pub)
                new_phone_secret = base64.b64encode(shared_bytes).decode()
                print(f"  ECDH new phoneSecret: {new_phone_secret[:20]}...")
            else:
                print("  WARNING: no newPhoneSecretHubHalf — keeping old phoneSecret")
        except Exception as e:
            print(f"  WARNING: could not decrypt/parse migrationData: {e}")
            print(f"  Raw migrationData: {migration_b64[:200]}")
    else:
        print(f"  WARNING: no migrationData in response. Keys: {list(resp.keys())}")

    print(f"  v3migrate done. sdkPhonePassword={SDK_PHONE_PW}")
    return {
        "rsa_priv_b64":     rsa_priv_der_b64,
        "new_phone_secret": new_phone_secret,
        "hub_key_b64":      hub_key_b64,
    }


# ── Step 4: sdk/auth → session key ────────────────────────────────────────────

def sdk_auth(hub_id: str, phone_id: str, phone_secret: str,
             phone_key_b64: str, user_pw: str) -> tuple[str | None, str | None]:
    """Authenticate via SDK protocol. Returns (session_key, action_device_id).

    The hub embeds 'devicePermissions' in the auth response, keyed by actionDeviceId.
    This is how actionDeviceId is discovered automatically during registration.
    """
    print(f"\n=== Step 4: sdk/auth -> session key + actionDeviceId ===")
    auth_cmd = json.dumps({
        "path": "auth",
        "data": {
            "userPassword":  user_pw,
            "phonePassword": SDK_PHONE_PW,
            "temporary":     False,
        }
    }, separators=(",", ":"))

    for label, mac_key in [("NOKEY", "NOKEY"), ("SDK_PHONE_PW", SDK_PHONE_PW),
                            ("phoneSecret", phone_secret)]:
        try:
            ts = get_hub_ts()
            resp = send_sdk_message(hub_id, phone_id, phone_secret, phone_key_b64,
                                    auth_cmd, mac_key, ts)
            resp_mac = resp.get("mac", "?")
            raw      = resp.get("response", "")
            print(f"  [{label}] mac={resp_mac} | raw={raw[:80]}")
            if resp_mac == "INVALID":
                continue
            key, did = extract_session_key(resp, phone_secret)
            if key:
                print(f"  OK session key: {key[:20]}...")
                if did:
                    print(f"  OK actionDeviceId: {did}")
                return key, did
        except Exception as e:
            print(f"  [{label}] error: {e}")

    print("  FAIL Could not obtain session key")
    return None, None


# ── Step 5: setUserPassword ────────────────────────────────────────────────────

def set_user_password(hub_id: str, phone_id: str, phone_secret: str,
                      phone_key_b64: str, session_key: str, user_pw: str,
                      user_id: str = "") -> tuple[bool, str | None]:
    """Clear isPasswordExpired. Returns (success, action_device_id).

    Like sdk/auth, the hub may include devicePermissions in the response,
    providing a second opportunity to capture the actionDeviceId.
    """
    print(f"\n=== Step 5: setUserPassword (clear isPasswordExpired) ===")
    data = {"oldPassword": user_pw, "newPassword": user_pw}
    if user_id:
        data["userId"] = user_id
    cmd = json.dumps({"path": "setUserPassword", "data": data}, separators=(",", ":"))

    for label, mac_key in [("session_key", session_key), ("SDK_PHONE_PW", SDK_PHONE_PW),
                            ("phoneSecret", phone_secret), ("NOKEY", "NOKEY")]:
        if not mac_key:
            continue
        try:
            ts   = get_hub_ts()
            resp = send_sdk_message(hub_id, phone_id, phone_secret, phone_key_b64,
                                    cmd, mac_key, ts)
            inner    = parse_sdk_response(resp, phone_secret, ts)
            resp_mac = resp.get("mac", "?")
            err_code = inner.get("errorCode", "?")
            did      = action_device_id_from_parsed(inner)
            print(f"  [{label}] mac={resp_mac} | errorCode={err_code} | state={inner.get('state','?')}")
            if resp_mac != "INVALID" and err_code == 0:
                print(f"  OK isPasswordExpired cleared")
                if did:
                    print(f"  OK actionDeviceId: {did}")
                return True, did
        except Exception as e:
            print(f"  [{label}] error: {e}")

    print("  FAIL setUserPassword did not return errorCode=0")
    return False, None


# ── Step 6: getDeviceState ─────────────────────────────────────────────────────

def get_device_state(hub_id: str, phone_id: str, phone_secret: str,
                     phone_key_b64: str, session_key: str, device_id: str) -> dict:
    print(f"\n=== Step 6: getDeviceState (verify SDK) ===")
    ts  = get_hub_ts()
    cmd = json.dumps({
        "path": "getDeviceState",
        "data": {"deviceId": int(device_id)},
    }, separators=(",", ":"))
    resp     = send_sdk_message(hub_id, phone_id, phone_secret, phone_key_b64,
                                cmd, session_key, ts)
    raw      = resp.get("response", "")
    resp_mac = resp.get("mac", "?")
    print(f"  mac={resp_mac} | raw={raw[:120]}")
    inner = parse_sdk_response(resp, phone_secret, ts)
    print(f"  Parsed: {json.dumps(inner)[:300]}")
    return inner


# ── Step 7: discover devices via app protocol ──────────────────────────────────

APP_HEADERS_DISCOVER = {
    "Content-Type": "application/json",
    "version":      "2.21.1",
    "app-version":  "1.2.3",
}


def discover_devices(hub_id: str, phone_id: str, phone_pw: str,
                     phone_secret: str, user_pw: str) -> list:
    """Connect with app protocol, fetch all devices, return list of (name, actionDeviceId)."""
    print(f"\n=== Step 7: Discover devices ===")

    # Fresh app/connect
    r = lan.post(f"{LAN_8989}/app/connect", timeout=10, json={
        "bsid":              hub_id,
        "phoneId":           phone_id,
        "phonePassword":     phone_pw,
        "userPassword":      user_pw,
        "communicationType": 1,
    })
    if not r.ok:
        print(f"  app/connect failed: {r.status_code} — skipping device discovery")
        return []
    conn           = r.json()
    session_id     = conn["sessionId"]
    session_secret = conn["sessionSecret"]
    print(f"  sessionId: {session_id[:12]}...")

    # Encrypt an empty fetch to list all devices
    ts        = int(time.time() * 1000)
    data_json = "{}"
    encrypted = aes128_enc_md5(phone_secret, str(ts), data_json)
    signing   = f"{ts}:{encrypted}"
    body = {
        "bsid":        hub_id,
        "sessionId":   session_id,
        "time":        ts,
        "data":        encrypted,
        "processId":   "0",
        "sessionSig":  hmac_b64(session_secret, signing),
        "phoneSig":    hmac_b64(phone_secret, signing),
        "isEncrypted": True,
    }
    r2 = lan.post(f"{LAN_8989}/app/res/devices/fetch",
                  headers=APP_HEADERS_DISCOVER, json=body, timeout=15)
    if not r2.ok:
        print(f"  devices/fetch failed: {r2.status_code} — skipping device discovery")
        return []

    try:
        msgs = json.loads(r2.json().get("messages", "[]"))
    except Exception:
        print("  Could not parse messages — skipping device discovery")
        return []

    found = []
    for m in msgs:
        if m.get("processState") == 0:
            try:
                payload = json.loads(m.get("data", "{}"))
                for dev_entry in payload.get("devices", []):
                    dev = dev_entry.get("device", {})
                    name = dev_entry.get("name", "") or dev.get("name", "")
                    dev_id = dev_entry.get("deviceId") or dev.get("deviceId") or dev.get("id")
                    if dev_id:
                        found.append((name, str(dev_id)))
                        print(f"  Found: {name!r}  actionDeviceId={dev_id}")
            except Exception as e:
                print(f"  Parse error: {e}")

    if not found:
        print("  No devices found in response (hub may require a specific deviceId).")
    return found


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 4:
        print("Usage: python full_register.py <hub-ip> <activation_code> <user_password>")
        sys.exit(1)

    hub_ip          = sys.argv[1]
    activation_code = sys.argv[2]
    temp_password   = sys.argv[3]

    global LAN_8989, LAN_8991
    LAN_8989 = f"https://{hub_ip}:8989"
    LAN_8991 = f"https://{hub_ip}:8991"

    existing = json.loads(CREDS_FILE.read_text()) if CREDS_FILE.exists() else {}
    user_pw  = temp_password

    # Step 0: extract hubId from hub TLS certificate
    print(f"\n=== Step 0: Extract hubId from hub certificate ({hub_ip}:8989) ===")
    try:
        hub_id = hub_id_from_cert(hub_ip)
        print(f"  hubId: {hub_id}")
    except Exception as e:
        print(f"  ERROR: {e}")
        print("  Check the hub IP and that the hub is powered on and reachable.")
        sys.exit(1)

    print(f"Hub IP: {hub_ip}")

    # Step 1: Cloud register
    reg          = cloud_register(hub_id, activation_code, temp_password)
    phone_id     = reg["phoneId"]
    phone_pw     = reg["phonePassword"]
    phone_secret = reg["phoneSecret"]
    user_id      = reg["userId"]

    if not phone_secret:
        print("\nWARNING: phoneSecret is empty — v3migrate will likely fail.")

    # Step 2: LAN connect
    conn           = lan_connect(hub_id, phone_id, phone_pw, user_pw)
    session_secret = conn["sessionSecret"]

    # Step 3: v3migrate
    mig              = v3migrate(hub_id, phone_id, phone_secret,
                                 phone_pw, user_pw, session_secret)
    rsa_priv_b64     = mig["rsa_priv_b64"]
    new_phone_secret = mig["new_phone_secret"]
    hub_key_b64      = mig["hub_key_b64"]

    # Save immediately after v3migrate so keys are never lost to a later crash
    partial_creds = {
        "hubId":            hub_id,
        "phoneId":          phone_id,
        "phonePassword":    phone_pw,
        "phoneKey":         rsa_priv_b64,
        "phoneSecret":      new_phone_secret,
        "sdkPhonePassword": SDK_PHONE_PW,
        "userPassword":     user_pw,
        "userId":           user_id,
        "hubKey":           hub_key_b64,
    }
    CREDS_FILE.write_text(json.dumps(partial_creds, indent=2))
    print(f"  [checkpoint] credentials saved after v3migrate")

    # Step 4: sdk/auth — also captures actionDeviceId from devicePermissions
    session_key, action_device_id = sdk_auth(hub_id, phone_id, new_phone_secret, rsa_priv_b64, user_pw)

    # Step 5: setUserPassword — second opportunity to capture actionDeviceId
    cleared = False
    if session_key:
        cleared, did5 = set_user_password(hub_id, phone_id, new_phone_secret,
                                          rsa_priv_b64, session_key, user_pw, user_id)
        action_device_id = action_device_id or did5
    else:
        print("\nSkipping setUserPassword — no session key")

    # Step 6: fallback device discovery via app protocol (if SDK steps didn't yield actionDeviceId)
    if not action_device_id:
        devices = discover_devices(hub_id, phone_id, phone_pw, new_phone_secret, user_pw)
        if devices:
            if len(devices) == 1:
                action_device_id = devices[0][1]
                print(f"  Auto-selected actionDeviceId: {action_device_id} ({devices[0][0]})")
            else:
                print("\nMultiple devices found. Enter the number of your garage door:")
                for i, (name, did) in enumerate(devices):
                    print(f"  {i + 1}. {name!r}  ({did})")
                while True:
                    try:
                        choice = int(input("Choice: ").strip()) - 1
                        if 0 <= choice < len(devices):
                            action_device_id = devices[choice][1]
                            break
                    except (ValueError, KeyboardInterrupt):
                        pass
                    print("  Invalid — enter a number from the list.")

    # Last resort: preserve from previous credentials.json if present
    if not action_device_id:
        action_device_id = existing.get("actionDeviceId", "")
        if action_device_id:
            print(f"  Preserved actionDeviceId from existing credentials: {action_device_id}")
        else:
            print("\nWARNING: Could not discover actionDeviceId automatically.")
            print("  Set GARAGE_ACTIONDEVICEID in your .env manually.")

    # Re-check isPasswordExpired
    print(f"\n=== Re-check LAN app/connect ===")
    try:
        r_check = lan.post(f"{LAN_8989}/app/connect", timeout=10, json={
            "bsid":              hub_id,
            "phoneId":           phone_id,
            "phonePassword":     phone_pw,
            "userPassword":      user_pw,
            "communicationType": 3,
        })
        if r_check.ok:
            check_data = r_check.json().get("data", {})
            if isinstance(check_data, str):
                try: check_data = json.loads(check_data)
                except Exception: check_data = {}
            print(f"  isPasswordExpired: {check_data.get('isPasswordExpired', '?')}")
            print(f"  communicationType: {r_check.json().get('communicationType')}")
    except Exception as e:
        print(f"  re-check failed: {e}")

    # Save credentials.json
    creds = {
        "hubId":            hub_id,
        "phoneId":          phone_id,
        "phonePassword":    phone_pw,         # app/connect password
        "phoneKey":         rsa_priv_b64,     # RSA-2048 PKCS8 DER base64
        "phoneSecret":      new_phone_secret, # ECDH-derived (or original if ECDH failed)
        "sdkPhonePassword": SDK_PHONE_PW,     # sdk/auth password (newPhonePassword from v3migrate)
        "userPassword":     user_pw,
        "userId":           user_id,
        "hubKey":           hub_key_b64,
        "actionDeviceId":   action_device_id,
    }
    CREDS_FILE.write_text(json.dumps(creds, indent=2))
    print(f"\nOK Saved {CREDS_FILE}")

    # Write .env — preserve existing API key if already set
    env_file = Path(".env")
    existing_env: dict[str, str] = {}
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            if "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                existing_env[k.strip()] = v.strip()

    api_key = existing_env.get("GARAGE_API_KEY") or secrets.token_hex(32)

    env_content = (
        f"GARAGE_API_KEY={api_key}\n"
        f"GARAGE_HUBIP={hub_ip}\n"
        f"GARAGE_PHONEID={phone_id}\n"
        f"GARAGE_PHONEPASSWORD={phone_pw}\n"
        f"GARAGE_PHONESECRET={new_phone_secret}\n"
        f"GARAGE_USERPASSWORD={user_pw}\n"
        f"GARAGE_HUBID={hub_id}\n"
        f"GARAGE_ACTIONDEVICEID={action_device_id}\n"
    )
    env_file.write_text(env_content)
    print(f"OK Saved .env")

    print(f"\n{'=' * 60}")
    print(f"Setup complete!")
    print(f"  API key:        {api_key}")
    print(f"  actionDeviceId: {action_device_id or '(not found — set GARAGE_ACTIONDEVICEID manually)'}")
    print(f"  isExpiredCleared: {cleared}")
    print(f"\nNext step:  docker compose up -d")
    print(f"\nKeep your API key — you will need it for Home Assistant and Siri Shortcuts.")
    if not action_device_id:
        print(f"\nWARNING: actionDeviceId was not discovered automatically.")
        print(f"  Set GARAGE_ACTIONDEVICEID in .env before deploying.")


if __name__ == "__main__":
    main()

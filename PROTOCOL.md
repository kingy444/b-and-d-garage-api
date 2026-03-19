# B&D SmartDoorDevices Protocol — Reverse Engineering Notes

This document records the research and reverse engineering that underpins this project:
how the B&D garage hub's LAN protocol was discovered, how authentication works, the
cryptography involved, all known endpoints, and how each credential is obtained.

---

## Background

The B&D Smart Garage Access system uses a proprietary hub (the "Basestation") that
communicates with the cloud service at `https://version2.smartdoordevices.com` and
exposes a LAN API on the local network. The official app (Android and iOS) is the only
intended client.

This project reverse-engineered the LAN protocol to enable direct control without
cloud dependency, enabling low-latency local control and integration with Home Assistant
and Siri Shortcuts.

---

## Reverse Engineering Approach

### Tools and method

**Primary: APK decompilation with jadx**

The official B&D Smart Garage Access Android app (`.xapk`) was obtained and decompiled
using `jadx`. The decompiled Java/Kotlin source revealed:
- All API endpoint paths (both cloud and LAN)
- Request and response structure for each endpoint
- Cryptographic algorithms, key derivation, and signing logic
- The two-port architecture (8989 app protocol, 8991 SDK protocol)
- Version strings required in request headers

**iOS app analysis**

The iOS IPA was extracted and cross-referenced to confirm endpoint behaviour and
recover any iOS-specific constants. Findings were consistent with the Android app.

**Traffic interception (attempted, blocked)**

mitmproxy was set up in Docker to intercept HTTPS traffic from the app. The app
performs certificate pinning and rejected the mitmproxy CA certificate, so no traffic
was captured this way. All protocol knowledge came from static analysis of the
decompiled source.

**Direct LAN probing**

Once the protocol structure was understood from decompilation, Python scripts were
written to send crafted requests directly to the hub and observe responses. This
confirmed the decompiled logic and revealed empirical details such as:
- Which `phoneSecret` value the hub actually uses for decryption (the original cloud
  registration value, not the ECDH-derived one from `v3migrate`)
- The zero-IV decryption behaviour for SDK responses
- The `devicePermissions` key structure that exposes `actionDeviceId`
- Rate limiting behaviour via `nextAccess`

**Hub TLS certificate**

Connecting to the hub's TLS port and reading the server certificate revealed that the
`hubId` is encoded in the certificate's Common Name field. This became the basis for
`hub_id_from_cert()`, allowing automatic discovery without any manual lookup.

### Key findings summary

- The hub exposes **two independent LAN APIs** on separate ports:
  - Port **8989**: "App protocol" — used for sessions, device control, and status
  - Port **8991**: "SDK protocol" — newer signed-message protocol used for registration
    and advanced operations
- Cloud registration is required once to obtain phone credentials. All subsequent
  control is entirely local — no cloud dependency at runtime.
- The `phoneSecret` for app-protocol encryption is the value from cloud registration,
  **not** the ECDH-derived value from the `v3migrate` step. The hub does not apply the
  ECDH update in practice despite the migration completing successfully.
- The `actionDeviceId` (required for all device operations) is embedded as a key in the
  `devicePermissions` object in the `setUserPassword` SDK response. Because the first
  16 decrypted bytes are garbled (zero-IV), JSON parsing fails, so `full_register.py`
  uses regex extraction — no manual lookup required.

---

## Network Architecture

```
iPhone / HA / this API
         │
         │  HTTPS (TLS, reverse proxy + Cloudflare)
         ▼
  this FastAPI service  (port 8080 / mapped externally)
         │
         │  HTTPS (TLS 1.0, self-signed cert, LAN only)
         ▼
    B&D Hub / Basestation
     ├── :8989  App protocol  (sessions, device control, status)
     └── :8991  SDK protocol  (registration, signed messages)
         │
         │  Proprietary RF / wired
         ▼
   Garage door motor
```

---

## TLS Details

The hub presents a self-signed certificate issued by "SmartDoorDevices Engineering".

```
Issuer:  C=AU, ST=VIC, L=Melbourne, O=SmartDoorDevices, OU=Engineering, CN=Basestation CA
Subject: OU=Hub, O=SmartDoorDevices, CN=<hubId>
```

The certificate's Common Name **is** the `hubId`. `full_register.py` connects to port
8989, reads the certificate, and extracts the CN to obtain the `hubId` automatically.

Connecting to the hub requires relaxed TLS settings — it does not support modern TLS:
- `ssl.CERT_NONE` — no CA verification (self-signed cert)
- `check_hostname = False`
- `minimum_version = TLSv1` — hub does not negotiate TLS 1.2+
- `set_ciphers("DEFAULT:@SECLEVEL=0")` — hub uses weak cipher suites

---

## App Protocol — Port 8989

All requests are JSON over HTTPS. Action and status requests use an AES-encrypted,
HMAC-signed payload envelope.

### Headers

```
Content-Type: application/json
version: 2.21.1
app-version: 1.2.3
```

These version strings were extracted from the decompiled app. If the hub firmware is
upgraded and rejects older version strings, they may need updating.

### Session establishment: `POST /app/connect`

Authenticates the phone and establishes a session. The request body is not encrypted.

**Request:**
```json
{
  "bsid":              "<hubId>",
  "phoneId":           "<phoneId>",
  "phonePassword":     "<phonePassword>",
  "userPassword":      "<userPassword>",
  "communicationType": 1
}
```

**Response:**
```json
{
  "sessionId":         "<sessionId>",
  "sessionSecret":     "<sessionSecret>",
  "communicationType": 1,
  "data": "{\"userAccess\":{\"isAccessReady\":false,\"nextAccess\":<ts_ms>}}"
}
```

- `sessionId` and `sessionSecret` are used to sign all subsequent encrypted requests.
- `data.userAccess.nextAccess` is a millisecond timestamp. The hub rate-limits commands
  and will reject requests sent before this time. Wait if `nextAccess > now`.
- Sessions expire after approximately 2 minutes; reconnecting is fast.

### Encrypted request envelope

All action and status endpoints use this request structure:

```json
{
  "bsid":        "<hubId>",
  "sessionId":   "<sessionId>",
  "time":        <timestamp_ms>,
  "data":        "<base64-AES128-encrypted-payload>",
  "processId":   "0",
  "sessionSig":  "<base64-HMAC-SHA256>",
  "phoneSig":    "<base64-HMAC-SHA256>",
  "isEncrypted": true
}
```

See the **Cryptography** section for how `data`, `sessionSig`, and `phoneSig`
are computed.

### Send a command: `POST /app/res/action`

**Plaintext payload (before encryption):**
```json
{"deviceId": "<actionDeviceId>", "action": {"cmd": <N>}}
```

Command codes:
| Code | Action |
|------|--------|
| 2    | Open   |
| 4    | Close  |
| 3    | Stop   |

**Response:** The hub returns a `messages` JSON array. Each message has a `processState`:
- `1` — command accepted, still processing. Poll `app/res/messages` for the result.
- `0` — completed. The `data` field contains the result JSON.
- `-1` — error. The `data` field contains `{"code": N, "description": "..."}`.

### Poll for result: `POST /app/res/messages`

Used when a command returns `processState == 1`. Send with an empty encrypted payload.
Returns the same message structure as `app/res/action`.

### Get device state: `POST /app/res/devices/fetch`

**Plaintext payload:**
```json
{"deviceId": "<actionDeviceId>"}
```

**Decrypted response data:**
```json
{
  "devices": [{
    "name": "The garage door",
    "device": {
      "position": 0,
      "rate": 0,
      "door": {"icon": "0050", "title": "0"}
    }
  }]
}
```

- `position`: 0 = fully closed, 100 = fully open, values in between = partially open
- `rate`: negative = closing, positive = opening, 0 = stationary
- `door.icon`: internal icon code used by the app UI

**Note on device identity:** This endpoint requires the `actionDeviceId` — a short
alphanumeric string (e.g. `cWepe5Rn`). Sending `{}` or any wildcard returns an empty
devices array; the hub requires an exact ID. See the **Credentials** section for how
this value is obtained automatically during registration.

---

## SDK Protocol — Port 8991

A newer, more secure protocol introduced alongside `v3migrate`. Uses RSA-2048 signing
and AES-256-CBC encryption. Required for initial phone registration; not used for
normal open/close/status operations (those use the app protocol on 8989).

### `POST /sdk/info`

Unauthenticated. Returns the hub's monotonic clock in nanoseconds, used as the
timestamp for SDK message signing.

```json
{"mono": <nanoseconds>}
```

### `POST /sdk/message`

All SDK operations are sent via this single endpoint with a `path` field in the
encrypted command body.

**Request envelope:**
```json
{
  "hubId":     "<hubId>",
  "phoneId":   "<phoneId>",
  "requestId": "<random-string>",
  "time":      <timestamp>,
  "request":   "<base64-AES256-encrypted-command>",
  "signature": "<base64-RSA-SHA512-signature>",
  "mac":       "<base64-HMAC-SHA256-mac>"
}
```

The MAC key depends on auth state:
- Before `sdk/auth`: send the literal string `"NOKEY"` as the mac value
- After `sdk/auth`: use the session key returned by auth

**Encrypted command body structure:**
```json
{"path": "<command>", "data": {<command-specific fields>}}
```

### Known SDK commands

**`path: "auth"`** — Authenticate and obtain a session key.

```json
{
  "path": "auth",
  "data": {
    "userPassword":  "<userPassword>",
    "phonePassword": "<sdkPhonePassword>",
    "temporary":     false
  }
}
```

The response is AES-256-CBC encrypted with a zero IV (see Cryptography section).
Decrypting the response yields the session key:

```json
{
  "data": {"session": {"value": 0}, "key": "<session_key>", "expiresIn": 0},
  "appTimeout": 0,
  "errorCode": 0,
  "state": 0
}
```

**Note:** For Standard users, `devicePermissions` is **not** present in the `auth`
response. It appears in the `setUserPassword` response instead (see below).

**`path: "setUserPassword"`** — Clears the `isPasswordExpired` flag.

```json
{
  "path": "setUserPassword",
  "data": {
    "oldPassword": "<userPassword>",
    "newPassword": "<userPassword>",
    "userId":      "<userId>"
  }
}
```

The response is encrypted with the same zero-IV AES-256 scheme. The decrypted payload
contains `devicePermissions` — this is where `full_register.py` discovers the
`actionDeviceId`. The first 16 bytes of the decrypted payload are garbled (as with all
zero-IV responses), so JSON parsing often fails; `full_register.py` uses a regex
fallback to extract `devicePermissions` and `errorCode` directly from the raw text:

```json
{
  "errorCode": 0,
  "devicePermissions": {
    "<actionDeviceId>": {"accessLevel": 3, ...}
  }
}
```

**`path: "getDeviceState"`** — Get state of a device using the numeric device ID.

```json
{"path": "getDeviceState", "data": {"deviceId": <numeric_device_id>}}
```

This uses a separate numeric device ID (e.g. `4052079990`) which is distinct from
the alphanumeric `actionDeviceId` used in the app protocol. This numeric ID is not
required for normal operations and is not used by this project.

---

## Cloud API — `https://version2.smartdoordevices.com`

Used only during initial phone registration. All runtime operations are LAN-only.

### `POST /app/remoteregister`

Registers a new virtual phone using a one-time activation code generated in the app.

**Request:**
```json
{
  "bsid":                   "<hubId>",
  "remoteRegistrationCode": "<activation_code>",
  "userPassword":           "<password>",
  "phoneName":              "GarageAPI",
  "phoneModel":             "GarageAPI"
}
```

**Response:**
```json
{
  "phoneId":       "<phoneId>",
  "phonePassword": "<phonePassword>",
  "phoneSecret":   "<phoneSecret>",
  "userId":        "<userId>",
  "isAdmin":       false,
  "userName":      "<name set in app>"
}
```

---

## Registration Flow

Complete sequence performed once by `full_register.py` to produce a working `.env`:

```
1. hub_id_from_cert(hub_ip)
   └── TLS connect to hub:8989
   └── Read CN from server certificate → hubId

2. Cloud: POST https://version2.smartdoordevices.com/app/remoteregister
   └── Returns phoneId, phonePassword, phoneSecret, userId

3. LAN: POST /app/connect  (port 8989, communicationType=3)
   └── Returns sessionId, sessionSecret
   └── Checks isPasswordExpired and nextAccess wait time

4. LAN: POST /app/v3migrate  (port 8989)
   ├── Client generates RSA-2048 key pair
   ├── Client generates EC-P256 key pair
   ├── Sends encrypted payload containing both public keys + new SDK phone password
   ├── Hub returns migrationData (ECDH hub half, encrypted)
   └── Client derives ECDH shared secret (used as phoneSecret for SDK protocol only)

5. SDK: POST /sdk/message  path=auth  (port 8991)
   └── Returns session key for subsequent SDK MAC signing

6. SDK: POST /sdk/message  path=setUserPassword  (port 8991)
   ├── Clears isPasswordExpired if set
   └── Response contains devicePermissions → extract actionDeviceId (regex fallback
       used because first 16 decrypted bytes are garbled)

7. Write credentials.json and .env
   └── All fields populated; actionDeviceId from step 5 or 6
```

---

## Cryptography

### App protocol (port 8989) — AES-128-CBC

**Payload encryption:**
```
key       = MD5(phoneSecret)           # 16 bytes
iv        = MD5(str(timestamp_ms))     # 16 bytes
encrypted = AES-128-CBC(key, iv, PKCS7-pad(plaintext))
data      = base64(encrypted)
```

**Request signing:**
```
signing    = "{timestamp_ms}:{base64_encrypted_data}"
sessionSig = base64(HMAC-SHA256(sessionSecret, signing))
phoneSig   = base64(HMAC-SHA256(phoneSecret,   signing))
```

Both `sessionSig` and `phoneSig` are sent on every request. The hub validates both.

Using MD5 for key/IV derivation is cryptographically weak by modern standards. This
is the hub's own protocol design — it cannot be changed without replacing the hub.

### SDK protocol (port 8991) — AES-256-CBC + RSA-2048

**Request payload encryption:**
```
key       = SHA256(phoneSecret)        # 32 bytes
iv        = SHA256(str(timestamp))[:16]  # first 16 bytes
encrypted = AES-256-CBC(key, iv, PKCS7-pad(plaintext))
request   = base64(encrypted)
```

**Request MAC:**
```
signing = "{hubId}:{phoneId}:{timestamp}:{requestId}:{base64_encrypted}"
mac     = base64(HMAC-SHA256(mac_key, signing))
```

**Request RSA signature** (after v3migrate provides the private key):
```
signature = base64(RSA-PKCS1v15-SHA512(rsa_private_key, signing))
```

**Hub response decryption — zero IV:**

The hub encrypts SDK responses with AES-256-CBC using a zero IV (`b'\x00' * 16`).
Because the true IV is unknown, the first 16-byte block decrypts incorrectly (it is
XORed with the wrong IV). All subsequent blocks are correct, since CBC chaining uses
the previous ciphertext block as the IV. The first 16 bytes are discarded:

```python
key    = hashlib.sha256(phone_secret.encode()).digest()
ct     = base64.b64decode(ciphertext_b64)
dec    = AES-256-CBC(key, iv=b'\x00'*16, ct)
result = dec[16:]   # skip garbled first block
```

### v3migrate — ECDH key exchange

During `v3migrate`, the client and hub perform Elliptic Curve Diffie-Hellman key
exchange over P-256 to derive a new `phoneSecret`:

1. Client generates an RSA-2048 key pair and an EC-P256 key pair
2. Client sends both public keys (encrypted with the original AES-128 app-protocol
   scheme) in the `v3migrate` request body
3. Hub responds with its EC-P256 public key half in `migrationData` (AES-128 encrypted)
4. Client computes: `shared_secret = ECDH(client_ec_private, hub_ec_public)`
5. `new_phoneSecret = base64(shared_secret)`

**Important:** The ECDH-derived `phoneSecret` is only used for the SDK protocol
(port 8991). The original `phoneSecret` from cloud registration continues to be used
for all app-protocol (port 8989) requests. This was confirmed empirically — using the
ECDH secret for app-protocol encryption causes decryption failures at the hub.

---

## Credentials Reference

| Field | How obtained | Used for |
|-------|-------------|----------|
| `hubId` | Hub TLS certificate CN (auto-extracted) | Identifying the hub in all requests |
| `phoneId` | Cloud registration response | `app/connect` authentication |
| `phonePassword` | Cloud registration response | `app/connect` authentication |
| `phoneSecret` | Cloud registration response (original value) | AES-128 encryption + HMAC signing (app protocol) |
| `userPassword` | Set when creating user in B&D app | `app/connect` authentication |
| `phoneKey` | Generated locally (RSA-2048, PKCS8 DER, base64) | SDK message RSA signatures |
| `sdkPhonePassword` | Fixed constant set during v3migrate | `sdk/auth` password field |
| `actionDeviceId` | Keys of `devicePermissions` in `sdk/auth` response | All device control and status requests |
| `hubKey` | Returned by `v3migrate` (hub's RSA public key) | SDK operations |

---

## Session Lifecycle

```
startup → app/connect → cache {sessionId, sessionSecret, timestamp}
                                        │
                            request arrives
                                        │
                         session age < 120s? ──yes──▶ use cached session
                                        │
                                       no
                                        │
                              app/connect again → refresh cache
                                        │
                           hub returns 403? ──yes──▶ clear session, retry once
```

---

## Rate Limiting

The hub enforces a minimum interval between successive commands. After `app/connect`,
the response includes `data.userAccess.nextAccess` — a Unix timestamp in milliseconds.
If `nextAccess > now_ms`, the client must sleep until that time before sending a command.
Sending early results in a hub error response (`processState = -1`).

This is most noticeable immediately after connecting: `isAccessReady` is `false` and
`nextAccess` is typically a few hundred milliseconds in the future.

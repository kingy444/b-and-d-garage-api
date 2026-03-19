# B&D Garage Door API

A self-hosted HTTP API that controls a B&D SmartDoorDevices garage hub over LAN.
Designed for integration with Siri Shortcuts and Home Assistant.

## Endpoints

| Method | Path      | Auth | Description                        |
|--------|-----------|------|------------------------------------|
| `POST` | `/open`   | Yes  | Opens the garage door              |
| `POST` | `/close`  | Yes  | Closes the garage door             |
| `POST` | `/stop`   | Yes  | Stops the door mid-travel          |
| `GET`  | `/status` | Yes  | Returns current door state         |
| `GET`  | `/health` | No   | Health check / session age         |

### Status response

```json
{
  "state": "closed",
  "position": 0,
  "rate": 0
}
```

`state` is one of `"open"`, `"closed"`, `"moving"`, or `"partial_N"` (where N is the position 0–100).

## Setup

### 1. Register a phone and generate config (first time only)

```bash
python full_register.py <hub-ip> <activation_code> <user_password>
```

- **`hub-ip`** — your hub's LAN IP address (check your router's DHCP table)
- **`activation_code`** — from the B&D Smart Garage Access app under **Settings → Users → \<Your Hub\> → Add new user**. Name the new user, set privileges (Standard is fine), give control of your device. This provides the activation code and password.
- **`user_password`** — the password set for that new user

The script will:
1. Read the hub's TLS certificate to find the `hubId` automatically
2. Register a virtual phone with the hub
3. Discover your garage door device ID
4. Write `credentials.json` with all hub credentials
5. Write `.env` with all environment variables ready for Docker, including a freshly generated API key

Note your API key from the output — you'll need it for Home Assistant and Siri Shortcuts.

`credentials.json` and `.env` are gitignored and never committed. Keep them safe.

### 2. Run with Docker

```bash
docker-compose up -d
```

The API listens on port `8080` inside the container. The default `docker-compose.yml` maps it to port `20000` externally — adjust to suit your setup.

### 3. Authenticate requests

All action endpoints require an `X-API-Key` header:

```bash
curl -X POST -H "X-API-Key: your-key" http://localhost:20000/open
```

### 4. Siri Shortcuts

In the Shortcuts app, add a **Get Contents of URL** action:

- **URL:** `https://your-domain/open` (or `/close`, `/stop`, `/status`)
- **Method:** `POST`
- **Headers:** `X-API-Key` = your API key

For voice control: **"Hey Siri, Open Garage"** (name the shortcut to match).

### 5. Home Assistant

See [`homeassistant.yaml`](homeassistant.yaml) for a full configuration example with:
- REST commands (`rest_command.garage_open` / `garage_close`)
- REST sensor polling `/status` every 30 s
- Automations for arrival/departure detection (zone + WiFi triggers)
- Nobody-home safety net

## Protocol notes

Communicates with the hub at port `8989` using the SmartDoorDevices LAN app protocol:

- **Auth:** `app/connect` → `sessionId` + `sessionSecret` (cached for 2 minutes)
- **Encryption:** AES-128-CBC, key=MD5(phoneSecret), IV=MD5(timestamp_ms)
- **Signing:** HMAC-SHA256 with both `phoneSecret` (phoneSig) and `sessionSecret` (sessionSig)
- **Commands:** `app/res/action` with `{"deviceId": "<id>", "action": {"cmd": N}}`
  - `OPEN=2`, `CLOSE=4`, `STOP=3`
- **Status:** `app/res/devices/fetch` — returns `position` (0=closed, 100=open) and `rate`

The hub uses a self-signed TLS certificate on port 8989. SSL verification is disabled for this connection; certificate pinning via `hub.crt` can be substituted if preferred.

## Security

- All action endpoints require an `X-API-Key` header. The `/health` endpoint is unauthenticated (returns only `status` and `session_age_s`).
- Run behind a reverse proxy with HTTPS (e.g. Nginx Proxy Manager + Cloudflare) when exposing externally.
- `credentials.json`, `.env`, and `hub.crt` are gitignored and must never be committed.

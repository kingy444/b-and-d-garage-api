#!/usr/bin/env python3
"""
Discover B&D hub credentials from the LAN before registering a phone.

Usage:
    python discover.py <hub-ip>

What it does:
    1. Connects to the hub's TLS port (8989) and extracts the hubId from
       the server certificate's Common Name field.
    2. Writes (or updates) credentials.json with the discovered hubId.

Run this once before full_register.py. You only need the hub's LAN IP address.
"""

import json
import ssl
import sys
from pathlib import Path

from cryptography import x509

CREDS_FILE = Path("credentials.json")


def get_hub_id_from_cert(hub_ip: str, port: int = 8989) -> str:
    """Connect to hub TLS, extract hubId from certificate CN."""
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

    print(f"Connecting to {hub_ip}:{port}...")
    with ssl.create_connection((hub_ip, port), timeout=10) as raw:
        with ctx.wrap_socket(raw) as ssock:
            cert_der = ssock.getpeercert(binary_form=True)

    cert = x509.load_der_x509_certificate(cert_der)
    cn_attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if not cn_attrs:
        raise RuntimeError("No CN found in hub certificate")
    return cn_attrs[0].value


def main():
    if len(sys.argv) < 2:
        print("Usage: python discover.py <hub-ip>")
        print("  Example: python discover.py 192.168.1.103")
        sys.exit(1)

    hub_ip = sys.argv[1]

    try:
        hub_id = get_hub_id_from_cert(hub_ip)
    except Exception as e:
        print(f"ERROR: Could not connect to hub at {hub_ip}:8989 — {e}")
        print("  Check the hub is powered on and connected to your LAN.")
        sys.exit(1)

    print(f"  hubId: {hub_id}")

    existing = json.loads(CREDS_FILE.read_text()) if CREDS_FILE.exists() else {}
    existing["hubId"] = hub_id
    CREDS_FILE.write_text(json.dumps(existing, indent=2))
    print(f"\nSaved to {CREDS_FILE}")
    print("\nNext steps:")
    print("  1. Open the B&D Smart Garage Access app.")
    print("  2. Go to Settings → Add Phone and note the activation code and your user password.")
    print(f"  3. Run:  python full_register.py <activation_code> <user_password>")


if __name__ == "__main__":
    main()

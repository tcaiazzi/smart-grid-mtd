#!/usr/bin/env python3
"""
cert_client.py  —  SCMC / client side
--------------------------------------
1. Sends its CN (encrypted) to the CA.
2. Receives the encrypted bundle (client.key + client.crt + ca.crt).
3. Saves everything to --out-dir.

Usage:
    python3 cert_client.py --shared-key <hex64> --ca-host 10.1.0.2
                           [--ca-port 9999] [--cn scmc1] [--out-dir certs/]
"""

import argparse
import os
import socket
import struct
import sys

from cryptography import x509

# Crypto (AES-256-GCM under the QKD shared key) and wire framing are shared
# with cert_authority.py, mtd_coordinator.py and mtd_executor.py — see
# mtd_crypto.py / mtd_wire.py, copied alongside this file on every machine.
from mtd_crypto import encrypt_payload, decrypt_payload
from mtd_wire import send_bytes as send_msg, recv_bytes as recv_msg


# ---------------------------------------------------------------------------
# Bundle parsing
# ---------------------------------------------------------------------------

def unpack_bundle(bundle: bytes):
    """
    Bundle format (set by cert_authority.py):
        4-byte key_len  | key_pem
        4-byte cert_len | cert_pem
        ca_cert_pem (remainder)
    Returns (key_pem, cert_pem, ca_cert_pem).
    """
    key_len  = struct.unpack(">I", bundle[0:4])[0]
    key_pem  = bundle[4 : 4 + key_len]

    offset   = 4 + key_len
    cert_len = struct.unpack(">I", bundle[offset : offset + 4])[0]
    cert_pem = bundle[offset + 4 : offset + 4 + cert_len]

    ca_cert_pem = bundle[offset + 4 + cert_len:]
    return key_pem, cert_pem, ca_cert_pem


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--shared-key", required=True,
                        help="64-char hex string (32-byte AES-256 key from QKD)")
    parser.add_argument("--ca-host", required=True)
    parser.add_argument("--ca-port", type=int, default=9999)
    parser.add_argument("--cn",      default="scmc1")
    parser.add_argument("--out-dir", default="certs")
    args = parser.parse_args()

    if len(args.shared_key) != 64:
        print("[!] --shared-key must be exactly 64 hex chars (32 bytes)")
        sys.exit(1)
    shared_key = bytes.fromhex(args.shared_key)

    os.makedirs(args.out_dir, exist_ok=True)

    # Connect and send CN
    print(f"[{args.cn}] Connecting to CA at {args.ca_host}:{args.ca_port}...")
    with socket.create_connection((args.ca_host, args.ca_port), timeout=15) as sock:
        send_msg(sock, encrypt_payload(args.cn.encode(), shared_key))
        print(f"[{args.cn}] CN sent, waiting for certificates...")
        enc_bundle = recv_msg(sock)

    # Decrypt and unpack
    bundle = decrypt_payload(enc_bundle, shared_key)
    key_pem, cert_pem, ca_cert_pem = unpack_bundle(bundle)

    # Save
    def save(filename, data, mode=0o644):
        path = os.path.join(args.out_dir, filename)
        with open(path, "wb") as f:
            f.write(data)
        os.chmod(path, mode)
        return path

    print(f"[{args.cn}] Certificates saved:")
    print(f"  client.key → {save('client.key', key_pem, 0o600)}")
    print(f"  client.crt → {save('client.crt', cert_pem)}")
    print(f"  ca.crt     → {save('ca.crt',     ca_cert_pem)}")

    cert = x509.load_pem_x509_certificate(cert_pem)
    print(f"[{args.cn}] Valid until: {cert.not_valid_after_utc}")


if __name__ == "__main__":
    main()
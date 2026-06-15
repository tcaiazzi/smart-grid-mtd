#!/usr/bin/env python3
"""
cert_authority.py  —  CA side (runs on SEMP)
---------------------------------------------
At startup:
  - Generates CA key + self-signed CA certificate.
  - Generates server key + server certificate signed by the CA.
  - Saves all files to --out-dir (default: /etc/mosquitto/certs/).

For each connecting client:
  - Generates a client key + client certificate signed by the CA.
  - Encrypts the bundle (client.key + client.crt + ca.crt) with the
    shared QKD key and sends it back.

Usage:
    python3 cert_authority.py --shared-key <hex64>
                              [--host 0.0.0.0] [--port 9999]
                              [--out-dir /etc/mosquitto/certs/]
                              [--server-cn semp] [--server-ip 10.1.0.2,10.1.0.4,...]
"""

import argparse
import datetime
import os
import socket
import struct
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID
import ipaddress


# ---------------------------------------------------------------------------
# Key + certificate generation helpers
# ---------------------------------------------------------------------------

def generate_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def key_to_pem(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )


def generate_ca(out_dir: str):
    """Generate CA key and self-signed certificate. Save to out_dir."""
    ca_key = generate_key()

    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "SmartGrid-CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SmartGrid Lab"),
    ])

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    _save(out_dir, "ca.key", key_to_pem(ca_key), mode=0o600)
    _save(out_dir, "ca.crt", ca_cert.public_bytes(serialization.Encoding.PEM))

    print(f"[CA] CA key  → {out_dir}/ca.key")
    print(f"[CA] CA cert → {out_dir}/ca.crt")
    return ca_key, ca_cert


def generate_server_cert(ca_key, ca_cert, cn: str, ip: str, out_dir: str):
    """Generate server key + certificate signed by the CA. Save to out_dir.

    `ip` may be a comma-separated list of addresses (the MTD IP-hop pool); each
    valid address is added as its own SAN IP entry so the single broker cert is
    valid on every address it can appear on after a hop.
    """
    srv_key = generate_key()

    san_entries = [x509.DNSName(cn)]
    for entry in (ip or "").split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            san_entries.append(x509.IPAddress(ipaddress.ip_address(entry)))
        except ValueError:
            print(f"[CA] Warning: invalid server IP '{entry}', skipping SAN IP entry")

    srv_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SmartGrid Lab"),
        ]))
        .issuer_name(ca_cert.subject)
        .public_key(srv_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    _save(out_dir, "server.key", key_to_pem(srv_key), mode=0o640)
    _save(out_dir, "server.crt", srv_cert.public_bytes(serialization.Encoding.PEM))

    print(f"[CA] Server key  → {out_dir}/server.key")
    print(f"[CA] Server cert → {out_dir}/server.crt")


def generate_client_cert(ca_key, ca_cert, cn: str, client_ips):
    """Generate a client key + certificate. Returns (key_pem, cert_pem).

    `client_ips` is a list of source addresses to add as SAN IP entries (the SCMC
    source-IP hop pool), so the single client cert stays valid whichever source
    address the client binds to after a source-IP hop.
    """
    cli_key = generate_key()

    san_entries = [x509.DNSName(cn)]
    for entry in client_ips or []:
        entry = (entry or "").strip()
        if not entry:
            continue
        try:
            san_entries.append(x509.IPAddress(ipaddress.ip_address(entry)))
        except ValueError:
            print(f"[CA] Warning: invalid client IP '{entry}', skipping SAN IP entry")

    cli_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SmartGrid Lab"),
        ]))
        .issuer_name(ca_cert.subject)
        .public_key(cli_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    return key_to_pem(cli_key), cli_cert.public_bytes(serialization.Encoding.PEM)


def _save(directory: str, filename: str, data: bytes, mode: int = 0o644):
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, filename)
    with open(path, "wb") as f:
        f.write(data)
    os.chmod(path, mode)


# ---------------------------------------------------------------------------
# Encrypted transport
# ---------------------------------------------------------------------------

def encrypt_payload(data: bytes, key: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, data, None)


def decrypt_payload(data: bytes, key: bytes) -> bytes:
    return AESGCM(key).decrypt(data[:12], data[12:], None)


def recv_msg(sock: socket.socket) -> bytes:
    length = struct.unpack(">I", _recv_exact(sock, 4))[0]
    return _recv_exact(sock, length)


def send_msg(sock: socket.socket, data: bytes):
    sock.sendall(struct.pack(">I", len(data)) + data)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed")
        buf += chunk
    return buf


# ---------------------------------------------------------------------------
# Client handler
# ---------------------------------------------------------------------------

def handle_client(conn: socket.socket, addr,
                  ca_key, ca_cert, ca_cert_pem: bytes,
                  shared_key: bytes, client_ips=None):
    client_ip = addr[0]
    print(f"[CA] Connection from {client_ip}:{addr[1]}")
    try:
        # Receive encrypted CN from client
        enc_cn = recv_msg(conn)
        cn = decrypt_payload(enc_cn, shared_key).decode()
        print(f"[CA] Generating certificate for CN='{cn}'...")

        # Put the whole SCMC source-IP pool in the cert SAN (so it survives source
        # hops); fall back to just the connecting address when no pool is given.
        key_pem, cert_pem = generate_client_cert(
            ca_key, ca_cert, cn, client_ips or [client_ip]
        )

        # Bundle: 4-byte key_len | key_pem | 4-byte cert_len | cert_pem | ca_cert_pem
        bundle = (
            struct.pack(">I", len(key_pem))  + key_pem  +
            struct.pack(">I", len(cert_pem)) + cert_pem +
            ca_cert_pem
        )

        send_msg(conn, encrypt_payload(bundle, shared_key))
        print(f"[CA] Bundle sent to {client_ip} (CN='{cn}')")

    except Exception as e:
        print(f"[CA] Error handling {client_ip}: {e}")
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--shared-key", required=True,
                        help="64-char hex string (32-byte AES-256 key from QKD)")
    parser.add_argument("--host",      default="0.0.0.0")
    parser.add_argument("--port",      type=int, default=9999)
    parser.add_argument("--out-dir",   default="/etc/mosquitto/certs",
                        help="Where to save ca.crt, server.crt, server.key")
    parser.add_argument("--server-cn", default="semp",
                        help="CN for the broker certificate (default: semp)")
    parser.add_argument("--server-ip", default="",
                        help="IP(s) to include in the broker certificate SAN; "
                             "comma-separated to cover an MTD IP-hop pool")
    parser.add_argument("--client-ip", default="",
                        help="IP(s) to include in every client certificate SAN; "
                             "comma-separated to cover the SCMC source-IP hop pool")
    args = parser.parse_args()
    client_ips = [x.strip() for x in args.client_ip.split(",") if x.strip()]

    if len(args.shared_key) != 64:
        print("[!] --shared-key must be exactly 64 hex chars (32 bytes)")
        sys.exit(1)
    shared_key = bytes.fromhex(args.shared_key)

    # --- Bootstrap: generate CA + server cert ---
    ca_key, ca_cert = generate_ca(args.out_dir)
    generate_server_cert(ca_key, ca_cert, args.server_cn, args.server_ip, args.out_dir)
    ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM)

    # --- Listen for client requests ---
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(10)
    print(f"[CA] Listening for client requests on {args.host}:{args.port}")

    try:
        while True:
            conn, addr = srv.accept()
            handle_client(conn, addr, ca_key, ca_cert, ca_cert_pem, shared_key, client_ips)
    except KeyboardInterrupt:
        print("\n[CA] Shutting down.")
    finally:
        srv.close()


if __name__ == "__main__":
    main()
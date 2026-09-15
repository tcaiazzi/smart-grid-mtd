#!/usr/bin/env python3
"""mtd_wire.py — length-prefixed socket framing shared by every MTD/QKD guest
agent. Copied flat alongside mtd_crypto.py (see network_scenario.guest_files).

Two independent message shapes ride this network, both framed as a 4-byte
big-endian length prefix followed by that many bytes:

  - JSON control messages between mtd_coordinator.py and mtd_executor.py,
    optionally AES-GCM encrypted under the QKD-derived key (send_msg/recv_msg).
  - Raw byte blobs between cert_authority.py and cert_client.py, which apply
    mtd_crypto.encrypt_payload/decrypt_payload themselves around the framed
    bytes rather than through this module (send_bytes/recv_bytes).

The two message shapes also differ in what a peer hang-up should say: the
control channel logs "socket closed" (mtd_executor.py catches and retries on
it), while the QKD bootstrap logs "Connection closed" — recv_exact's
closed_msg lets each flavor keep its original wording.
"""

import json
import struct

from mtd_crypto import decrypt_payload, encrypt_payload


def recv_exact(sock, n: int, closed_msg: str = "socket closed") -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(closed_msg)
        buf += chunk
    return buf


def send_msg(sock, obj: dict, key: bytes = None) -> None:
    """Coordinator <-> executor control messages: JSON, optionally AES-GCM
    encrypted under the QKD-derived key."""
    payload = json.dumps(obj).encode()
    if key is not None:
        payload = encrypt_payload(payload, key)
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def recv_msg(sock, key: bytes = None) -> dict:
    length = struct.unpack(">I", recv_exact(sock, 4))[0]
    payload = recv_exact(sock, length)
    if key is not None:
        payload = decrypt_payload(payload, key)
    return json.loads(payload)


def send_bytes(sock, data: bytes) -> None:
    """QKD cert-bootstrap channel: raw length-prefixed bytes; the caller
    applies mtd_crypto.encrypt_payload/decrypt_payload itself around this."""
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_bytes(sock) -> bytes:
    length = struct.unpack(">I", recv_exact(sock, 4, closed_msg="Connection closed"))[0]
    return recv_exact(sock, length, closed_msg="Connection closed")

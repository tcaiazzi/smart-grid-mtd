#!/usr/bin/env python3
"""mtd_crypto.py — AES-256-GCM helpers shared by every MTD/QKD guest agent.

Copied flat onto every machine that needs it (see network_scenario.guest_files):
mtd_coordinator.py and mtd_executor.py use it to encrypt the MTD control
channel; cert_authority.py and cert_client.py use it to encrypt the QKD-derived
cert bootstrap. All four share the same construction and the same key, since
the QKD-simulated secret protects both channels (see mtd_coordinator.py's
module docstring).
"""

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_payload(data: bytes, key: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, data, None)


def decrypt_payload(data: bytes, key: bytes) -> bytes:
    return AESGCM(key).decrypt(data[:12], data[12:], None)

"""
crypto_utils.py — HKDF + AES-256-GCM encryption for eFRAC
==========================================================
All nodes (H1, MB1, MB2, H2) use this module to derive the same AES-256 key
from a pre-shared key file (efrac.psk) via HKDF-SHA256, then encrypt/decrypt
payloads using AES-256-GCM.

Wire format:  [12B nonce][ciphertext][16B GCM tag]
Overhead:     28 bytes per packet
"""

import os
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Constants — must match crypto_utils.h
EFRAC_NONCE_LEN = 12
EFRAC_TAG_LEN = 16
EFRAC_OVERHEAD = EFRAC_NONCE_LEN + EFRAC_TAG_LEN  # 28 bytes
EFRAC_SALT = b"efrac-salt-v1"
EFRAC_INFO = b"efrac-aes256-gcm-key"
EFRAC_KEY_LEN = 32  # AES-256


def derive_key(ikm: bytes) -> bytes:
    """Derive a 32-byte AES-256 key from input key material using HKDF-SHA256."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=EFRAC_KEY_LEN,
        salt=EFRAC_SALT,
        info=EFRAC_INFO,
    )
    return hkdf.derive(ikm)


def load_key(psk_path: str = "efrac.psk") -> bytes:
    """Read the hex-encoded PSK from file and derive the AES-256 key."""
    with open(psk_path, "r") as f:
        hex_str = f.read().strip()
    ikm = bytes.fromhex(hex_str)
    return derive_key(ikm)


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt plaintext with AES-256-GCM.
    Returns: nonce (12B) + ciphertext + tag (16B)
    """
    nonce = os.urandom(EFRAC_NONCE_LEN)
    aesgcm = AESGCM(key)
    # AESGCM.encrypt returns ciphertext + tag concatenated
    ct_and_tag = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct_and_tag


def decrypt(key: bytes, blob: bytes) -> bytes:
    """
    Decrypt an AES-256-GCM blob: nonce (12B) + ciphertext + tag (16B).
    Returns the original plaintext.
    Raises cryptography.exceptions.InvalidTag on auth failure.
    """
    if len(blob) < EFRAC_OVERHEAD:
        raise ValueError(f"Blob too short for AES-GCM: {len(blob)} < {EFRAC_OVERHEAD}")
    nonce = blob[:EFRAC_NONCE_LEN]
    ct_and_tag = blob[EFRAC_NONCE_LEN:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct_and_tag, None)


if __name__ == "__main__":
    # Quick self-test
    key = load_key("efrac.psk")
    msg = b"Hello eFRAC encryption test payload " * 20
    ct = encrypt(key, msg)
    pt = decrypt(key, ct)
    assert pt == msg, f"Mismatch: {len(pt)} vs {len(msg)}"
    print(f"OK: {len(msg)}B plaintext -> {len(ct)}B ciphertext -> {len(pt)}B decrypted")
    print(f"Overhead: {len(ct) - len(msg)} bytes ({EFRAC_NONCE_LEN}B nonce + {EFRAC_TAG_LEN}B tag)")

"""
Utility untuk XOR, Base64, dan PKCS7 padding.
"""

import base64
import os

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR dua bytes, minimal sepanjang yang terpendek."""
    return bytes(x ^ y for x, y in zip(a, b))

def pad_pkcs7(data: bytes, block_size: int = 16) -> bytes:
    """Padding PKCS7."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def unpad_pkcs7(data: bytes) -> bytes:
    """Menghapus padding PKCS7. Asumsikan data valid."""
    pad_len = data[-1]
    if pad_len > len(data) or pad_len == 0:
        raise ValueError("Padding tidak valid")
    for i in range(1, pad_len + 1):
        if data[-i] != pad_len:
            raise ValueError("Padding tidak konsisten")
    return data[:-pad_len]

def encode_base64(data: bytes) -> str:
    """Encode bytes ke string base64."""
    return base64.b64encode(data).decode()

def decode_base64(encoded: str) -> bytes:
    """Decode string base64 ke bytes."""
    return base64.b64decode(encoded)

def generate_key_salt(length: int = 16) -> bytes:
    """Generate random salt."""
    return os.urandom(length)
"""
Key-Wrapping untuk fitur Re-encryption saat sharing.

Konsep (proxy re-encryption gaya edukasi):
- Setiap objek memiliki DEK (Data Encryption Key) acak 256-bit.
- Payload objek dienkripsi dengan DEK (AES-256-CTR), BUKAN dengan kunci user.
- Saat owner membagikan objek ke penerima:
  1. Owner mendekripsi DEK dengan kunci utamanya (atau menyimpannya di sesi).
  2. DEK di-wrap (dienkripsi ulang) memakai KEK (Key Encryption Key)
     penerima yang diturunkan dari passphrase bersama via PBKDF2-HMAC-SHA256.
- Server hanya menyimpan ciphertext objek + wrapped key; tidak pernah
  melihat plaintext maupun DEK.
- Penerima membuka bungkus wrapped key dengan passphrase yang sama,
  lalu mendekripsi payload dengan DEK yang berhasil dipulihkan.

Murni edukasional: pakai AES-256-CTR custom, bukan standar NIST key-wrap.
"""

import os

from cloudsim.crypto.aes_custom import AES256CTR
from cloudsim.crypto.key_derivation import pbkdf2_sha256
from cloudsim.crypto.utils import encode_base64, decode_base64

# Parameter derivasi kunci pembungkus (KEK)
WRAP_ITERATIONS = 100_000
WRAP_SALT_LEN = 16      # bytes
DEK_LEN = 32            # bytes (AES-256)


def generate_dek() -> bytes:
    """Bangkitkan Data Encryption Key (DEK) acak sepanjang 256 bit."""
    return os.urandom(DEK_LEN)


def derive_wrap_key(passphrase: str, salt: bytes,
                    iterations: int = WRAP_ITERATIONS) -> bytes:
    """Turunkan Key Encryption Key (KEK) dari passphrase + salt via PBKDF2-HMAC-SHA256."""
    return pbkdf2_sha256(passphrase, salt, iterations=iterations, dklen=DEK_LEN)


def wrap_key(dek: bytes, passphrase: str) -> dict:
    """Bungkus (enkripsi) DEK dengan KEK yang diturunkan dari passphrase.

    Mengembalikan dict berisi parameter yang dibutuhkan server/klien penerima:
      {"wrapped_key": b64, "wrap_nonce": b64, "wrap_salt": hex, "iterations": int}
    """
    if len(dek) != DEK_LEN:
        raise ValueError(f"DEK harus {DEK_LEN} bytes")
    if not passphrase:
        raise ValueError("Passphrase wrapping tidak boleh kosong")
    salt = os.urandom(WRAP_SALT_LEN)
    kek = derive_wrap_key(passphrase, salt)
    cipher = AES256CTR(kek)
    wrapped, nonce = cipher.encrypt(dek)
    return {
        "wrapped_key": encode_base64(wrapped),
        "wrap_nonce": encode_base64(nonce),
        "wrap_salt": salt.hex(),
        "iterations": WRAP_ITERATIONS,
    }


def unwrap_key(wrapped_key_b64: str, wrap_nonce_b64: str, wrap_salt_hex: str,
               passphrase: str, iterations: int = WRAP_ITERATIONS) -> bytes:
    """Buka bungkus DEK menggunakan passphrase yang sama dengan peng-wrap.

    Menghasilkan DEK bila passphrase benar; menghasilkan bytes sampah bila
    salah (verifikasi keabsahan dilakukan pemanggil dengan mencoba dekripsi
    payload dan mencocokkan hasilnya).
    """
    salt = bytes.fromhex(wrap_salt_hex)
    kek = derive_wrap_key(passphrase, salt, iterations=iterations)
    cipher = AES256CTR(kek)
    return cipher.decrypt(decode_base64(wrapped_key_b64), decode_base64(wrap_nonce_b64))

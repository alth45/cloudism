"""
PBKDF2 manual menggunakan HMAC-SHA256.
Digunakan untuk menurunkan kunci dari password + salt.
"""

import hashlib
import hmac

def pbkdf2_sha256(password: str, salt: bytes, iterations: int = 100000, dklen: int = 32) -> bytes:
    """
    PBKDF2 (Password-Based Key Derivation Function 2) dengan HMAC-SHA256.
    password: string password
    salt: bytes salt
    iterations: jumlah iterasi (default 100k)
    dklen: panjang kunci yang diinginkan (dalam bytes, default 32 = 256 bit)
    """
    if dklen <= 0:
        raise ValueError("dklen harus positif")
    hlen = 32  # output SHA256
    # Hitung jumlah blok
    l = (dklen + hlen - 1) // hlen
    result = b""
    password_bytes = password.encode('utf-8')
    for i in range(1, l + 1):
        # U = HMAC-SHA256(password, salt + i_big_endian)
        i_enc = i.to_bytes(4, 'big')
        u_prev = hmac.new(password_bytes, salt + i_enc, hashlib.sha256).digest()
        u_sum = bytes(u_prev)
        for _ in range(iterations - 1):
            u_prev = hmac.new(password_bytes, u_prev, hashlib.sha256).digest()
            # XOR between bytes
            u_sum = bytes(a ^ b for a, b in zip(u_sum, u_prev))
        result += u_sum
    return result[:dklen]

# Contoh penggunaan
if __name__ == "__main__":
    key = pbkdf2_sha256("password", b"salt", iterations=1000, dklen=32)
    print("Derived key hex:", key.hex())
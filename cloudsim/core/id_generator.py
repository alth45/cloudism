import os
import time

def _random_hex(length: int) -> str:
    """Menghasilkan string heksadesimal acak sepanjang `length`."""
    return os.urandom(length // 2 + 1).hex()[:length]

def generate_user_id() -> str:
    """ID pengguna: usr-{8 hex}"""
    return f"usr-{_random_hex(8)}"

def generate_object_id() -> str:
    """ID objek: obj-{12 hex}"""
    return f"obj-{_random_hex(12)}"

def generate_bucket_id() -> str:
    """ID bucket: bkt-{8 hex}"""
    return f"bkt-{_random_hex(8)}"

def generate_version_id() -> str:
    """ID versi objek: ver-{12 hex} (flag identitas satu versi objek)"""
    return f"ver-{_random_hex(12)}"


def generate_token_id() -> str:
    """ID token: tok-{24 hex} (untuk header JWT)"""
    return f"tok-{_random_hex(24)}"

# Contoh penggunaan jika dijalankan langsung
if __name__ == "__main__":
    print("User ID:", generate_user_id())
    print("Object ID:", generate_object_id())
    print("Token ID:", generate_token_id())
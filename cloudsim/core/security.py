import hashlib
import hmac
import base64
import time
import json
import os
from cloudsim.core.id_generator import generate_token_id

class AuthManager:
    """Menangani registrasi, login, token (JWT manual), dan hashing password."""
    
    def __init__(self, secret_key: str = None):
        # Prioritas: argumen eksplisit > env CLOUDSIM_JWT_SECRET > acak.
        # Env var menjamin konsistensi token create/verify saat proses
        # yang sama memuat modul melalui jalur berbeda (mis. plugin pytest).
        self.secret_key = (
            secret_key
            or os.environ.get("CLOUDSIM_JWT_SECRET")
            or base64.b64encode(os.urandom(32)).decode()
        )
    
    # ---------- Password ----------
    def hash_password(self, password: str, salt: bytes = None) -> tuple[str, str]:
        """Hash password dengan SHA-256 + salt. Kembalikan (hash_hex, salt_hex)."""
        if salt is None:
            salt = os.urandom(16)
        elif isinstance(salt, str):
            salt = bytes.fromhex(salt)
        salted = password.encode() + salt
        hash_bytes = hashlib.sha256(salted).digest()
        return hash_bytes.hex(), salt.hex()
    
    def verify_password(self, password: str, stored_hash: str, stored_salt: str) -> bool:
        """Verifikasi password terhadap hash dan salt tersimpan."""
        salt = bytes.fromhex(stored_salt)
        new_hash, _ = self.hash_password(password, salt)
        return hmac.compare_digest(new_hash, stored_hash)
    
    # ---------- Token (Custom JWT) ----------
    def create_token(self, user_id: str, expiry_seconds: int = 3600) -> str:
        """Buat token akses dengan format header.payload.signature."""
        header = {"alg": "HS256", "typ": "JWT", "kid": generate_token_id()}
        payload = {
            "user_id": user_id,
            "iat": int(time.time()),
            "exp": int(time.time()) + expiry_seconds
        }
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        message = f"{header_b64}.{payload_b64}"
        signature = hmac.new(self.secret_key.encode(), message.encode(), hashlib.sha256).digest()
        signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")
        return f"{header_b64}.{payload_b64}.{signature_b64}"
    
    def verify_token(self, token: str) -> dict | None:
        """Verifikasi token, kembalikan payload jika valid, atau None."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None
            header_b64, payload_b64, signature_b64 = parts
            # Tambahkan padding jika perlu
            header_b64 += "=" * (4 - len(header_b64) % 4) if len(header_b64) % 4 else ""
            payload_b64 += "=" * (4 - len(payload_b64) % 4) if len(payload_b64) % 4 else ""
            signature_b64 += "=" * (4 - len(signature_b64) % 4) if len(signature_b64) % 4 else ""
            
            header = json.loads(base64.urlsafe_b64decode(header_b64))
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            expected_sig = hmac.new(self.secret_key.encode(), 
                                    f"{header_b64.rstrip('=')}.{payload_b64.rstrip('=')}".encode(), 
                                    hashlib.sha256).digest()
            actual_sig = base64.urlsafe_b64decode(signature_b64)
            if not hmac.compare_digest(expected_sig, actual_sig):
                return None
            # Cek kedaluwarsa
            if payload.get("exp", 0) < time.time():
                return None
            return payload
        except (json.JSONDecodeError, KeyError, ValueError):
            return None

# Singleton sederhana untuk digunakan di seluruh aplikasi
auth_manager = AuthManager()
# pyrefly: ignore [missing-import]
from fastapi import APIRouter, HTTPException, status, Request
from pydantic import BaseModel
from cloudsim.core.security import auth_manager
from cloudsim.core.id_generator import generate_user_id
from cloudsim.core.audit import audit_logger, RT_AUTH, R_SUCCESS, R_DENIED
from cloudsim.db.database import db
from cloudsim.crypto.key_derivation import pbkdf2_sha256
from cloudsim.crypto.utils import generate_key_salt

router = APIRouter()


def _client_ip(request: Request) -> str:
    """IP asal permintaan (untuk kolom `source` audit log)."""
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

class RegisterRequest(BaseModel):
    username: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

class AuthResponse(BaseModel):
    token: str
    user_id: str
    key_salt: str   # hex encoded salt untuk derivasi kunci enkripsi

@router.post("/register", response_model=AuthResponse)
def register(req: RegisterRequest):
    """Registrasi pengguna baru dan langsung dapatkan token + key_salt."""
    if db.user_exists(req.username):
        raise HTTPException(status_code=400, detail="Username sudah terdaftar")
    
    user_id = generate_user_id()
    # Hash password untuk autentikasi
    password_salt = generate_key_salt()
    password_hash, password_salt_hex = auth_manager.hash_password(req.password, password_salt)
    # Salt untuk derivasi kunci enkripsi (disimpan di DB)
    key_salt_bytes = generate_key_salt()
    key_salt_hex = key_salt_bytes.hex()
    
    success = db.create_user(user_id, req.username, password_hash, password_salt_hex, key_salt_hex)
    if not success:
        raise HTTPException(status_code=500, detail="Gagal membuat pengguna")
    
    token = auth_manager.create_token(user_id)
    return AuthResponse(token=token, user_id=user_id, key_salt=key_salt_hex)

@router.post("/login", response_model=AuthResponse)
def login(req: LoginRequest):
    """Login dan dapatkan token akses + key_salt untuk enkripsi."""
    user = db.get_user_by_username(req.username)
    if not user:
        raise HTTPException(status_code=401, detail="Username atau password salah")
    if not auth_manager.verify_password(req.password, user["password_hash"], user["password_salt"]):
        raise HTTPException(status_code=401, detail="Username atau password salah")
    token = auth_manager.create_token(user["id"])
    return AuthResponse(token=token, user_id=user["id"], key_salt=user["key_salt"])
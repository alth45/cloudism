# pyrefly: ignore [missing-import]
from fastapi import Depends, HTTPException, status
# pyrefly: ignore [missing-import]
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from cloudsim.core.security import auth_manager
from cloudsim.db.database import db

bearer_scheme = HTTPBearer()

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> dict:
    """Dependency untuk mendapatkan user saat ini dari token JWT."""
    token = credentials.credentials
    payload = auth_manager.verify_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token tidak valid atau kedaluwarsa"
        )
    user_id = payload.get("user_id")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token tidak mengandung user_id"
        )
    user = db.get_user_by_id(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Pengguna tidak ditemukan"
        )
    return dict(user)
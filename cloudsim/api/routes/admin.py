# pyrefly: ignore [missing-import]
from fastapi import APIRouter, Depends, HTTPException
from cloudsim.api.dependencies import get_current_user
from cloudsim.db.database import db

router = APIRouter()

@router.get("/users")
def list_users(current_user: dict = Depends(get_current_user)):
    """Lihat daftar pengguna (khusus admin)."""
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Hanya admin yang dapat mengakses")
    import sqlite3
    rows = db.conn.execute("SELECT id, username, role FROM users").fetchall()
    users = [{"id": r["id"], "username": r["username"], "role": r["role"]} for r in rows]
    return users
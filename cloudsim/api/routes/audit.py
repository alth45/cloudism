# pyrefly: ignore [missing-import]
"""Endpoint REST untuk membaca audit log (siapa, apa, kapan).

Kebijakan akses:
- /audit dan /audit/mine : user terautentikasi.
  * Admin melihat seluruh log; user biasa hanya entri miliknya sendiri.
- /objects/{id}/audit    : riwayat satu objek — hanya owner atau penerima
  akses (ACL) yang boleh melihat.
Log bersifat append-only: tidak ada endpoint uba/hapus.
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from cloudsim.api.dependencies import get_current_user
from cloudsim.core.audit import audit_logger
from cloudsim.db.database import db

router = APIRouter()


def _is_admin(current_user: dict) -> bool:
    return current_user.get("role") == "admin"


@router.get("")
def list_audit_logs(
    actor_id: str | None = Query(None, description="Filter ID pelaku"),
    resource_id: str | None = Query(None, description="Filter ID sumber daya"),
    action: str | None = Query(None, description="Filter aksi (cocok awalan, mis. 'object.share')"),
    since: str | None = Query(None, description="Batas bawah timestamp ISO-8601 (inklusif)"),
    until: str | None = Query(None, description="Batas atas timestamp ISO-8601 (inklusif)"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    current_user: dict = Depends(get_current_user),
):
    """Daftar audit log terbaru dulu. Admin: semua; user biasa: milik sendiri."""
    if not _is_admin(current_user):
        # Non-admin dipaksa memfilter ke dirinya sendiri.
        if actor_id not in (None, current_user["id"]):
            raise HTTPException(status_code=403,
                                detail="Hanya admin yang dapat melihat log pengguna lain")
        actor_id = current_user["id"]
    return audit_logger.query(actor_id=actor_id, resource_id=resource_id,
                              action=action, since=since, until=until,
                              limit=limit, offset=offset)


@router.get("/mine")
def my_audit_logs(
    action: str | None = Query(None, description="Filter aksi (cocok awalan)"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    current_user: dict = Depends(get_current_user),
):
    """Audit log milik pengguna yang sedang login."""
    return audit_logger.query(actor_id=current_user["id"], action=action,
                              limit=limit, offset=offset)


@router.get("/objects/{object_id}/audit")
def object_audit_history(object_id: str,
                         limit: int = Query(100, ge=1, le=1000),
                         current_user: dict = Depends(get_current_user)):
    """Riwayat aksi pada satu objek (hanya owner/pemegang ACL/admin)."""
    obj = db.get_object_by_id(object_id)
    if obj is None:
        raise HTTPException(status_code=404, detail="Objek tidak ditemukan")
    is_owner = obj["owner_id"] == current_user["id"]
    has_acl = db.check_access(object_id, current_user["id"], "read")
    if not (is_owner or has_acl or _is_admin(current_user)):
        raise HTTPException(status_code=403,
                            detail="Tidak memiliki akses ke riwayat objek ini")
    return {"object_id": object_id,
            "items": audit_logger.history_for_object(object_id, limit=limit)}

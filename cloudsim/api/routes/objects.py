# pyrefly: ignore [missing-import]
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from typing import List
from cloudsim.core.engine import CloudObjectManager
from cloudsim.api.dependencies import get_current_user
from cloudsim.db.database import db
from cloudsim.core.acl import acl as acl_manager
from cloudsim.storage.storage_manager import StorageManager

router = APIRouter()

# Engine dengan storage manager nyata
object_manager = CloudObjectManager(StorageManager())

class ObjectMetadataResponse(BaseModel):
    id: str
    owner: str
    filename: str
    size: int
    mime_type: str
    created_at: str
    version: int

class UploadRequest(BaseModel):
    encrypted_payload: str   # base64
    nonce: str               # base64
    filename: str
    mime_type: str = "application/octet-stream"

class ShareRequest(BaseModel):
    username: str
    permission: str = "read"

# ---------- List ----------
@router.get("/", response_model=List[ObjectMetadataResponse])
def list_objects(current_user: dict = Depends(get_current_user)):
    """Daftar semua objek yang dapat diakses oleh user."""
    return object_manager.list_accessible_objects(current_user["id"])

# ---------- Upload ----------
@router.post("/upload", response_model=ObjectMetadataResponse)
def upload_object(req: UploadRequest, current_user: dict = Depends(get_current_user)):
    """Unggah file yang sudah dienkripsi oleh client."""
    metadata = object_manager.upload_encrypted(
        owner_id=current_user["id"],
        filename=req.filename,
        encrypted_payload=req.encrypted_payload,
        nonce=req.nonce,
        mime_type=req.mime_type
    )
    return metadata

# ---------- Info ----------
@router.get("/{object_id}", response_model=ObjectMetadataResponse)
def get_object_info(object_id: str, current_user: dict = Depends(get_current_user)):
    """Dapatkan metadata satu objek."""
    meta = object_manager.get_metadata(object_id, current_user["id"])
    if meta is None:
        raise HTTPException(status_code=404, detail="Objek tidak ditemukan atau akses ditolak")
    return meta

# ---------- Download ----------
@router.get("/{object_id}/download")
def download_object(object_id: str, current_user: dict = Depends(get_current_user)):
    """Dapatkan data terenkripsi untuk di-download (client akan mendekripsi sendiri)."""
    data = object_manager.download_encrypted(object_id, current_user["id"])
    if data is None:
        raise HTTPException(status_code=404, detail="Objek tidak ditemukan atau akses ditolak")
    return data

# ---------- Delete ----------
@router.delete("/{object_id}")
def delete_object(object_id: str, current_user: dict = Depends(get_current_user)):
    """Hapus objek. Hanya pemilik atau admin yang bisa."""
    success = object_manager.delete(object_id, current_user["id"])
    if not success:
        raise HTTPException(status_code=404, detail="Objek tidak ditemukan atau tidak bisa dihapus")
    return {"detail": "Objek berhasil dihapus"}

# ---------- Share ----------
@router.post("/{object_id}/share")
def share_object(
    object_id: str,
    share_req: ShareRequest,
    current_user: dict = Depends(get_current_user)
):
    """Bagikan akses objek ke pengguna lain."""
    meta = object_manager.get_metadata(object_id, current_user["id"])
    if not meta or meta["owner"] != current_user["id"]:
        raise HTTPException(status_code=403, detail="Hanya pemilik yang bisa membagikan objek")
    target_user = db.get_user_by_username(share_req.username)
    if not target_user:
        raise HTTPException(status_code=404, detail="User tujuan tidak ditemukan")

    # Tambahkan ACL di database dan di memory
    db.set_acl(object_id, target_user["id"], share_req.permission)
    acl_manager.share_with(object_id, target_user["id"], share_req.permission)
    return {"detail": f"Objek {object_id} dibagikan ke {share_req.username} dengan izin {share_req.permission}"}
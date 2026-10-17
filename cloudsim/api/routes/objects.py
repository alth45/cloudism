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
    version_id: str | None = None  # flag: ID versi current objek (versioning nyata)
    bucket_id: str | None = None

class VersionResponse(BaseModel):
    version_id: str
    object_id: str
    version: int
    filename: str
    mime_type: str
    size: int
    created_at: str
    created_by: str
    current: bool

class UploadRequest(BaseModel):
    encrypted_payload: str   # base64
    nonce: str               # base64
    filename: str
    mime_type: str = "application/octet-stream"
    bucket_id: str | None = None  # opsional: kaitkan objek ke bucket
    dek_wrapping: dict | None = None  # hasil key-wrapping DEK utk owner (re-encryption)

class ShareRequest(BaseModel):
    username: str
    permission: str = "read"
    dek_wrapping: dict | None = None  # hasil re-wrap DEK utk penerima (re-encryption)
    # dek_wrapping = {"wrapped_key": b64, "wrap_nonce": b64, "wrap_salt": hex, "iterations": int}

def _validate_wrapping(w: dict) -> dict:
    """Validasi bentuk dek_wrapping yang dikirim client."""
    required = ("wrapped_key", "wrap_nonce", "wrap_salt")
    if not isinstance(w, dict) or any(k not in w for k in required):
        raise HTTPException(
            status_code=422,
            detail="dek_wrapping tidak valid (butuh wrapped_key, wrap_nonce, wrap_salt)"
        )
    return w

# ---------- List ----------
@router.get("/", response_model=List[ObjectMetadataResponse])
def list_objects(bucket_id: str | None = None, current_user: dict = Depends(get_current_user)):
    """Daftar semua objek yang dapat diakses oleh user. Filter opsional per bucket."""
    return object_manager.list_accessible_objects(current_user["id"], bucket_id=bucket_id)

# ---------- Upload ----------
@router.post("/upload", response_model=ObjectMetadataResponse)
def upload_object(req: UploadRequest, current_user: dict = Depends(get_current_user)):
    """Unggah file yang sudah dienkripsi oleh client."""
    if req.bucket_id is not None:
        bucket = db.get_bucket_by_id(req.bucket_id)
        if not bucket or bucket["owner_id"] != current_user["id"]:
            raise HTTPException(status_code=404, detail="Bucket tidak ditemukan atau bukan milik Anda")
    if req.dek_wrapping is not None:
        _validate_wrapping(req.dek_wrapping)
    metadata = object_manager.upload_encrypted(
        owner_id=current_user["id"],
        filename=req.filename,
        encrypted_payload=req.encrypted_payload,
        nonce=req.nonce,
        mime_type=req.mime_type,
        bucket_id=req.bucket_id,
        dek_wrapping=req.dek_wrapping
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
def download_object(object_id: str, version_id: str | None = None,
                    current_user: dict = Depends(get_current_user)):
    """Dapatkan data terenkripsi untuk di-download (client akan mendekripsi sendiri).

    Opsional `?version_id=ver-...` untuk mengunduh versi tertentu (riwayat lama
    tetap tersedia — versi bersifat immutable). Tanpa parameter, versi current.
    """
    data = object_manager.download_encrypted(object_id, current_user["id"],
                                             version_id=version_id)
    if data is None:
        raise HTTPException(status_code=404, detail="Objek/versi tidak ditemukan atau akses ditolak")
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
    """Bagikan akses objek ke pengguna lain.

    Jika `dek_wrapping` disertakan (dihasilkan client dari re-encryption
    key-wrapping/PBKDF2), DEK objek dibungkus ulang dengan KEK turunan
    passphrase pembagian sehingga penerima dapat mendekripsi isinya.
    Tanpa `dek_wrapping`, hanya metadata+ciphertext yang dibagikan (mode lama).
    """
    meta = object_manager.get_metadata(object_id, current_user["id"])
    if not meta or meta["owner"] != current_user["id"]:
        raise HTTPException(status_code=403, detail="Hanya pemilik yang bisa membagikan objek")
    target_user = db.get_user_by_username(share_req.username)
    if not target_user:
        raise HTTPException(status_code=404, detail="User tujuan tidak ditemukan")

    if share_req.dek_wrapping is not None:
        _validate_wrapping(share_req.dek_wrapping)
        ok = object_manager.share_with_reencryption(
            object_id=object_id,
            owner_id=current_user["id"],
            target_user_id=target_user["id"],
            permission=share_req.permission,
            dek_wrapping=share_req.dek_wrapping,
        )
        if not ok:
            raise HTTPException(status_code=500, detail="Gagal menyimpan wrapped key")
        return {
            "detail": f"Objek {object_id} dibagikan ke {share_req.username} "
                      f"dengan izin {share_req.permission} (re-encryption: kunci di-wrap utk penerima)"
        }

    # Mode lama: tanpa re-encryption
    db.set_acl(object_id, target_user["id"], share_req.permission)
    acl_manager.share_with(object_id, target_user["id"], share_req.permission)
    return {"detail": f"Objek {object_id} dibagikan ke {share_req.username} dengan izin {share_req.permission}"}

class RevokeRequest(BaseModel):
    username: str

# ---------- Revoke ----------
@router.post("/{object_id}/revoke")
def revoke_share(object_id: str, req: RevokeRequest, current_user: dict = Depends(get_current_user)):
    """Cabut sharing: hapus ACL dan wrapped DEK milik penerima (hanya owner)."""
    meta = object_manager.get_metadata(object_id, current_user["id"])
    if not meta or meta["owner"] != current_user["id"]:
        raise HTTPException(status_code=403, detail="Hanya pemilik yang bisa mencabut akses")
    target_user = db.get_user_by_username(req.username)
    if not target_user:
        raise HTTPException(status_code=404, detail="User tujuan tidak ditemukan")
    ok = object_manager.revoke_share(object_id, current_user["id"], target_user["id"])
    if not ok:
        raise HTTPException(status_code=500, detail="Gagal mencabut akses")
    return {"detail": f"Akses {req.username} pada objek {object_id} dicabut"}

# ---------- Shares ----------
@router.get("/{object_id}/shares")
def list_shares(object_id: str, current_user: dict = Depends(get_current_user)):
    """Daftar pengguna yang memegang wrapped key pada objek ini."""
    shares = object_manager.list_shares(object_id, current_user["id"])
    if shares is None:
        raise HTTPException(status_code=404, detail="Objek tidak ditemukan atau akses ditolak")
    return shares

# ==================== VERSIONING NYATA PER OBJEK ====================

@router.get("/{object_id}/versions", response_model=List[VersionResponse])
def list_versions(object_id: str, current_user: dict = Depends(get_current_user)):
    """Daftar seluruh versi objek (terbaru dulu) beserta flag `current`."""
    versions = object_manager.list_versions(object_id, current_user["id"])
    if versions is None:
        raise HTTPException(status_code=404, detail="Objek tidak ditemukan atau akses ditolak")
    return versions

@router.get("/{object_id}/versions/{version_id}", response_model=VersionResponse)
def get_version(object_id: str, version_id: str, current_user: dict = Depends(get_current_user)):
    """Metadata satu versi tertentu."""
    v = object_manager.get_version(object_id, current_user["id"], version_id)
    if v is None:
        raise HTTPException(status_code=404, detail="Versi tidak ditemukan atau akses ditolak")
    return v

@router.post("/{object_id}/versions/{version_id}/restore")
def restore_version(object_id: str, version_id: str, current_user: dict = Depends(get_current_user)):
    """Restore versi lama menjadi versi aktif.

    Non-destructive: dibuat VERSI BARU yang isinya salinan versi target
    (riwayat tetap utuh), lalu ditandai sebagai current. Hanya owner."""
    meta = object_manager.get_metadata(object_id, current_user["id"])
    if not meta or meta["owner"] != current_user["id"]:
        raise HTTPException(status_code=403, detail="Hanya pemilik yang bisa me-restore versi")
    result = object_manager.restore_version(object_id, current_user["id"], version_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Versi tidak ditemukan")
    return {
        "detail": f"Versi {version_id} berhasil di-restore sebagai versi {result['version']}",
        **result
    }
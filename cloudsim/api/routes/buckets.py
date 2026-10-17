# pyrefly: ignore [missing-import]
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from typing import List, Optional

from cloudsim.core.engine import CloudObjectManager
from cloudsim.api.dependencies import get_current_user
from cloudsim.storage.storage_manager import StorageManager

router = APIRouter()

object_manager = CloudObjectManager(StorageManager())


class BucketCreateRequest(BaseModel):
    name: str = Field(..., min_length=3, max_length=63,
                      pattern=r"^[a-z0-9][a-z0-9._-]*[a-z0-9]$",
                      description="Nama bucket: huruf kecil, angka, '-', '.', '_'")


class BucketResponse(BaseModel):
    id: str
    name: str
    owner_id: str
    created_at: str


class ObjectInBucketResponse(BaseModel):
    id: str
    owner: str
    filename: str
    size: int
    mime_type: str
    created_at: str
    version: int
    bucket_id: Optional[str] = None


# ---------- Buat bucket ----------
@router.post("", response_model=BucketResponse)
def create_bucket(req: BucketCreateRequest, current_user: dict = Depends(get_current_user)):
    """Buat bucket baru milik user saat ini. Nama unik secara global."""
    bucket = object_manager.create_bucket(current_user["id"], req.name)
    if bucket is None:
        raise HTTPException(status_code=409, detail=f"Bucket '{req.name}' sudah ada atau gagal dibuat")
    return bucket


# ---------- List bucket user ----------
@router.get("", response_model=List[BucketResponse])
def list_buckets(current_user: dict = Depends(get_current_user)):
    """Daftar semua bucket milik user saat ini."""
    return object_manager.list_buckets(current_user["id"])


# ---------- Info bucket + isi ----------
@router.get("/{bucket_id}")
def get_bucket(bucket_id: str, current_user: dict = Depends(get_current_user)):
    """Info bucket dan daftar objek yang bisa diakses di dalamnya."""
    bucket = object_manager.get_bucket(bucket_id, current_user["id"])
    if bucket is None:
        raise HTTPException(status_code=404, detail="Bucket tidak ditemukan atau bukan milik Anda")
    objects = object_manager.list_accessible_objects(current_user["id"], bucket_id=bucket_id)
    return {"bucket": bucket, "objects": objects}


# ---------- Hapus bucket ----------
@router.delete("/{bucket_id}")
def delete_bucket(bucket_id: str, current_user: dict = Depends(get_current_user)):
    """Hapus bucket. Hanya pemilik, dan bucket harus kosong."""
    ok = object_manager.delete_bucket(bucket_id, current_user["id"])
    if not ok:
        raise HTTPException(
            status_code=400,
            detail="Gagal menghapus: bucket tidak ditemukan, bukan milik Anda, atau masih berisi objek"
        )
    return {"detail": f"Bucket {bucket_id} berhasil dihapus"}


# ---------- Resolve nama bucket ke ID (untuk CLI gs://) ----------
@router.get("/name/{name}/id")
def resolve_bucket_name(name: str, current_user: dict = Depends(get_current_user)):
    """Resolve nama bucket menjadi ID. Hanya untuk pemilik bucket."""
    bucket = object_manager.get_bucket(object_manager.get_bucket_id_by_name(name) or "", current_user["id"])
    if bucket is None:
        raise HTTPException(status_code=404, detail="Bucket tidak ditemukan atau bukan milik Anda")
    return {"id": bucket["id"], "name": bucket["name"]}


# ---------- Cari objek di bucket via nama/ID (gs://bucket/identifier) ----------
@router.get("/name/{name}/objects/{identifier}")
def find_object_in_bucket(name: str, identifier: str, current_user: dict = Depends(get_current_user)):
    """Cari objek di bucket berdasarkan ID objek atau nama file."""
    meta = object_manager.resolve_object(current_user["id"], name, identifier)
    if meta is None:
        raise HTTPException(status_code=404, detail="Objek tidak ditemukan di bucket atau akses ditolak")
    return meta

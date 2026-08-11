import json
import os
from datetime import datetime, timezone
from typing import Optional

from cloudsim.core.id_generator import generate_object_id, generate_bucket_id
from cloudsim.core.acl import acl as acl_manager
from cloudsim.db.database import db
from cloudsim.storage.storage_manager import StorageManager


class CloudObjectManager:
    """Mengelola objek cloud: menyimpan ciphertext ke DB + storage.txt."""

    def __init__(self, storage_manager: StorageManager = None):
        self.storage = storage_manager or StorageManager()

    def upload_encrypted(self, owner_id: str, filename: str,
                         encrypted_payload: str, nonce: str,
                         mime_type: str = "application/octet-stream",
                         bucket_id: str = None) -> dict:
        """Simpan ciphertext yang sudah dienkripsi client.
        Jika bucket_id diberikan, kaitkan objek ke bucket tersebut."""
        obj_id = generate_object_id()
        created_at = datetime.now(timezone.utc).isoformat()
        payload_size = len(encrypted_payload.encode('utf-8'))  # ukuran base64 string

        # Tulis ke database
        success = db.create_object(
            obj_id=obj_id,
            owner_id=owner_id,
            filename=filename,
            size=payload_size,
            mime_type=mime_type,
            encrypted_payload=encrypted_payload,
            iv="",          # mode CTR tidak butuh IV terpisah, nonce sudah cukup
            nonce=nonce,
            created_at=created_at,
            bucket_id=bucket_id
        )
        if not success:
            raise Exception("Gagal menyimpan ke database")

        # Tulis ke storage.txt (append-only)
        record = {
            "id": obj_id,
            "owner": owner_id,
            "filename": filename,
            "mime_type": mime_type,
            "encrypted_payload": encrypted_payload,
            "nonce": nonce,
            "created_at": created_at,
            "bucket_id": bucket_id,
            "deleted": False
        }
        line = self.storage.append_record(record)

        # Update storage_line di database
        db.conn.execute("UPDATE objects SET storage_line = ? WHERE id = ?", (line, obj_id))
        db.conn.commit()

        # Set ACL owner
        acl_manager.set_owner(obj_id, owner_id)

        return {
            "id": obj_id,
            "owner": owner_id,
            "filename": filename,
            "size": payload_size,
            "mime_type": mime_type,
            "created_at": created_at,
            "version": 1,
            "bucket_id": bucket_id
        }

    def download_encrypted(self, object_id: str, user_id: str) -> Optional[dict]:
        """Dapatkan data terenkripsi untuk didownload (setelah cek akses)."""
        if not db.check_access(object_id, user_id, "read"):
            return None
        obj = db.get_object_by_id(object_id)
        if not obj:
            return None
        return {
            "encrypted_payload": obj["encrypted_payload"],
            "nonce": obj["nonce"],
            "filename": obj["filename"],
            "mime_type": obj["mime_type"]
        }

    def delete(self, object_id: str, user_id: str) -> bool:
        """Hapus objek (hanya owner). Menambah tombstone di storage."""
        obj = db.get_object_by_id(object_id)
        if not obj or obj["owner_id"] != user_id:
            return False
        # Tandai deleted di storage
        tombstone = {
            "id": object_id,
            "deleted": True,
            "deleted_at": datetime.now(timezone.utc).isoformat()
        }
        self.storage.append_record(tombstone)
        # Hapus dari database
        db.delete_object(object_id)
        # Hapus ACL
        acl_manager.revoke_access(object_id, user_id)  # kurang lengkap, tapi ok
        return True

    def list_accessible_objects(self, user_id: str, bucket_id: str = None) -> list[dict]:
        """List objek yang dapat diakses user, dari DB.
        Jika bucket_id diberikan, hanya tampilkan objek pada bucket tersebut."""
        rows = db.list_accessible_objects(user_id, bucket_id)
        result = []
        for r in rows:
            result.append({
                "id": r["id"],
                "owner": r["owner_id"],
                "filename": r["filename"],
                "size": r["size"],
                "mime_type": r["mime_type"],
                "created_at": r["created_at"],
                "version": 1,
                "bucket_id": r["bucket_id"] if "bucket_id" in r.keys() else None
            })
        return result

    def get_metadata(self, object_id: str, user_id: str) -> Optional[dict]:
        """Metadata tanpa payload."""
        if not db.check_access(object_id, user_id, "read"):
            return None
        obj = db.get_object_by_id(object_id)
        if not obj:
            return None
        return {
            "id": obj["id"],
            "owner": obj["owner_id"],
            "filename": obj["filename"],
            "size": obj["size"],
            "mime_type": obj["mime_type"],
            "created_at": obj["created_at"],
            "version": 1,
            "bucket_id": obj["bucket_id"] if "bucket_id" in obj.keys() else None
        }

    # ==================== BUCKET MANAGEMENT ====================
    def create_bucket(self, owner_id: str, name: str) -> Optional[dict]:
        """Buat bucket baru untuk user. Mengembalikan metadata bucket atau None jika gagal."""
        bucket_id = generate_bucket_id()
        created_at = datetime.now(timezone.utc).isoformat()
        success = db.create_bucket(bucket_id, name, owner_id, created_at)
        if not success:
            return None  # nama sudah ada
        return {
            "id": bucket_id,
            "name": name,
            "owner_id": owner_id,
            "created_at": created_at
        }

    def list_buckets(self, owner_id: str) -> list[dict]:
        """Daftar semua bucket yang dimiliki oleh user."""
        rows = db.get_buckets_by_owner(owner_id)
        return [
            {
                "id": r["id"],
                "name": r["name"],
                "owner_id": r["owner_id"],
                "created_at": r["created_at"]
            }
            for r in rows
        ]

    def get_bucket_id_by_name(self, name: str) -> Optional[str]:
        """Resolve nama bucket ke ID."""
        bucket = db.get_bucket_by_name(name)
        return bucket["id"] if bucket else None

    def get_bucket(self, bucket_id: str, owner_id: str) -> Optional[dict]:
        """Dapatkan info bucket jika dimiliki oleh user."""
        bucket = db.get_bucket_by_id(bucket_id)
        if not bucket:
            return None
        if bucket["owner_id"] != owner_id:
            return None
        return {
            "id": bucket["id"],
            "name": bucket["name"],
            "owner_id": bucket["owner_id"],
            "created_at": bucket["created_at"]
        }

    def delete_bucket(self, bucket_id: str, owner_id: str) -> bool:
        """Hapus bucket jika kosong dan user adalah pemiliknya."""
        # Validasi kepemilikan
        bucket = db.get_bucket_by_id(bucket_id)
        if not bucket or bucket["owner_id"] != owner_id:
            return False
        # Delewakan ke db.delete_bucket yang akan mengecek kekosongan
        return db.delete_bucket(bucket_id, owner_id)
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
                         bucket_id: str = None,
                         dek_wrapping: dict = None) -> dict:
        """Simpan ciphertext yang sudah dienkripsi client.
        Jika bucket_id diberikan, kaitkan objek ke bucket tersebut.
        Jika dek_wrapping diberikan (hasil wrap_key DEK untuk owner),
        simpan pula kunci ter-bungkusnya agar objek mendukung re-encryption
        saat sharing."""
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

        # Simpan wrapped DEK milik owner (untuk re-encryption saat sharing)
        if dek_wrapping:
            db.set_object_key(
                object_id=obj_id,
                user_id=owner_id,
                wrapped_key=dek_wrapping["wrapped_key"],
                wrap_nonce=dek_wrapping["wrap_nonce"],
                wrap_salt=dek_wrapping["wrap_salt"],
                iterations=int(dek_wrapping.get("iterations", 100000)),
                created_at=created_at,
            )

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
        result = {
            "encrypted_payload": obj["encrypted_payload"],
            "nonce": obj["nonce"],
            "filename": obj["filename"],
            "mime_type": obj["mime_type"]
        }
        # Sertakan wrapped DEK untuk pengguna ini bila ada (alur re-encryption).
        key_row = db.get_object_key(object_id, user_id)
        if key_row:
            result["wrapped_key"] = {
                "wrapped_key": key_row["wrapped_key"],
                "wrap_nonce": key_row["wrap_nonce"],
                "wrap_salt": key_row["wrap_salt"],
                "iterations": key_row["iterations"],
            }
        return result

    def share_with_reencryption(self, object_id: str, owner_id: str, target_user_id: str,
                                permission: str, dek_wrapping: dict) -> bool:
        """Re-encryption saat sharing: simpan DEK yang sudah di-wrap ulang oleh
        client owner memakai KEK turunan passphrase pembagian untuk penerima.

        Payload ciphertext TIDAK diubah — yang di-re-encrypt adalah kunci datanya
        (key-wrapping), sehingga server tetap tidak pernah melihat plaintext/DEK.
        """
        obj = db.get_object_by_id(object_id)
        if not obj or obj["owner_id"] != owner_id:
            return False
        created_at = datetime.now(timezone.utc).isoformat()
        ok = db.set_object_key(
            object_id=object_id,
            user_id=target_user_id,
            wrapped_key=dek_wrapping["wrapped_key"],
            wrap_nonce=dek_wrapping["wrap_nonce"],
            wrap_salt=dek_wrapping["wrap_salt"],
            iterations=int(dek_wrapping.get("iterations", 100000)),
            created_at=created_at,
        )
        if not ok:
            return False
        db.set_acl(object_id, target_user_id, permission)
        acl_manager.share_with(object_id, target_user_id, permission)
        return True

    def revoke_share(self, object_id: str, owner_id: str, target_user_id: str) -> bool:
        """Cabut sharing: hapus ACL dan wrapped DEK milik penerima."""
        obj = db.get_object_by_id(object_id)
        if not obj or obj["owner_id"] != owner_id:
            return False
        db.remove_acl(object_id, target_user_id)
        acl_manager.revoke_access(object_id, target_user_id)
        # Ganti wrapped key penerima dengan versi ter-bungkus passphrase acak
        # agar tidak bisa lagi membuka DEK lama? Cukup hapus barisnya.
        cur = db.conn.execute(
            "DELETE FROM object_keys WHERE object_id = ? AND user_id = ?",
            (object_id, target_user_id)
        )
        db.conn.commit()
        return cur.rowcount >= 0  # sukses meski tidak ada key yang terhapus

    def list_shares(self, object_id: str, user_id: str) -> Optional[list]:
        """Daftar pembagian objek: siapa saja yang memegang wrapped DEK."""
        if not db.check_access(object_id, user_id, "read"):
            return None
        rows = db.list_object_keys(object_id)
        result = []
        for r in rows:
            u = db.get_user_by_id(r["user_id"])
            result.append({
                "user_id": r["user_id"],
                "username": u["username"] if u else "?",
                "permission": db.get_acl(object_id, r["user_id"]) or "owner",
                "created_at": r["created_at"],
            })
        return result

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
        # Hapus dari database (wrapped keys ikut terhapus via ON DELETE CASCADE)
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
        # Delegasikan ke db.delete_bucket yang akan mengecek kekosongan
        return db.delete_bucket(bucket_id, owner_id)

    def resolve_object(self, user_id: str, bucket_name: str, identifier: str) -> Optional[dict]:
        """Resolve path gs://bucket/identifier menjadi objek yang bisa diakses user.
        Identifier bisa berupa ID objek (obj-...) atau nama file di dalam bucket.
        Mengembalikan metadata objek + bucket_name, atau None jika tidak ditemukan."""
        bucket = db.get_bucket_by_name(bucket_name)
        if not bucket:
            return None
        obj = db.find_accessible_object_by_name(user_id, bucket["id"], identifier)
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
            "bucket_id": obj["bucket_id"],
            "bucket_name": bucket["name"]
        }
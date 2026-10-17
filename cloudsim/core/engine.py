import json
import os
from datetime import datetime, timezone, timedelta
from typing import Optional

from cloudsim.core.id_generator import generate_object_id, generate_bucket_id, generate_version_id
from cloudsim.core.acl import acl as acl_manager
from cloudsim.core.audit import audit_logger, RT_OBJECT, RT_BUCKET, R_SUCCESS, R_DENIED, R_FAILED
from cloudsim.db.database import db, get_trash_retention_days
from cloudsim.storage.storage_manager import StorageManager


class CloudObjectManager:
    """Mengelola objek cloud: menyimpan ciphertext ke DB + storage.txt."""

    def __init__(self, storage_manager: StorageManager = None):
        self.storage = storage_manager or StorageManager()

    # ==================== AUDIT HELPERS ====================
    @staticmethod
    def _username(actor_id):
        """Resolver nama actor untuk entri audit (best-effort)."""
        if not actor_id:
            return None
        u = db.get_user_by_id(actor_id)
        return u["username"] if u else None

    def _audit(self, action, *, actor_id=None, resource_id=None,
               resource_name=None, details=None, result=R_SUCCESS, source=None):
        """Tulis entri audit log (siapa, apa, kapan). Non-blocking: kegagalan
        pencatatan tidak boleh menggagalkan operasi utama."""
        try:
            audit_logger.record(action, RT_OBJECT,
                                actor_id=actor_id,
                                actor_username=self._username(actor_id),
                                resource_id=resource_id,
                                resource_name=resource_name,
                                details=details, result=result, source=source)
        except Exception:
            pass

    def upload_encrypted(self, owner_id: str, filename: str,
                         encrypted_payload: str, nonce: str,
                         mime_type: str = "application/octet-stream",
                         bucket_id: str = None,
                         dek_wrapping: dict = None) -> dict:
        """Simpan ciphertext yang sudah dienkripsi client.
        Jika bucket_id diberikan, kaitkan objek ke bucket tersebut.
        Jika dek_wrapping diberikan (hasil wrap_key DEK untuk owner),
        simpan pula kunci ter-bungkusnya agar objek mendukung re-encryption
        saat sharing.

        VERSIONING NYATA: jika sudah ada objek milik owner dengan nama file
        yang sama pada bucket yang sama, upload ini menjadi VERSI BARU pada
        objek yang sama (nomor versi naik, `version_id` baru dibuat, dan
        menjadi versi current). Objek lama tidak ditimpa — setiap versi
        tersimpan immutable di tabel object_versions + storage.txt.
        """
        created_at = datetime.now(timezone.utc).isoformat()
        payload_size = len(encrypted_payload.encode('utf-8'))  # ukuran base64 string

        existing = db.find_object_for_versioning(owner_id, filename, bucket_id)
        if existing:
            obj_id = existing["id"]
            version_no = db.next_version_number(obj_id)
        else:
            obj_id = generate_object_id()
            version_no = 1
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

        # Tulis ke storage.txt (append-only) — satu baris per versi, immutable
        record = {
            "id": obj_id,
            "owner": owner_id,
            "filename": filename,
            "mime_type": mime_type,
            "encrypted_payload": encrypted_payload,
            "nonce": nonce,
            "created_at": created_at,
            "bucket_id": bucket_id,
            "version": version_no,
            "deleted": False
        }
        line = self.storage.append_record(record)

        if existing:
            # Update baris objects agar mencerminkan versi terbaru
            db.update_object_payload(
                obj_id=obj_id,
                encrypted_payload=encrypted_payload,
                nonce=nonce,
                size=payload_size,
                mime_type=mime_type,
                updated_at=created_at,
                storage_line=line,
            )
        else:
            db.conn.execute("UPDATE objects SET storage_line = ? WHERE id = ?", (line, obj_id))
            db.conn.commit()

        # Buat rekaman versi baru + flag current
        version_id = generate_version_id()
        ok = db.create_object_version(
            version_id=version_id,
            object_id=obj_id,
            version=version_no,
            filename=filename,
            mime_type=mime_type,
            size=payload_size,
            encrypted_payload=encrypted_payload,
            nonce=nonce,
            created_at=created_at,
            created_by=owner_id,
            storage_line=line,
        )
        if not ok:
            raise Exception("Gagal menyimpan versi objek")
        db.set_current_version(obj_id, version_id)

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

        # --- Audit: upload / versi baru (siapa, apa, kapan) ---
        self._audit("object.upload.new" if not existing else "object.upload.version",
                    actor_id=owner_id, resource_id=obj_id, resource_name=filename,
                    details={"version": version_no, "version_id": version_id,
                             "bucket_id": bucket_id, "size": payload_size})

        return {
            "id": obj_id,
            "owner": owner_id,
            "filename": filename,
            "size": payload_size,
            "mime_type": mime_type,
            "created_at": created_at,
            "version": version_no,
            "version_id": version_id,
            "bucket_id": bucket_id
        }

    def download_encrypted(self, object_id: str, user_id: str,
                           version_id: str = None) -> Optional[dict]:
        """Dapatkan data terenkripsi untuk didownload (setelah cek akses).

        Jika `version_id` diberikan, kembalikan snapshot versi tersebut
        (versi lama tetap bisa diunduh — sifat immutable dari versioning).
        Tanpa version_id, kembalikan versi current."""
        if not db.check_access(object_id, user_id, "read"):
            self._audit("object.download", actor_id=user_id, resource_id=object_id,
                        result=R_DENIED, details={"reason": "access denied"})
            return None
        obj = db.get_object_by_id(object_id)
        if not obj:
            self._audit("object.download", actor_id=user_id, resource_id=object_id,
                        result=R_DENIED, details={"reason": "object not found"})
            return None
        # Objek di trash tidak bisa didownload (kecuali restore dulu)
        if "status" in obj.keys() and obj["status"] == "trashed":
            self._audit("object.download", actor_id=user_id, resource_id=object_id,
                        resource_name=obj["filename"], result=R_DENIED,
                        details={"reason": "object in trash"})
            return None
        if version_id is not None:
            ver = db.get_object_version(version_id)
            if not ver or ver["object_id"] != object_id:
                self._audit("object.download", actor_id=user_id, resource_id=object_id,
                            resource_name=obj["filename"], result=R_DENIED,
                            details={"reason": "version not found", "version_id": version_id})
                return None
            payload = ver["encrypted_payload"]
            nonce_v = ver["nonce"]
            mime = ver["mime_type"]
        else:
            payload = obj["encrypted_payload"]
            nonce_v = obj["nonce"]
            mime = obj["mime_type"]
        result = {
            "encrypted_payload": payload,
            "nonce": nonce_v,
            "filename": obj["filename"],
            "mime_type": mime
        }
        if version_id is not None:
            result["version_id"] = version_id
        # Sertakan wrapped DEK untuk pengguna ini bila ada (alur re-encryption).
        key_row = db.get_object_key(object_id, user_id)
        if key_row:
            result["wrapped_key"] = {
                "wrapped_key": key_row["wrapped_key"],
                "wrap_nonce": key_row["wrap_nonce"],
                "wrap_salt": key_row["wrap_salt"],
                "iterations": key_row["iterations"],
            }
        self._audit("object.download", actor_id=user_id, resource_id=object_id,
                    resource_name=obj["filename"],
                    details={"version_id": version_id} if version_id else None)
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
            self._audit("object.share", actor_id=owner_id, resource_id=object_id,
                        result=R_DENIED,
                        details={"target_user_id": target_user_id, "reason": "not owner"})
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
            self._audit("object.share", actor_id=owner_id, resource_id=object_id,
                        result=R_FAILED,
                        details={"target_user_id": target_user_id, "reason": "wrapped key gagal disimpan"})
            return False
        db.set_acl(object_id, target_user_id, permission)
        acl_manager.share_with(object_id, target_user_id, permission)
        self._audit("object.share", actor_id=owner_id, resource_id=object_id,
                    resource_name=obj["filename"],
                    details={"target_user_id": target_user_id,
                            "target_username": self._username(target_user_id),
                            "permission": permission, "re_encryption": True})
        return True

    def revoke_share(self, object_id: str, owner_id: str, target_user_id: str) -> bool:
        """Cabut sharing: hapus ACL dan wrapped DEK milik penerima."""
        obj = db.get_object_by_id(object_id)
        if not obj or obj["owner_id"] != owner_id:
            self._audit("object.revoke", actor_id=owner_id, resource_id=object_id,
                        result=R_DENIED,
                        details={"target_user_id": target_user_id, "reason": "not owner"})
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
        self._audit("object.revoke", actor_id=owner_id, resource_id=object_id,
                    resource_name=obj["filename"],
                    details={"target_user_id": target_user_id,
                            "target_username": self._username(target_user_id)})
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
            self._audit("object.delete.permanent", actor_id=user_id,
                        resource_id=object_id, result=R_DENIED,
                        details={"reason": "objek tidak ada / bukan pemilik"})
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
        self._audit("object.delete.permanent", actor_id=user_id, resource_id=object_id,
                    resource_name=obj["filename"], details={"via_trash": False})
        return True

    # ==================== SOFT DELETE & TRASH ====================
    def _trash_window(self):
        """(trashed_at_iso, purge_after_iso) sesuai konfigurasi retensi saat ini."""
        now = datetime.now(timezone.utc)
        days = get_trash_retention_days()
        return now.isoformat(), (now + timedelta(days=days)).isoformat()

    def soft_delete(self, object_id: str, user_id: str) -> Optional[dict]:
        """Soft delete: pindahkan objek ke trash dengan batas retensi waktu.

        Hanya owner yang bisa melakukan. Objek yang sudah berada di trash
        tidak bisa ditras ulang (kembalikan None). Mengembalikan metadata
        trash (termasuk `purge_after`) bila sukses."""
        obj = db.get_object_by_id(object_id)
        if not obj or obj["owner_id"] != user_id:
            self._audit("object.trash", actor_id=user_id, resource_id=object_id,
                        result=R_DENIED, details={"reason": "objek tidak ada / bukan pemilik"})
            return None
        if "status" in obj.keys() and obj["status"] == "trashed":
            self._audit("object.trash", actor_id=user_id, resource_id=object_id,
                        resource_name=obj["filename"], result=R_DENIED,
                        details={"reason": "sudah berada di trash"})
            return None  # sudah di trash
        trashed_at, purge_after = self._trash_window()
        if not db.mark_object_trashed(object_id, trashed_at, purge_after):
            self._audit("object.trash", actor_id=user_id, resource_id=object_id,
                        resource_name=obj["filename"], result=R_FAILED,
                        details={"reason": "gagal menandai trash"})
            return None
        # Tombstone non-destruktif di storage (objek belum hilang permanen)
        self.storage.append_record({
            "id": object_id,
            "trashed": True,
            "trashed_at": trashed_at,
            "purge_after": purge_after,
        })
        self._audit("object.trash", actor_id=user_id, resource_id=object_id,
                    resource_name=obj["filename"],
                    details={"trashed_at": trashed_at, "purge_after": purge_after})
        return {
            "id": object_id,
            "filename": obj["filename"],
            "trashed_at": trashed_at,
            "purge_after": purge_after,
            "retention_days": get_trash_retention_days(),
        }

    def restore_from_trash(self, object_id: str, user_id: str) -> Optional[dict]:
        """Keluarkan objek dari trash dan aktifkan kembali (hanya owner)."""
        obj = db.get_object_by_id(object_id)
        if not obj or obj["owner_id"] != user_id:
            self._audit("object.restore", actor_id=user_id, resource_id=object_id,
                        result=R_DENIED, details={"reason": "objek tidak ada / bukan pemilik"})
            return None
        if not db.restore_object_from_trash(object_id):
            self._audit("object.restore", actor_id=user_id, resource_id=object_id,
                        resource_name=obj["filename"], result=R_DENIED,
                        details={"reason": "objek tidak berada di trash"})
            return None
        self.storage.append_record({
            "id": object_id,
            "restored_from_trash": True,
            "restored_at": datetime.now(timezone.utc).isoformat(),
        })
        self._audit("object.restore", actor_id=user_id, resource_id=object_id,
                    resource_name=obj["filename"])
        return {
            "id": object_id,
            "filename": obj["filename"],
            "restored_at": datetime.now(timezone.utc).isoformat(),
        }

    def list_trash(self, user_id: str, bucket_id: str = None) -> list[dict]:
        """Daftar objek di trash milik user, termasuk sisa hari retensi."""
        out = []
        for r in db.list_trashed_objects(user_id, bucket_id):
            keys = r.keys()
            remaining = None
            if "purge_after" in keys and r["purge_after"]:
                try:
                    dt = datetime.fromisoformat(r["purge_after"])
                    remaining = max((dt - datetime.now(timezone.utc)).total_seconds() / 86400.0, 0.0)
                except ValueError:
                    remaining = None
            out.append({
                "id": r["id"],
                "filename": r["filename"],
                "size": r["size"],
                "mime_type": r["mime_type"],
                "created_at": r["created_at"],
                "bucket_id": r["bucket_id"] if "bucket_id" in keys else None,
                "version": r["version"] if "version" in keys else 1,
                "trashed_at": r["trashed_at"] if "trashed_at" in keys else None,
                "purge_after": r["purge_after"] if "purge_after" in keys else None,
                "days_remaining": round(remaining, 2) if remaining is not None else None,
            })
        return out

    def trash_count(self, user_id: str) -> int:
        return db.count_trashed_objects(user_id)

    def purge_object(self, object_id: str, user_id: str) -> bool:
        """Hapus permanen satu objek dari trash sebelum batas waktunya (hanya owner)."""
        obj = db.get_object_by_id(object_id)
        if not obj or obj["owner_id"] != user_id:
            self._audit("object.purge", actor_id=user_id, resource_id=object_id,
                        result=R_DENIED, details={"reason": "objek tidak ada / bukan pemilik"})
            return False
        if "status" not in obj.keys() or obj["status"] != "trashed":
            self._audit("object.purge", actor_id=user_id, resource_id=object_id,
                        resource_name=obj["filename"], result=R_DENIED,
                        details={"reason": "objek tidak berada di trash"})
            return False  # hanya objek di trash yang boleh di-purge manual
        self.storage.append_record({
            "id": object_id,
            "deleted": True,
            "permanently_deleted_at": datetime.now(timezone.utc).isoformat(),
        })
        ok = db.delete_object(object_id)
        self._audit("object.purge", actor_id=user_id, resource_id=object_id,
                    resource_name=obj["filename"],
                    result=R_SUCCESS if ok else R_FAILED,
                    details={"via_trash": True})
        return ok

    def empty_trash(self, user_id: str) -> int:
        """Hapus permanen seluruh isi trash milik user. Kembalikan jumlah objek."""
        purged = 0
        purged_names = []
        for r in db.list_trashed_objects(user_id):
            if db.delete_object(r["id"]):
                purged += 1
                purged_names.append(r["filename"])
                self.storage.append_record({
                    "id": r["id"],
                    "deleted": True,
                    "permanently_deleted_at": datetime.now(timezone.utc).isoformat(),
                })
                self._audit("object.purge", actor_id=user_id, resource_id=r["id"],
                            resource_name=r["filename"],
                            details={"via_trash": True, "trigger": "empty_trash"})
        return purged

    def auto_purge_expired(self) -> int:
        """Purge otomatis objek di trash yang melewati batas retensi.

        Dipanggil lazy (mis. saat listing trash / awal sesi). Mengembalikan
        jumlah objek yang dipurge."""
        now_iso = datetime.now(timezone.utc).isoformat()
        expired = db.get_expired_trash_ids(now_iso)
        for oid in expired:
            obj = db.get_object_by_id(oid)
            self.storage.append_record({
                "id": oid,
                "deleted": True,
                "auto_purged_at": now_iso,
            })
            db.delete_object(oid)
            # Pencatat 'system': aksi otomatis, bukan perintah user langsung
            try:
                audit_logger.record("object.auto_purge", RT_OBJECT,
                                    actor_id=None, actor_username="system",
                                    resource_id=oid,
                                    resource_name=obj["filename"] if obj else None,
                                    details={"purge_after_lewat": now_iso},
                                    result=R_SUCCESS, source="system")
            except Exception:
                pass
        return len(expired)

    def list_accessible_objects(self, user_id: str, bucket_id: str = None) -> list[dict]:
        """List objek yang dapat diakses user, dari DB.
        Jika bucket_id diberikan, hanya tampilkan objek pada bucket tersebut."""
        rows = db.list_accessible_objects(user_id, bucket_id)
        result = []
        for r in rows:
            keys = r.keys()
            version = r["version"] if "version" in keys else 1
            ver_id = r["current_version_id"] if "current_version_id" in keys else None
            result.append({
                "id": r["id"],
                "owner": r["owner_id"],
                "filename": r["filename"],
                "size": r["size"],
                "mime_type": r["mime_type"],
                "created_at": r["created_at"],
                "version": version,
                "version_id": ver_id,
                "bucket_id": r["bucket_id"] if "bucket_id" in keys else None
            })
        return result

    def get_metadata(self, object_id: str, user_id: str) -> Optional[dict]:
        """Metadata tanpa payload."""
        if not db.check_access(object_id, user_id, "read"):
            return None
        obj = db.get_object_by_id(object_id)
        if not obj:
            return None
        # Objek di trash tersembunyi dari metadata publik (404)
        if "status" in obj.keys() and obj["status"] == "trashed":
            return None
        keys = obj.keys()
        return {
            "id": obj["id"],
            "owner": obj["owner_id"],
            "filename": obj["filename"],
            "size": obj["size"],
            "mime_type": obj["mime_type"],
            "created_at": obj["created_at"],
            "version": obj["version"] if "version" in keys else 1,
            "version_id": obj["current_version_id"] if "current_version_id" in keys else None,
            "bucket_id": obj["bucket_id"] if "bucket_id" in keys else None
        }

    # ==================== OBJECT VERSIONING (nyata, per objek) ====================
    def list_versions(self, object_id: str, user_id: str) -> Optional[list]:
        """Daftar seluruh versi sebuah objek (termasuk flag `current`).
        Mengembalikan None jika objek tidak ada / akses ditolak."""
        if not db.check_access(object_id, user_id, "read"):
            return None
        obj = db.get_object_by_id(object_id)
        if not obj:
            return None
        # Riwayat versi objek di trash tidak ditampilkan (tersembunyi)
        if "status" in obj.keys() and obj["status"] == "trashed":
            return None
        out = []
        for v in db.list_object_versions(object_id):
            out.append({
                "version_id": v["version_id"],
                "object_id": v["object_id"],
                "version": v["version"],
                "filename": v["filename"],
                "mime_type": v["mime_type"],
                "size": v["size"],
                "created_at": v["created_at"],
                "created_by": v["created_by"],
                "current": bool(v["is_current"]),
            })
        return out

    def get_version(self, object_id: str, user_id: str, version_id: str) -> Optional[dict]:
        """Metadata satu versi tertentu (tanpa payload)."""
        if not db.check_access(object_id, user_id, "read"):
            return None
        v = db.get_object_version(version_id)
        if not v or v["object_id"] != object_id:
            return None
        return {
            "version_id": v["version_id"],
            "object_id": v["object_id"],
            "version": v["version"],
            "filename": v["filename"],
            "mime_type": v["mime_type"],
            "size": v["size"],
            "created_at": v["created_at"],
            "created_by": v["created_by"],
            "current": bool(v["is_current"]),
        }

    def restore_version(self, object_id: str, user_id: str, version_id: str) -> Optional[dict]:
        """Restore versi lama menjadi versi aktif.

        Sifatnya NON-DESTRUCTIVE (mirip GCS): versi target di-snapshot ulang
        sebagai versi BARU dengan version_id baru, lalu ditandai current.
        Semua riwayat lama tetap utuh. Hanya owner yang boleh me-restore."""
        obj = db.get_object_by_id(object_id)
        if not obj or obj["owner_id"] != user_id:
            self._audit("object.version.restore", actor_id=user_id, resource_id=object_id,
                        result=R_DENIED,
                        details={"reason": "objek tidak ada / bukan pemilik",
                                 "version_id": version_id})
            return None
        v = db.get_object_version(version_id)
        if not v or v["object_id"] != object_id:
            self._audit("object.version.restore", actor_id=user_id, resource_id=object_id,
                        resource_name=obj["filename"], result=R_DENIED,
                        details={"reason": "versi tidak ditemukan", "version_id": version_id})
            return None
        created_at = datetime.now(timezone.utc).isoformat()
        new_no = db.next_version_number(object_id)
        new_vid = generate_version_id()

        record = {
            "id": object_id,
            "owner": obj["owner_id"],
            "filename": v["filename"],
            "mime_type": v["mime_type"],
            "encrypted_payload": v["encrypted_payload"],
            "nonce": v["nonce"],
            "created_at": created_at,
            "bucket_id": obj["bucket_id"] if "bucket_id" in obj.keys() else None,
            "version": new_no,
            "restored_from": version_id,
            "deleted": False
        }
        line = self.storage.append_record(record)

        ok = db.create_object_version(
            version_id=new_vid,
            object_id=object_id,
            version=new_no,
            filename=v["filename"],
            mime_type=v["mime_type"],
            size=v["size"],
            encrypted_payload=v["encrypted_payload"],
            nonce=v["nonce"],
            created_at=created_at,
            created_by=user_id,
            storage_line=line,
        )
        if not ok:
            self._audit("object.version.restore", actor_id=user_id, resource_id=object_id,
                        resource_name=obj["filename"], result=R_FAILED,
                        details={"reason": "gagal membuat versi restore",
                                 "version_id": version_id})
            return None
        # Versi restored menjadi current; baris objects mengikuti versi current
        db.set_current_version(object_id, new_vid)
        db.update_object_payload(
            obj_id=object_id,
            encrypted_payload=v["encrypted_payload"],
            nonce=v["nonce"],
            size=v["size"],
            mime_type=v["mime_type"],
            updated_at=created_at,
            storage_line=line,
        )
        self._audit("object.version.restore", actor_id=user_id, resource_id=object_id,
                    resource_name=obj["filename"],
                    details={"restored_from": version_id, "new_version": new_no,
                             "new_version_id": new_vid})
        return {
            "id": object_id,
            "version": new_no,
            "version_id": new_vid,
            "restored_from": version_id,
            "created_at": created_at,
        }

    # ==================== BUCKET MANAGEMENT ====================
    def _audit_bucket(self, action, *, actor_id=None, resource_id=None,
                      resource_name=None, details=None, result=R_SUCCESS):
        """Catat aksi bucket ke audit log (best-effort)."""
        try:
            audit_logger.record(action, RT_BUCKET, actor_id=actor_id,
                                actor_username=self._username(actor_id),
                                resource_id=resource_id, resource_name=resource_name,
                                details=details, result=result)
        except Exception:
            pass

    def create_bucket(self, owner_id: str, name: str) -> Optional[dict]:
        """Buat bucket baru untuk user. Mengembalikan metadata bucket atau None jika gagal."""
        bucket_id = generate_bucket_id()
        created_at = datetime.now(timezone.utc).isoformat()
        success = db.create_bucket(bucket_id, name, owner_id, created_at)
        if not success:
            self._audit_bucket("bucket.create", actor_id=owner_id, resource_name=name,
                               result=R_FAILED, details={"reason": "nama sudah ada / gagal"})
            return None  # nama sudah ada
        self._audit_bucket("bucket.create", actor_id=owner_id, resource_id=bucket_id,
                           resource_name=name)
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
            self._audit_bucket("bucket.delete", actor_id=owner_id, resource_id=bucket_id,
                               resource_name=bucket["name"] if bucket else None,
                               result=R_DENIED, details={"reason": "tidak ada / bukan pemilik"})
            return False
        # Delegasikan ke db.delete_bucket yang akan mengecek kekosongan
        ok = db.delete_bucket(bucket_id, owner_id)
        self._audit_bucket("bucket.delete", actor_id=owner_id, resource_id=bucket_id,
                           resource_name=bucket["name"],
                           result=R_SUCCESS if ok else R_FAILED,
                           details=None if ok else {"reason": "bucket masih berisi objek"})
        return ok

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
            "version": obj["version"] if "version" in obj.keys() else 1,
            "version_id": obj["current_version_id"] if "current_version_id" in obj.keys() else None,
            "bucket_id": obj["bucket_id"],
            "bucket_name": bucket["name"]
        }
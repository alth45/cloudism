"""Audit log CloudSim — catatan aksi "siapa, apa, kapan".

Setiap aksi penting (login/register, upload, download, share/revoke,
trash/restore/purge, create/delete bucket) dicatat sebagai entri append-only
di tabel SQLite `audit_log`, plus salinan immutable di storage.txt
(baris JSON {"audit": {...}}) agar jejak tetap ada meski DB di-reset.

Kebijakan desain:
- Pencatatan bersifat BEST-EFFORT: kegagalan menulis log tidak boleh
  menggagalkan operasi utama (prinsip non-intrusive auditing).
- Entri TIDAK pernah diubah/dihapus lewat API (append-only).
- Aksi 'denied' juga dicatat (mis. login gagal, akses download ditolak),
  karena justru itu yang paling sering dicari saat mengaudit keamanan.
"""
import json
from datetime import datetime, timezone
from typing import Optional

from cloudsim.core.id_generator import generate_log_id
from cloudsim.db.database import db

# resource_type baku
RT_AUTH = "auth"
RT_OBJECT = "object"
RT_BUCKET = "bucket"

# result baku
R_SUCCESS = "success"
R_DENIED = "denied"
R_FAILED = "failed"


class AuditLogger:
    """Fasad pencatatan & pembacaan audit log."""

    def __init__(self, storage_manager=None):
        # Import lokal agar modul audit bisa dipakai tanpa menarik siklus impor
        self._storage_manager = storage_manager

    @property
    def storage(self):
        if self._storage_manager is None:
            from cloudsim.storage.storage_manager import StorageManager
            self._storage_manager = StorageManager()
        return self._storage_manager

    # ==================== WRITE ====================
    def record(self, action: str, resource_type: str, *,
               actor_id: Optional[str] = None,
               actor_username: Optional[str] = None,
               resource_id: Optional[str] = None,
               resource_name: Optional[str] = None,
               details: Optional[dict] = None,
               result: str = R_SUCCESS,
               source: Optional[str] = None) -> Optional[dict]:
        """Catat satu aksi. Mengembalikan dict entri (atau None jika gagal).

        `details` berupa dict kecil berisi konteks tambahan (nomor versi,
        permission, jumlah objek ter-purge, dsb) — JANGAN pernah berisi
        payload/rahasia user."""
        timestamp = datetime.now(timezone.utc).isoformat()
        entry = {
            "id": generate_log_id(),
            "timestamp": timestamp,
            "actor_id": actor_id,
            "actor_username": actor_username,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "resource_name": resource_name,
            "details": details or {},
            "result": result,
            "source": source,
        }
        details_json = json.dumps(entry["details"], default=str)
        try:
            db.insert_audit_log(
                log_id=entry["id"], timestamp=timestamp, action=action,
                resource_type=resource_type, actor_id=actor_id,
                actor_username=actor_username, resource_id=resource_id,
                resource_name=resource_name, details=details_json,
                result=result, source=source,
            )
        except Exception:
            pass  # best-effort: log DB gagal, tetap coba tulis ke storage
        # Salinan immutable di storage.txt (append-only log)
        try:
            self.storage.append_record({"audit": entry})
        except Exception:
            pass
        return entry

    # ==================== READ ====================
    def query(self, *, actor_id: Optional[str] = None,
              resource_id: Optional[str] = None,
              action: Optional[str] = None,
              since: Optional[str] = None, until: Optional[str] = None,
              limit: int = 100, offset: int = 0) -> dict:
        """Ambil entri audit log (terbaru dulu) dengan filter opsional.

        `action` dicocokkan sebagai awalan (prefix), mis. 'object.' atau
        'object.share'. Mengembalikan {items, count, total, limit, offset}."""
        rows = db.list_audit_logs(actor_id=actor_id, resource_id=resource_id,
                                  action=action, since=since, until=until,
                                  limit=limit, offset=offset)
        items = [self._row_to_dict(r) for r in rows]
        total = db.count_audit_logs(actor_id=actor_id, resource_id=resource_id,
                                    action=action, since=since, until=until)
        return {"items": items, "count": len(items),
                "total": total, "limit": limit, "offset": offset}

    def history_for_object(self, object_id: str, limit: int = 100) -> list[dict]:
        """Riwayat aksi pada satu objek saja (dipakai endpoint /objects/{id}/audit)."""
        return self.query(resource_id=object_id, limit=limit)["items"]

    @staticmethod
    def _row_to_dict(row) -> dict:
        try:
            details = json.loads(row["details"]) if row["details"] else {}
        except (ValueError, TypeError):
            details = {"raw": row["details"]}
        return {
            "id": row["id"],
            "timestamp": row["timestamp"],
            "actor_id": row["actor_id"],
            "actor_username": row["actor_username"],
            "action": row["action"],
            "resource_type": row["resource_type"],
            "resource_id": row["resource_id"],
            "resource_name": row["resource_name"],
            "details": details,
            "result": row["result"],
            "source": row["source"],
        }


# Singleton untuk dipakai lintas layer (API/engine) tanpa wiring manual.
audit_logger = AuditLogger()

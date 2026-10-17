# pyrefly: ignore [missing-import]
"""Pengujian fitur Audit Log (catatan aksi siapa, apa, kapan).

Mencakup:
- Instrumentasi autentikasi (register/login sukses & gagal, logout).
- Instrumentasi engine (upload/download/share/trash/bucket) lewat API.
- Endpoint REST /audit, /audit/mine, /audit/objects/{id}/audit + kebijakan
  akses (admin vs user biasa).
- Penulisan salinan immutable {"audit": ...} ke storage.txt.
"""
import json

import pytest

from cloudsim.core.audit import audit_logger
from tests.test_e2e import (
    register_and_get_key, login_and_get_key, auth_header, encrypt_file,
)


def _actions(db, actor_id=None):
    """Kumpulan nama aksi di DB (opsional per aktor)."""
    rows = db.list_audit_logs(actor_id=actor_id, limit=1000)
    return [r["action"] for r in rows]


class TestAuthAudit:
    def test_register_login_logged(self, client, test_db):
        token, uid, key = register_and_get_key(client, "alice", "pass-a")
        actions = _actions(test_db)
        assert "auth.register" in actions
        entry = next(r for r in test_db.list_audit_logs(limit=1000)
                     if r["action"] == "auth.register")
        assert entry["actor_id"] == uid
        assert entry["actor_username"] == "alice"
        assert entry["result"] == "success"
        assert entry["resource_type"] == "auth"
        assert entry["timestamp"]  # "kapan" selalu terisi

        login_and_get_key(client, "alice", "pass-a")
        assert "auth.login" in _actions(test_db, actor_id=uid)

    def test_failed_login_denied(self, client, test_db):
        register_and_get_key(client, "bob", "pass-b")
        resp = client.post("/auth/login", json={"username": "bob", "password": "salah"})
        assert resp.status_code == 401
        rows = [r for r in test_db.list_audit_logs(limit=1000)
                if r["action"] == "auth.login"]
        denied = [r for r in rows if r["result"] == "denied"]
        assert denied, "login gagal harus dicatat sebagai 'denied'"
        assert denied[0]["details"] and "bad_password" in denied[0]["details"]

    def test_unknown_user_login_denied(self, client, test_db):
        resp = client.post("/auth/login", json={"username": "hantu", "password": "x"})
        assert resp.status_code == 401
        rows = [r for r in test_db.list_audit_logs(limit=1000)
                if r["action"] == "auth.login" and r["result"] == "denied"]
        assert rows and rows[0]["actor_username"] == "hantu"

    def test_duplicate_register_failed(self, client, test_db):
        register_and_get_key(client, "eve", "pass-e")
        resp = client.post("/auth/register", json={"username": "eve", "password": "lain"})
        assert resp.status_code == 400
        rows = [r for r in test_db.list_audit_logs(limit=1000)
                if r["action"] == "auth.register" and r["result"] == "failed"]
        assert rows

    def test_logout_endpoint(self, client, test_db):
        token, uid, _ = register_and_get_key(client, "carol", "pass-c")
        resp = client.post("/auth/logout", headers=auth_header(token))
        assert resp.status_code == 200
        rows = [r for r in test_db.list_audit_logs(limit=1000)
                if r["action"] == "auth.logout"]
        assert rows and rows[0]["actor_id"] == uid


class TestObjectAudit:
    def _upload(self, client, token, key, filename="laporan.txt"):
        enc_b64, nonce_b64 = encrypt_file(b"isinya rahasia", key)
        resp = client.post("/objects/upload", json={
            "encrypted_payload": enc_b64, "nonce": nonce_b64,
            "filename": filename, "mime_type": "text/plain",
        }, headers=auth_header(token))
        assert resp.status_code == 200
        return resp.json()["id"]

    def test_upload_download_share_trash_logged(self, client, test_db):
        t1, uid1, k1 = register_and_get_key(client, "owner", "p1")
        t2, uid2, k2 = register_and_get_key(client, "guest", "p2")
        obj_id = self._upload(client, t1, k1)

        assert "object.upload.new" in _actions(test_db, actor_id=uid1)

        client.get(f"/objects/{obj_id}/download", headers=auth_header(t1))
        assert "object.download" in _actions(test_db, actor_id=uid1)

        client.post(f"/objects/{obj_id}/share",
                    json={"username": "guest", "permission": "read"},
                    headers=auth_header(t1))
        assert "object.share" in _actions(test_db, actor_id=uid1)

        client.delete(f"/objects/{obj_id}", headers=auth_header(t1))
        assert "object.trash" in _actions(test_db, actor_id=uid1)

    def test_denied_download_logged(self, client, test_db):
        t1, _, k1 = register_and_get_key(client, "owner2", "p1")
        t2, uid2, _ = register_and_get_key(client, "outsider", "p2")
        obj_id = self._upload(client, t1, k1)

        resp = client.get(f"/objects/{obj_id}/download", headers=auth_header(t2))
        assert resp.status_code == 404  # akses ditolak disamarkan sebagai 404
        rows = [r for r in test_db.list_audit_logs(actor_id=uid2, limit=1000)
                if r["action"] == "object.download"]
        assert rows and rows[0]["result"] == "denied"
        assert rows[0]["resource_id"] == obj_id

    def test_bucket_actions_logged(self, client, test_db):
        t1, uid1, _ = register_and_get_key(client, "bucketman", "p1")
        resp = client.post("/buckets", json={"name": "data-saya"},
                           headers=auth_header(t1))
        assert resp.status_code == 200, resp.text
        bucket_id = resp.json()["id"]
        assert "bucket.create" in _actions(test_db, actor_id=uid1)

        resp = client.delete(f"/buckets/{bucket_id}", headers=auth_header(t1))
        assert resp.status_code == 200
        assert "bucket.delete" in _actions(test_db, actor_id=uid1)


class TestAuditEndpoints:
    def _make_entry(self):
        return audit_logger.record("object.test.probe", "object",
                                   actor_id="u-x", actor_username="x",
                                   resource_id="obj-x", resource_name="x.txt")

    def test_requires_auth(self, client):
        assert client.get("/audit").status_code in (401, 403)
        assert client.get("/audit/mine").status_code in (401, 403)

    def test_mine_only_own_entries(self, client, test_db):
        t1, uid1, _ = register_and_get_key(client, "user1", "p1")
        t2, uid2, _ = register_and_get_key(client, "user2", "p2")
        audit_logger.record("auth.probe", "auth", actor_id=uid1, actor_username="user1")
        audit_logger.record("auth.probe", "auth", actor_id=uid2, actor_username="user2")

        resp = client.get("/audit/mine", params={"action": "auth.probe"},
                          headers=auth_header(t1))
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 1 and items[0]["actor_id"] == uid1

    def test_nonadmin_cannot_query_other_actor(self, client, test_db):
        t1, uid1, _ = register_and_get_key(client, "peeker", "p1")
        t2, uid2, _ = register_and_get_key(client, "victim", "p2")
        resp = client.get("/audit", params={"actor_id": uid2},
                          headers=auth_header(t1))
        assert resp.status_code == 403

    def test_filter_action_prefix_and_pagination(self, client, test_db):
        t1, uid1, _ = register_and_get_key(client, "pager", "p1")
        for i in range(5):
            audit_logger.record(f"object.probe{i}", "object",
                                actor_id=uid1, actor_username="pager")
        resp = client.get("/audit", params={"action": "object.probe", "limit": 2},
                          headers=auth_header(t1))
        data = resp.json()
        assert data["count"] == 2 and data["total"] == 5
        resp2 = client.get("/audit", params={"action": "object.probe",
                                             "limit": 2, "offset": 4},
                           headers=auth_header(t1))
        assert resp2.json()["count"] == 1

    def test_object_history_access(self, client, test_db):
        t1, uid1, k1 = register_and_get_key(client, "hist-owner", "p1")
        t3, _, _ = register_and_get_key(client, "hist-stranger", "p3")
        enc_b64, nonce_b64 = encrypt_file(b"data", k1)
        resp = client.post("/objects/upload", json={
            "encrypted_payload": enc_b64, "nonce": nonce_b64,
            "filename": "h.txt", "mime_type": "text/plain",
        }, headers=auth_header(t1))
        obj_id = resp.json()["id"]

        resp = client.get(f"/audit/objects/{obj_id}/audit", headers=auth_header(t1))
        assert resp.status_code == 200
        assert any(i["action"].startswith("object.upload")
                   for i in resp.json()["items"])

        resp = client.get(f"/audit/objects/{obj_id}/audit", headers=auth_header(t3))
        assert resp.status_code == 403

        resp = client.get("/audit/objects/obj-tidakada/audit", headers=auth_header(t1))
        assert resp.status_code == 404


class TestAuditStorageMirror:
    def test_immutable_copy_in_storage(self, tmp_path):
        """Salinan entri audit ditulis sebagai baris {"audit": ...} ke storage."""
        from cloudsim.core.audit import AuditLogger
        from cloudsim.storage.storage_manager import StorageManager

        sm = StorageManager(str(tmp_path / "storage.txt"))
        logger = AuditLogger(storage_manager=sm)
        entry = logger.record("auth.login", "auth", actor_username="mirror",
                              result="success")
        records = sm.get_all_records()
        audit_rows = [r for r in records if "audit" in r]
        assert len(audit_rows) == 1
        assert audit_rows[0]["audit"]["id"] == entry["id"]
        assert audit_rows[0]["audit"]["action"] == "auth.login"

    def test_best_effort_never_raises(self, tmp_path, monkeypatch):
        """Kegagalan DB/storage tidak boleh menggagalkan operasi pencatatan."""
        from cloudsim.core.audit import AuditLogger
        from cloudsim.storage.storage_manager import StorageManager

        sm = StorageManager(str(tmp_path / "storage.txt"))
        logger = AuditLogger(storage_manager=sm)
        monkeypatch.setattr("cloudsim.core.audit.db.insert_audit_log",
                            lambda **kw: (_ for _ in ()).throw(RuntimeError("DB mati")))
        entry = logger.record("object.probe", "object")
        assert entry is not None and entry["action"] == "object.probe"

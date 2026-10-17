# pyrefly: ignore [missing-import]
"""Uji fitur Soft Delete & Trash dengan retensi waktu:
- DELETE default = soft delete (status 'trashed', trashed_at, purge_after),
- objek trash hilang dari list/download/versi, tapi barisnya tetap ada di DB,
- restore mengaktifkan kembali,
- purge & empty-trash menghapus permanen,
- auto-purge saat lewat retensi (retensi diatur via env CLOUDSIM_TRASH_RETENTION_DAYS).
"""
import importlib

from tests.test_e2e import register_and_get_key, auth_header, encrypt_file


def _upload(client, token, key, content=b"x", filename="a.txt", extra=None):
    enc_b64, nonce_b64 = encrypt_file(content, key)
    body = {"encrypted_payload": enc_b64, "nonce": nonce_b64,
            "filename": filename, "mime_type": "text/plain"}
    if extra:
        body.update(extra)
    resp = client.post("/objects/upload", json=body, headers=auth_header(token))
    assert resp.status_code == 200, resp.text
    return resp.json()


class TestSoftDeleteTrash:

    def test_delete_default_is_soft_delete(self, client, test_db):
        token, uid, key = register_and_get_key(client, "ardi", "passA123")
        obj = _upload(client, token, key, b"rahasia", "rahasia.txt")

        resp = client.delete(f"/objects/{obj['id']}", headers=auth_header(token))
        assert resp.status_code == 200
        body = resp.json()
        assert body["mode"] == "trash"
        assert body["purge_after"] > body["trashed_at"]

        # Baris objects TETAP ADA di DB dengan status 'trashed' (soft delete)
        row = test_db.get_object_by_id(obj["id"])
        assert row is not None and row["status"] == "trashed"
        assert row["trashed_at"] and row["purge_after"]

        # Tidak muncul di list, dan tidak bisa didownload / dilihat versinya
        listed = client.get("/objects/", headers=auth_header(token)).json()
        assert all(o["id"] != obj["id"] for o in listed)
        assert client.get(f"/objects/{obj['id']}/download",
                          headers=auth_header(token)).status_code == 404
        assert client.get(f"/objects/{obj['id']}/versions",
                          headers=auth_header(token)).status_code == 404

        # Muncul di trash dengan sisa retensi ~30 hari (default)
        trash = client.get("/objects/trash", headers=auth_header(token)).json()
        assert trash["count"] == 1 and trash["retention_days"] == 30
        item = trash["items"][0]
        assert item["id"] == obj["id"] and item["filename"] == "rahasia.txt"
        assert 29.0 < item["days_remaining"] <= 30.0

    def test_restore_from_trash(self, client, test_db):
        token, uid, key = register_and_get_key(client, "ardi", "passA123")
        obj = _upload(client, token, key, b"isi", "f1.txt")
        client.delete(f"/objects/{obj['id']}", headers=auth_header(token))

        resp = client.post(f"/objects/{obj['id']}/restore", headers=auth_header(token))
        assert resp.status_code == 200

        row = test_db.get_object_by_id(obj["id"])
        assert row["status"] == "active"
        assert row["trashed_at"] is None and row["purge_after"] is None

        listed = client.get("/objects/", headers=auth_header(token)).json()
        assert any(o["id"] == obj["id"] for o in listed)
        trash = client.get("/objects/trash", headers=auth_header(token)).json()
        assert trash["count"] == 0

    def test_purge_single_and_empty_trash(self, client, test_db):
        token, uid, key = register_and_get_key(client, "ardi", "passA123")
        o1 = _upload(client, token, key, b"1", "one.txt")
        o2 = _upload(client, token, key, b"2", "two.txt")
        o3 = _upload(client, token, key, b"3", "three.txt")
        for o in (o1, o2, o3):
            client.delete(f"/objects/{o['id']}", headers=auth_header(token))

        # Purge satu objek -> barisnya hilang permanen dari DB
        resp = client.delete(f"/objects/{o1['id']}/purge", headers=auth_header(token))
        assert resp.status_code == 200
        assert test_db.get_object_by_id(o1["id"]) is None

        # Purge objek yang TIDAK di trash ditolak
        fresh = _upload(client, token, key, b"baru", "fresh.txt")
        assert client.delete(f"/objects/{fresh['id']}/purge",
                             headers=auth_header(token)).status_code == 404

        # Empty trash -> sisanya ikut terhapus permanen
        resp = client.delete("/objects/trash/empty", headers=auth_header(token))
        assert resp.status_code == 200
        assert resp.json()["purged"] == 2  # o2 & o3
        assert test_db.get_object_by_id(o2["id"]) is None
        assert test_db.get_object_by_id(o3["id"]) is None
        # yang masih active tidak tersentuh
        assert test_db.get_object_by_id(fresh["id"]) is not None

    def test_permanent_delete_skips_trash(self, client, test_db):
        token, uid, key = register_and_get_key(client, "ardi", "passA123")
        obj = _upload(client, token, key, b"x", "p.txt")
        resp = client.delete(f"/objects/{obj['id']}?permanent=true",
                             headers=auth_header(token))
        assert resp.status_code == 200 and resp.json()["mode"] == "permanent"
        assert test_db.get_object_by_id(obj["id"]) is None
        trash = client.get("/objects/trash", headers=auth_header(token)).json()
        assert trash["count"] == 0

    def test_retention_expiry_auto_purge(self, client, test_db, monkeypatch):
        """Dengan retensi negatif, objek langsung kedaluwarsa dan di-purge otomatis."""
        db_mod = importlib.import_module("cloudsim.db.database")
        monkeypatch.setenv("CLOUDSIM_TRASH_RETENTION_DAYS", "-1")
        # get_trash_retention_days menolak nilai <= 0 dan jatuh ke default;
        # untuk uji expiry kita manipulasi purge_after langsung menjadi masa lalu.
        token, uid, key = register_and_get_key(client, "ardi", "passA123")
        obj = _upload(client, token, key, b"x", "exp.txt")
        client.delete(f"/objects/{obj['id']}", headers=auth_header(token))
        test_db.conn.execute(
            "UPDATE objects SET purge_after = '2000-01-01T00:00:00+00:00' WHERE id = ?",
            (obj["id"],))
        test_db.conn.commit()

        resp = client.get("/objects/trash", headers=auth_header(token))
        assert resp.status_code == 200
        body = resp.json()
        assert body["auto_purged"] == 1
        assert body["count"] == 0
        assert test_db.get_object_by_id(obj["id"]) is None

    def test_reupload_after_trash_creates_new_object(self, client, test_db):
        """Objek di trash tidak boleh ditimpa oleh upload nama sama."""
        token, uid, key = register_and_get_key(client, "ardi", "passA123")
        o1 = _upload(client, token, key, b"lama", "same.txt")
        client.delete(f"/objects/{o1['id']}", headers=auth_header(token))
        o2 = _upload(client, token, key, b"baru", "same.txt")
        assert o2["id"] != o1["id"] and o2["version"] == 1
        # versi lama masih aman di trash
        trash = client.get("/objects/trash", headers=auth_header(token)).json()
        assert trash["count"] == 1 and trash["items"][0]["id"] == o1["id"]

    def test_non_owner_cannot_trash_or_restore(self, client):
        token1, _, key1 = register_and_get_key(client, "ardi", "passA123")
        token2, _, _ = register_and_get_key(client, "budi", "passB123")
        obj = _upload(client, token1, key1, b"x", "priv.txt")
        # Budi bukan pemilik: tidak bisa tras / restore / purge
        assert client.delete(f"/objects/{obj['id']}",
                             headers=auth_header(token2)).status_code == 404
        client.delete(f"/objects/{obj['id']}", headers=auth_header(token1))
        assert client.post(f"/objects/{obj['id']}/restore",
                           headers=auth_header(token2)).status_code == 404
        assert client.delete(f"/objects/{obj['id']}/purge",
                             headers=auth_header(token2)).status_code == 404

    def test_bucket_not_deletable_while_trash_holds_objects(self, client):
        """Bucket dianggap masih berisi selama ada objeknya di trash."""
        token, uid, key = register_and_get_key(client, "ardi", "passA123")
        bucket = client.post("/buckets", json={"name": "bk-trash"},
                             headers=auth_header(token)).json()
        obj = _upload(client, token, key, b"x", "d.txt",
                      extra={"bucket_id": bucket["id"]})
        client.delete(f"/objects/{obj['id']}", headers=auth_header(token))
        # bucket belum boleh dihapus (isi trash dihitung)
        assert client.delete(f"/buckets/{bucket['id']}",
                             headers=auth_header(token)).status_code == 400
        # setelah purge permanen, bucket bisa dihapus
        assert client.delete(f"/objects/{obj['id']}/purge",
                             headers=auth_header(token)).status_code == 200
        assert client.delete(f"/buckets/{bucket['id']}",
                             headers=auth_header(token)).status_code == 200

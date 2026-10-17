# pyrefly: ignore [missing-import]
"""Uji fitur Versioning nyata per objek:
- flag version_id pada metadata,
- auto-versioning saat upload ulang nama+bucket yang sama,
- daftar versi & download versi tertentu (immutable),
- restore versi lama secara non-destructive.
"""
from tests.test_e2e import register_and_get_key, auth_header, encrypt_file, decrypt_file


class TestObjectVersioning:

    def _upload(self, client, token, key, content: bytes, filename="doc.txt", extra=None):
        enc_b64, nonce_b64 = encrypt_file(content, key)
        body = {"encrypted_payload": enc_b64, "nonce": nonce_b64,
                "filename": filename, "mime_type": "text/plain"}
        if extra:
            body.update(extra)
        resp = client.post("/objects/upload", json=body, headers=auth_header(token))
        assert resp.status_code == 200, resp.text
        return resp.json()

    def test_reupload_creates_new_version_with_version_id_flag(self, client):
        token, uid, key = register_and_get_key(client, "ardi", "passA123")

        v1 = self._upload(client, token, key, b"isi versi satu")
        assert v1["version"] == 1
        assert v1["version_id"].startswith("ver-")

        # Upload ulang nama sama (tanpa bucket) => objek SAMA, versi BARU
        v2 = self._upload(client, token, key, b"isi versi dua yang lebih panjang")
        assert v2["id"] == v1["id"]
        assert v2["version"] == 2
        assert v2["version_id"] != v1["version_id"]

        # Nama berbeda => objek baru, tetap versi 1
        other = self._upload(client, token, key, b"lain", filename="lain.txt")
        assert other["id"] != v1["id"] and other["version"] == 1

        # List hanya menampilkan 2 objek dengan versi current masing-masing
        objs = client.get("/objects/", headers=auth_header(token)).json()
        by_id = {o["id"]: o for o in objs}
        assert by_id[v1["id"]]["version"] == 2
        assert by_id[v1["id"]]["version_id"] == v2["version_id"]

        # Info objek menampilkan flag version_id + versi current
        meta = client.get(f"/objects/{v1['id']}", headers=auth_header(token)).json()
        assert meta["version"] == 2 and meta["version_id"] == v2["version_id"]

    def test_versions_listing_and_download_specific_version(self, client):
        token, uid, key = register_and_get_key(client, "budi", "passB123")
        c1, c2 = b"konten pertama", b"konten kedua!"
        v1 = self._upload(client, token, key, c1)
        v2 = self._upload(client, token, key, c2)

        rows = client.get(f"/objects/{v1['id']}/versions", headers=auth_header(token)).json()
        assert len(rows) == 2
        # terbaru dulu
        assert rows[0]["version"] == 2 and rows[0]["current"] is True
        assert rows[1]["version"] == 1 and rows[1]["current"] is False
        assert rows[1]["version_id"] == v1["version_id"]

        # Download default = versi current (v2)
        d = client.get(f"/objects/{v1['id']}/download", headers=auth_header(token)).json()
        assert decrypt_file(d["encrypted_payload"], d["nonce"], key) == c2

        # Download versi lama via ?version_id -> konten v1 utuh (immutable)
        d_old = client.get(f"/objects/{v1['id']}/download?version_id={v1['version_id']}",
                           headers=auth_header(token)).json()
        assert d_old["version_id"] == v1["version_id"]
        assert decrypt_file(d_old["encrypted_payload"], d_old["nonce"], key) == c1

        # Metadata satu versi
        one = client.get(f"/objects/{v1['id']}/versions/{v1['version_id']}",
                         headers=auth_header(token)).json()
        assert one["version"] == 1 and one["size"] == v1["size"]

        # Versi tak dikenal -> 404
        bad = client.get(f"/objects/{v1['id']}/download?version_id=ver-tidakada",
                         headers=auth_header(token))
        assert bad.status_code == 404

    def test_restore_old_version_is_non_destructive(self, client):
        token, uid, key = register_and_get_key(client, "citra", "passC123")
        c1, c2, c3 = b"v1 data", b"v2 data lain", b"v3 data lagi"
        v1 = self._upload(client, token, key, c1)
        v2 = self._upload(client, token, key, c2)
        v3 = self._upload(client, token, key, c3)

        # Restore versi 1 -> menjadi versi 4 (bukan menghapus riwayat)
        r = client.post(f"/objects/{v1['id']}/versions/{v1['version_id']}/restore",
                        headers=auth_header(token))
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["version"] == 4
        assert body["restored_from"] == v1["version_id"]
        new_vid = body["version_id"]
        assert new_vid.startswith("ver-")

        # Versi restored kini current; objek & metadata menunjuk v4
        meta = client.get(f"/objects/{v1['id']}", headers=auth_header(token)).json()
        assert meta["version"] == 4 and meta["version_id"] == new_vid

        # Download default sekarang berisi konten v1 lagi
        d = client.get(f"/objects/{v1['id']}/download", headers=auth_header(token)).json()
        assert decrypt_file(d["encrypted_payload"], d["nonce"], key) == c1

        # Riwayat lengkap: 4 versi, hanya satu current
        rows = client.get(f"/objects/{v1['id']}/versions", headers=auth_header(token)).json()
        assert [x["version"] for x in rows] == [4, 3, 2, 1]
        assert sum(1 for x in rows if x["current"]) == 1
        # v3 lama tetap bisa diunduh
        d3 = client.get(f"/objects/{v1['id']}/download?version_id={v3['version_id']}",
                        headers=auth_header(token)).json()
        assert decrypt_file(d3["encrypted_payload"], d3["nonce"], key) == c3

    def test_restore_requires_owner(self, client):
        t1, _, k1 = register_and_get_key(client, "ardi", "passA123")
        t2, _, _ = register_and_get_key(client, "budi", "passB123")
        v1 = self._upload(client, t1, k1, b"satu")
        v2 = self._upload(client, t1, k1, b"dua")

        # Budi (bukan owner) tidak boleh me-restore
        resp = client.post(f"/objects/{v1['id']}/versions/{v1['version_id']}/restore",
                           headers=auth_header(t2))
        assert resp.status_code in (403, 404)

        # Setelah dibagikan read pun, tetap bukan owner -> ditolak
        client.post(f"/objects/{v1['id']}/share", json={"username": "budi", "permission": "read"},
                    headers=auth_header(t1))
        resp = client.post(f"/objects/{v1['id']}/versions/{v1['version_id']}/restore",
                           headers=auth_header(t2))
        assert resp.status_code == 403

        # Budi bisa melihat daftar versi & mengunduh versi lama (read-only)
        rows = client.get(f"/objects/{v1['id']}/versions", headers=auth_header(t2)).json()
        assert len(rows) == 2

    def test_bucket_scoped_versioning(self, client):
        """Versi dihitung per (owner, filename, bucket): bucket beda = objek baru."""
        token, uid, key = register_and_get_key(client, "dwi", "passD123")
        b1 = client.post("/buckets", json={"name": "bk-satu"}, headers=auth_header(token)).json()
        b2 = client.post("/buckets", json={"name": "bk-dua"}, headers=auth_header(token)).json()

        o1 = self._upload(client, token, key, b"A", extra={"bucket_id": b1["id"]})
        o1b = self._upload(client, token, key, b"A2", extra={"bucket_id": b1["id"]})
        assert o1b["id"] == o1["id"] and o1b["version"] == 2

        o2 = self._upload(client, token, key, b"B", extra={"bucket_id": b2["id"]})
        assert o2["id"] != o1["id"] and o2["version"] == 1

    def test_delete_object_removes_all_versions(self, client):
        token, uid, key = register_and_get_key(client, "evi", "passE123")
        v1 = self._upload(client, token, key, b"x")
        self._upload(client, token, key, b"y")
        assert client.delete(f"/objects/{v1['id']}", headers=auth_header(token)).status_code == 200
        # Semua versi ikut hilang (ON DELETE CASCADE)
        resp = client.get(f"/objects/{v1['id']}/versions", headers=auth_header(token))
        assert resp.status_code == 404

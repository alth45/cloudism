# pyrefly: ignore [missing-import]
import pytest
import base64
from cloudsim.crypto.aes_custom import AES256CTR
from cloudsim.crypto.key_derivation import pbkdf2_sha256

def register_and_get_key(client, username, password):
    """Helper: registrasi user dan kembalikan (token, user_id, encryption_key)."""
    resp = client.post("/auth/register", json={"username": username, "password": password})
    assert resp.status_code == 200, f"Register gagal: {resp.text}"
    data = resp.json()
    # Derive kunci enkripsi dari password + key_salt
    key_salt = bytes.fromhex(data["key_salt"])
    encryption_key = pbkdf2_sha256(password, key_salt, iterations=100000, dklen=32)
    return data["token"], data["user_id"], encryption_key

def login_and_get_key(client, username, password):
    """Helper: login dan kembalikan (token, user_id, encryption_key)."""
    resp = client.post("/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, f"Login gagal: {resp.text}"
    data = resp.json()
    key_salt = bytes.fromhex(data["key_salt"])
    encryption_key = pbkdf2_sha256(password, key_salt, iterations=100000, dklen=32)
    return data["token"], data["user_id"], encryption_key

def auth_header(token):
    return {"Authorization": f"Bearer {token}"}

def encrypt_file(plaintext: bytes, key: bytes):
    """Enkripsi file dengan AES-256-CTR, kembalikan (encrypted_b64, nonce_b64)."""
    cipher = AES256CTR(key)
    encrypted, nonce = cipher.encrypt(plaintext)
    return base64.b64encode(encrypted).decode(), base64.b64encode(nonce).decode()

def decrypt_file(encrypted_b64: str, nonce_b64: str, key: bytes):
    cipher = AES256CTR(key)
    encrypted = base64.b64decode(encrypted_b64)
    nonce = base64.b64decode(nonce_b64)
    return cipher.decrypt(encrypted, nonce)

class TestCloudSimE2E:
    def test_full_flow(self, client):
        # 1. Register dua pengguna
        token1, uid1, key1 = register_and_get_key(client, "ardi", "pass123")
        token2, uid2, key2 = register_and_get_key(client, "budi", "pass456")

        # 2. Upload file oleh ardi
        plaintext = b"Hello CloudSim!"
        enc_b64, nonce_b64 = encrypt_file(plaintext, key1)
        resp = client.post(
            "/objects/upload",
            json={
                "encrypted_payload": enc_b64,
                "nonce": nonce_b64,
                "filename": "test.txt",
                "mime_type": "text/plain"
            },
            headers=auth_header(token1)
        )
        assert resp.status_code == 200
        obj_id = resp.json()["id"]
        assert obj_id.startswith("obj-")

        # 3. List objek oleh ardi, harus muncul 1
        resp = client.get("/objects/", headers=auth_header(token1))
        assert resp.status_code == 200
        objects = resp.json()
        assert len(objects) == 1
        assert objects[0]["id"] == obj_id

        # 4. Download oleh ardi, lalu dekripsi, harus cocok
        resp = client.get(f"/objects/{obj_id}/download", headers=auth_header(token1))
        assert resp.status_code == 200
        data = resp.json()
        decrypted = decrypt_file(data["encrypted_payload"], data["nonce"], key1)
        assert decrypted == plaintext

        # 5. Budi mencoba download (tanpa share) harus gagal
        resp = client.get(f"/objects/{obj_id}/download", headers=auth_header(token2))
        assert resp.status_code == 404  # akses ditolak

        # 6. Ardi share ke budi dengan izin read
        resp = client.post(
            f"/objects/{obj_id}/share",
            json={"username": "budi", "permission": "read"},
            headers=auth_header(token1)
        )
        assert resp.status_code == 200

        # 7. Budi sekarang bisa lihat metadata & download (tapi dekripsi gagal karena kunci berbeda)
        resp = client.get(f"/objects/{obj_id}/download", headers=auth_header(token2))
        assert resp.status_code == 200
        data = resp.json()
        # Budi coba dekripsi dengan kuncinya sendiri -> harus menghasilkan data berbeda (garbage)
        decrypted_by_budi = decrypt_file(data["encrypted_payload"], data["nonce"], key2)
        assert decrypted_by_budi != plaintext

        # 8. Ardi hapus objek
        resp = client.delete(f"/objects/{obj_id}", headers=auth_header(token1))
        assert resp.status_code == 200

        # 9. List ardi setelah hapus -> kosong
        resp = client.get("/objects/", headers=auth_header(token1))
        assert resp.status_code == 200
        assert len(resp.json()) == 0

        # 10. Budi juga tidak bisa melihat objek lagi
        resp = client.get("/objects/", headers=auth_header(token2))
        assert resp.status_code == 200
        assert len(resp.json()) == 0

# ==================== SKENARIO BUCKET ====================

class TestBucketFlow:
    """Uji alur bucket: mb -> cp (upload) -> ls -> stat -> download -> rm -> rb."""

    def test_full_bucket_lifecycle(self, client):
        token1, uid1, key1 = register_and_get_key(client, "ardi", "passA123")
        plaintext = b"rahasia arsip pribadi"
        enc_b64, nonce_b64 = encrypt_file(plaintext, key1)

        # 1. Buat bucket
        resp = client.post("/buckets", json={"name": "arsip-pribadi"}, headers=auth_header(token1))
        assert resp.status_code == 200, resp.text
        bucket = resp.json()
        assert bucket["id"].startswith("bkt-")
        assert bucket["name"] == "arsip-pribadi"

        # 2. Nama bucket unik global -> duplikat ditolak
        resp = client.post("/buckets", json={"name": "arsip-pribadi"}, headers=auth_header(token1))
        assert resp.status_code == 409

        # 3. List bucket milik user
        resp = client.get("/buckets", headers=auth_header(token1))
        assert resp.status_code == 200
        assert len(resp.json()) == 1
        assert resp.json()[0]["name"] == "arsip-pribadi"

        # 4. Upload objek ke bucket
        resp = client.post(
            "/objects/upload",
            json={
                "encrypted_payload": enc_b64,
                "nonce": nonce_b64,
                "filename": "rahasia.txt",
                "mime_type": "text/plain",
                "bucket_id": bucket["id"],
            },
            headers=auth_header(token1),
        )
        assert resp.status_code == 200, resp.text
        obj_id = resp.json()["id"]
        assert resp.json()["bucket_id"] == bucket["id"]

        # 5. Upload ke bucket milik orang lain harus ditolak
        token2, uid2, key2 = register_and_get_key(client, "budi", "passB123")
        resp = client.post(
            "/objects/upload",
            json={
                "encrypted_payload": enc_b64,
                "nonce": nonce_b64,
                "filename": "nyloncor.txt",
                "bucket_id": bucket["id"],
            },
            headers=auth_header(token2),
        )
        assert resp.status_code == 404

        # 6. List dengan filter bucket_id hanya menampilkan isi bucket
        resp = client.get(f"/objects/?bucket_id={bucket['id']}", headers=auth_header(token1))
        assert resp.status_code == 200
        objs = resp.json()
        assert len(objs) == 1 and objs[0]["id"] == obj_id

        # Tanpa filter tetap menampilkan semua (1 objek)
        resp = client.get("/objects/", headers=auth_header(token1))
        assert len(resp.json()) == 1

        # 7. Info bucket + isi
        resp = client.get(f"/buckets/{bucket['id']}", headers=auth_header(token1))
        assert resp.status_code == 200
        body = resp.json()
        assert body["bucket"]["name"] == "arsip-pribadi"
        assert len(body["objects"]) == 1

        # 8. Resolve gs://bucket/nama-file -> objek
        resp = client.get("/buckets/name/arsip-pribadi/objects/rahasia.txt", headers=auth_header(token1))
        assert resp.status_code == 200
        assert resp.json()["id"] == obj_id
        assert resp.json()["bucket_name"] == "arsip-pribadi"

        # Resolve via ID objek juga berhasil
        resp = client.get(f"/buckets/name/arsip-pribadi/objects/{obj_id}", headers=auth_header(token1))
        assert resp.status_code == 200
        assert resp.json()["id"] == obj_id

        # User lain tidak bisa resolve bucket milik ardi
        resp = client.get("/buckets/name/arsip-pribadi/objects/rahasia.txt", headers=auth_header(token2))
        assert resp.status_code == 404

        # 9. Hapus bucket yang masih berisi objek harus gagal
        resp = client.delete(f"/buckets/{bucket['id']}", headers=auth_header(token1))
        assert resp.status_code == 400

        # 10. Hapus objek dulu, lalu bucket bisa dihapus
        resp = client.delete(f"/objects/{obj_id}", headers=auth_header(token1))
        assert resp.status_code == 200
        resp = client.delete(f"/buckets/{bucket['id']}", headers=auth_header(token1))
        assert resp.status_code == 200

        # Bucket hilang
        resp = client.get("/buckets", headers=auth_header(token1))
        assert resp.json() == []

    def test_object_without_bucket_still_works(self, client):
        """Kompatibilitas mundur: objek tanpa bucket (bucket_id=NULL) tetap berfungsi."""
        token, uid, key = register_and_get_key(client, "citra", "passC123")
        enc_b64, nonce_b64 = encrypt_file(b"hello", key)
        resp = client.post(
            "/objects/upload",
            json={"encrypted_payload": enc_b64, "nonce": nonce_b64, "filename": "a.txt"},
            headers=auth_header(token),
        )
        assert resp.status_code == 200
        assert resp.json()["bucket_id"] is None
        resp = client.get("/objects/", headers=auth_header(token))
        assert len(resp.json()) == 1

    def test_invalid_bucket_names_rejected(self, client):
        token, _, _ = register_and_get_key(client, "dwi", "passD123")
        for bad in ["ab", "Ada-Huruf-Besar", "-awali-strip", "ada spasi"]:
            resp = client.post("/buckets", json={"name": bad}, headers=auth_header(token))
            assert resp.status_code == 422, f"nama '{bad}' seharusnya ditolak"

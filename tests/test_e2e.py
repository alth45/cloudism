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
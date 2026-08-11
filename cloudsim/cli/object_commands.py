"""Perintah terkait manajemen objek cloud."""
import os
# pyrefly: ignore [missing-import]
import typer
import requests
from cloudsim.cli.auth_commands import get_token_and_key, API_BASE
from cloudsim.crypto.aes_custom import AES256CTR
from cloudsim.crypto.utils import encode_base64, decode_base64

app = typer.Typer(help="Manajemen objek")

def _get_headers(token: str):
    return {"Authorization": f"Bearer {token}"}

@app.command("upload")
def upload(filepath: str = typer.Argument(..., help="Path file yang akan diunggah")):
    """Unggah file ke cloud (dienkripsi di sisi client)."""
    token, key = get_token_and_key()
    if not token or not key:
        print("Anda belum login. Silakan login dulu.")
        return
    if not os.path.exists(filepath):
        print(f"File '{filepath}' tidak ditemukan.")
        return

    filename = os.path.basename(filepath)
    with open(filepath, "rb") as f:
        plaintext = f.read()

    # Enkripsi dengan kunci pengguna
    cipher = AES256CTR(key)
    encrypted, nonce = cipher.encrypt(plaintext)

    payload_b64 = encode_base64(encrypted)
    nonce_b64 = encode_base64(nonce)

    req_data = {
        "encrypted_payload": payload_b64,
        "nonce": nonce_b64,
        "filename": filename,
        "mime_type": "application/octet-stream"
    }

    try:
        resp = requests.post(
            f"{API_BASE}/objects/upload",
            json=req_data,
            headers=_get_headers(token)
        )
        if resp.status_code == 200:
            meta = resp.json()
            print(f"Upload berhasil!")
            print(f"  ID        : {meta['id']}")
            print(f"  Nama file : {meta['filename']}")
            print(f"  Ukuran    : {meta['size']} bytes")
            print(f"  Tipe      : {meta['mime_type']}")
            print(f"  Dibuat    : {meta['created_at']}")
        else:
            print(f"Gagal: {resp.json().get('detail', resp.text)}")
    except requests.ConnectionError:
        print(f"Error: Tidak dapat terhubung ke server di {API_BASE}")

@app.command("list")
def list_objects():
    """Tampilkan daftar objek yang bisa diakses."""
    token, _ = get_token_and_key()
    if not token:
        return
    try:
        resp = requests.get(f"{API_BASE}/objects/", headers=_get_headers(token))
        if resp.status_code == 200:
            objects = resp.json()
            if not objects:
                print("Tidak ada objek yang tersedia.")
                return
            print(f"{'ID':<16} {'Nama File':<30} {'Ukuran':>10} {'Tipe':<20} {'Dibuat':<20}")
            print("-" * 100)
            for obj in objects:
                print(f"{obj['id']:<16} {obj['filename']:<30} {obj['size']:>10} {obj['mime_type']:<20} {obj['created_at']:<20}")
        else:
            print(f"Gagal: {resp.json().get('detail', resp.text)}")
    except requests.ConnectionError:
        print(f"Error: Tidak dapat terhubung ke server di {API_BASE}")

@app.command("info")
def info(object_id: str = typer.Argument(..., help="ID objek")):
    """Lihat metadata objek."""
    token, _ = get_token_and_key()
    if not token:
        return
    try:
        resp = requests.get(f"{API_BASE}/objects/{object_id}", headers=_get_headers(token))
        if resp.status_code == 200:
            meta = resp.json()
            print("Metadata Objek:")
            for key, value in meta.items():
                print(f"  {key}: {value}")
        else:
            print(f"Gagal: {resp.json().get('detail', resp.text)}")
    except requests.ConnectionError:
        print(f"Error: Tidak dapat terhubung ke server di {API_BASE}")

@app.command("download")
def download(object_id: str = typer.Argument(..., help="ID objek"),
             output: str = typer.Option(None, "--output", "-o", help="Path file output")):
    """Unduh file dari cloud (didekripsi di sisi client)."""
    token, key = get_token_and_key()
    if not token or not key:
        return
    try:
        # Ambil data terenkripsi dari API
        resp = requests.get(f"{API_BASE}/objects/{object_id}/download", headers=_get_headers(token))
        if resp.status_code != 200:
            print(f"Gagal: {resp.json().get('detail', resp.text)}")
            return
        data = resp.json()
        encrypted = decode_base64(data["encrypted_payload"])
        nonce = decode_base64(data["nonce"])

        # Dekripsi
        cipher = AES256CTR(key)
        plaintext = cipher.decrypt(encrypted, nonce)

        filename = output or data["filename"]
        with open(filename, "wb") as f:
            f.write(plaintext)
        print(f"File berhasil diunduh: {filename}")
    except requests.ConnectionError:
        print(f"Error: Tidak dapat terhubung ke server di {API_BASE}")

@app.command("delete")
def delete(object_id: str = typer.Argument(..., help="ID objek")):
    """Hapus objek dari cloud."""
    token, _ = get_token_and_key()
    if not token:
        return
    try:
        resp = requests.delete(f"{API_BASE}/objects/{object_id}", headers=_get_headers(token))
        if resp.status_code == 200:
            print(resp.json()["detail"])
        else:
            print(f"Gagal: {resp.json().get('detail', resp.text)}")
    except requests.ConnectionError:
        print(f"Error: Tidak dapat terhubung ke server di {API_BASE}")

@app.command("share")
def share(object_id: str = typer.Argument(..., help="ID objek"),
          username: str = typer.Argument(..., help="Username tujuan"),
          permission: str = typer.Option("read", "--perm", "-p", help="Izin: read/write/admin")):
    """Bagikan akses objek ke pengguna lain."""
    token, _ = get_token_and_key()
    if not token:
        return
    try:
        resp = requests.post(
            f"{API_BASE}/objects/{object_id}/share",
            json={"username": username, "permission": permission},
            headers=_get_headers(token)
        )
        if resp.status_code == 200:
            print(resp.json()["detail"])
        else:
            print(f"Gagal: {resp.json().get('detail', resp.text)}")
    except requests.ConnectionError:
        print(f"Error: Tidak dapat terhubung ke server di {API_BASE}")

if __name__ == "__main__":
    app()
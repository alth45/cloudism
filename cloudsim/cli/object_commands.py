"""Perintah terkait manajemen objek cloud."""
import os
# pyrefly: ignore [missing-import]
import typer
import requests
from getpass import getpass
from cloudsim.cli.auth_commands import get_token_and_key, API_BASE, load_session
from cloudsim.crypto.aes_custom import AES256CTR
from cloudsim.crypto.key_wrapping import generate_dek, wrap_key, unwrap_key
from cloudsim.crypto.utils import encode_base64, decode_base64

app = typer.Typer(help="Manajemen objek")

def _get_headers(token: str):
    return {"Authorization": f"Bearer {token}"}


def _session_deks() -> dict:
    """Peta object_id -> DEK (hex) yang diketahui sesi ini (hasil upload/share)."""
    session = load_session() or {}
    return session.get("dek_cache", {}) or {}


def _remember_dek(object_id: str, dek: bytes):
    """Simpan DEK objek ke cache sesi agar bisa di-re-wrap saat sharing."""
    session = load_session()
    if not session:
        return
    cache = session.setdefault("dek_cache", {})
    cache[object_id] = dek.hex()
    # Batasi ukuran cache sederhana
    if len(cache) > 200:
        for k in list(cache.keys())[:-200]:
            cache.pop(k)
    from cloudsim.cli.auth_commands import ensure_config_dir, CONFIG_FILE
    ensure_config_dir()
    import json
    with open(CONFIG_FILE, "w") as f:
        json.dump(session, f)


def _ask_share_passphrase(confirm: bool = False) -> str:
    from getpass import getpass as _gp
    p1 = _gp("Passphrase pembagian (untuk key-wrapping): ")
    if confirm:
        p2 = _gp("Konfirmasi passphrase: ")
        if p1 != p2:
            print("Passphrase tidak cocok.")
            raise typer.Exit(code=1)
    if not p1:
        print("Passphrase tidak boleh kosong.")
        raise typer.Exit(code=1)
    return p1


def _decrypt_with_fallback(data: dict, key: bytes, share_pass: str | None = None) -> tuple[bytes, str]:
    """Dekripsi payload. Kembalikan (plaintext, metode).

    Metode 'dek'  : wrapped key tersedia + passphrase benar -> DEK dipulihkan
                    (alur re-encryption/key-wrapping).
    Metode 'user-key': mode lama, payload dienkripsi dengan kunci user.
    """
    wk = data.get("wrapped_key")
    passphrase = share_pass or os.environ.get("CLOUDSIM_SHARE_PASS")
    if wk and passphrase:
        dek = unwrap_key(wk["wrapped_key"], wk["wrap_nonce"], wk["wrap_salt"],
                         passphrase, iterations=int(wk.get("iterations", 100000)))
        plaintext = AES256CTR(dek).decrypt(
            decode_base64(data["encrypted_payload"]), decode_base64(data["nonce"]))
        return plaintext, "dek"
    plaintext = AES256CTR(key).decrypt(
        decode_base64(data["encrypted_payload"]), decode_base64(data["nonce"]))
    return plaintext, "user-key"

@app.command("upload")
def upload(filepath: str = typer.Argument(..., help="Path file yang akan diunggah"),
           shareable: bool = typer.Option(False, "--shareable",
                                          help="Enkripsi via DEK + key-wrapping agar file bisa dibagikan dan didekripsi penerima (re-encryption)"),
           passphrase: str = typer.Option(None, "--passphrase",
                                          help="Passphrase pembungkus DEK (tanpa opsi ini akan ditanya aman via getpass)")):
    """Unggah file ke cloud (dienkripsi di sisi client).

    Mode default: payload dienkripsi dengan kunci user (mode lama).
    Mode --shareable: payload dienkripsi dengan DEK acak; DEK dibungkus
    (key-wrapping) memakai KEK hasil PBKDF2(passphrase) sehingga nanti bisa
    di-re-encryption saat `share`.
    """
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

    dek_wrapping = None
    dek = None
    if shareable:
        pp = passphrase or _ask_share_passphrase(confirm=True)
        dek = generate_dek()
        cipher = AES256CTR(dek)
        encrypted, nonce = cipher.encrypt(plaintext)
        # Bungkus DEK utk owner (diri sendiri) dg passphrase yg sama
        dek_wrapping = wrap_key(dek, pp)
    else:
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
    if dek_wrapping:
        req_data["dek_wrapping"] = dek_wrapping

    try:
        resp = requests.post(
            f"{API_BASE}/objects/upload",
            json=req_data,
            headers=_get_headers(token)
        )
        if resp.status_code == 200:
            meta = resp.json()
            if dek is not None:
                _remember_dek(meta["id"], dek)
            print(f"Upload berhasil!")
            print(f"  ID        : {meta['id']}")
            print(f"  Nama file : {meta['filename']}")
            print(f"  Ukuran    : {meta['size']} bytes")
            print(f"  Tipe      : {meta['mime_type']}")
            print(f"  Dibuat    : {meta['created_at']}")
            if dek_wrapping:
                print("  Mode      : shareable (DEK di-wrap via PBKDF2/key-wrapping)")
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
             output: str = typer.Option(None, "--output", "-o", help="Path file output"),
             passphrase: str = typer.Option(None, "--passphrase",
                                            help="Passphrase pembagian utk membuka wrapped DEK (re-encryption)"),
             version_id: str = typer.Option(None, "--version-id",
                                            help="Unduh versi tertentu (ver-...); default versi current")):
    """Unduh file dari cloud (didekripsi di sisi client).

    Jika respons server menyertakan wrapped key dan Anda memberi passphrase
    (atau env CLOUDSIM_SHARE_PASS), DEK dipulihkan via PBKDF2+key-unwrapping
    lalu payload didekripsi dengan DEK tersebut.
    """
    token, key = get_token_and_key()
    if not token or not key:
        return
    try:
        # Ambil data terenkripsi dari API
        params = {"version_id": version_id} if version_id else None
        resp = requests.get(f"{API_BASE}/objects/{object_id}/download",
                            headers=_get_headers(token), params=params)
        if resp.status_code != 200:
            print(f"Gagal: {resp.json().get('detail', resp.text)}")
            return
        data = resp.json()

        pp = passphrase
        if data.get("wrapped_key") and not pp and not os.environ.get("CLOUDSIM_SHARE_PASS"):
            pp = _ask_share_passphrase()

        plaintext, method = _decrypt_with_fallback(data, key, share_pass=pp)

        filename = output or data["filename"]
        with open(filename, "wb") as f:
            f.write(plaintext)
        if method == "dek":
            # ingat DEK-nya utk sesi ini (berguna bila kita ikut membagikan ulang)
            dek_hex = None
            wk = data.get("wrapped_key")
            if wk and pp:
                dek = unwrap_key(wk["wrapped_key"], wk["wrap_nonce"], wk["wrap_salt"],
                                 pp, iterations=int(wk.get("iterations", 100000)))
                dek_hex = dek.hex()
            if dek_hex:
                _remember_dek(object_id, bytes.fromhex(dek_hex))
            print(f"File berhasil diunduh: {filename} (dekripsi via re-encryption/key-wrapping)")
        else:
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
          permission: str = typer.Option("read", "--perm", "-p", help="Izin: read/write/admin"),
          passphrase: str = typer.Option(None, "--passphrase",
                                         help="Passphrase pembagian; DEK objek di-re-encrypt (key-wrapping/PBKDF2) utk penerima"),
          no_reencrypt: bool = typer.Option(False, "--no-reencrypt",
                                            help="Mode lama: hanya bagikan ACL, tanpa re-encryption")):
    """Bagikan akses objek ke pengguna lain.

    Secara default melakukan RE-ENCRYPTION: DEK objek dibungkus ulang
    (key-wrapping) memakai KEK hasil PBKDF2(passphrase) milik penerima,
    sehingga penerima dapat mendekripsi isi file. Passphrase harus
    disampaikan ke penerima melalui kanal aman.
    """
    token, _ = get_token_and_key()
    if not token:
        return

    dek_wrapping = None
    if not no_reencrypt:
        dek_hex = _session_deks().get(object_id)
        if not dek_hex:
            print("Objek ini tidak memiliki wrapped DEK yang diketahui sesi ini.")
            print("Upload ulang dengan `upload --shareable` atau gunakan --no-reencrypt.")
            return
        pp = passphrase or _ask_share_passphrase(confirm=True)
        dek = bytes.fromhex(dek_hex)
        # Re-encryption: bungkus ulang DEK utk penerima
        dek_wrapping = wrap_key(dek, pp)

    try:
        body = {"username": username, "permission": permission}
        if dek_wrapping:
            body["dek_wrapping"] = dek_wrapping
        resp = requests.post(
            f"{API_BASE}/objects/{object_id}/share",
            json=body,
            headers=_get_headers(token)
        )
        if resp.status_code == 200:
            print(resp.json()["detail"])
            if dek_wrapping:
                print(f"Sampaikan passphrase pembagian ke {username} lewat kanal aman agar bisa mendekripsi.")
        else:
            print(f"Gagal: {resp.json().get('detail', resp.text)}")
    except requests.ConnectionError:
        print(f"Error: Tidak dapat terhubung ke server di {API_BASE}")


@app.command("revoke")
def revoke(object_id: str = typer.Argument(..., help="ID objek"),
           username: str = typer.Argument(..., help="Username yang dicabut aksesnya")):
    """Cabut akses user pada objek (ACL + wrapped key ikut dihapus)."""
    token, _ = get_token_and_key()
    if not token:
        return
    try:
        resp = requests.post(
            f"{API_BASE}/objects/{object_id}/revoke",
            json={"username": username},
            headers=_get_headers(token)
        )
        if resp.status_code == 200:
            print(resp.json()["detail"])
        else:
            print(f"Gagal: {resp.json().get('detail', resp.text)}")
    except requests.ConnectionError:
        print(f"Error: Tidak dapat terhubung ke server di {API_BASE}")


@app.command("shares")
def shares(object_id: str = typer.Argument(..., help="ID objek")):
    """Daftar pengguna yang memegang wrapped key pada objek."""
    token, _ = get_token_and_key()
    if not token:
        return
    try:
        resp = requests.get(f"{API_BASE}/objects/{object_id}/shares", headers=_get_headers(token))
        if resp.status_code == 200:
            rows = resp.json()
            if not rows:
                print("Tidak ada wrapped key tersimpan untuk objek ini.")
                return
            print(f"{'User':<20} {'Izin':<8} {'Dibuat':<26}")
            print("-" * 56)
            for r in rows:
                print(f"{r['username']:<20} {r['permission']:<8} {r['created_at']:<26}")
        else:
            print(f"Gagal: {resp.json().get('detail', resp.text)}")
    except requests.ConnectionError:
        print(f"Error: Tidak dapat terhubung ke server di {API_BASE}")

@app.command("versions")
def versions(object_id: str = typer.Argument(..., help="ID objek")):
    """Daftar seluruh versi objek (versioning nyata) beserta flag current."""
    token, _ = get_token_and_key()
    if not token:
        return
    try:
        resp = requests.get(f"{API_BASE}/objects/{object_id}/versions", headers=_get_headers(token))
        if resp.status_code == 200:
            rows = resp.json()
            if not rows:
                print("Tidak ada versi untuk objek ini.")
                return
            print(f"{'Version ID':<18} {'Ver':>4} {'Ukuran':>8}  {'Current':<8} {'Dibuat':<26}")
            print("-" * 72)
            for r in rows:
                cur = "YA" if r["current"] else ""
                print(f"{r['version_id']:<18} {r['version']:>4} {r['size']:>8}  {cur:<8} {r['created_at']:<26}")
        else:
            print(f"Gagal: {resp.json().get('detail', resp.text)}")
    except requests.ConnectionError:
        print(f"Error: Tidak dapat terhubung ke server di {API_BASE}")


@app.command("restore")
def restore(object_id: str = typer.Argument(..., help="ID objek"),
            version_id: str = typer.Argument(..., help="ID versi lama yang ingin dipulihkan (ver-...)")):
    """Restore versi lama menjadi versi aktif.

    Non-destructive: dibuat versi baru berisi salinan versi target —
    riwayat lama tetap utuh. Hanya pemilik objek yang bisa me-restore."""
    token, _ = get_token_and_key()
    if not token:
        return
    try:
        resp = requests.post(
            f"{API_BASE}/objects/{object_id}/versions/{version_id}/restore",
            headers=_get_headers(token)
        )
        if resp.status_code == 200:
            body = resp.json()
            print(body["detail"])
            print(f"  Versi baru    : v{body['version']} ({body['version_id']})")
            print(f"  Restored from : {body['restored_from']}")
        else:
            print(f"Gagal: {resp.json().get('detail', resp.text)}")
    except requests.ConnectionError:
        print(f"Error: Tidak dapat terhubung ke server di {API_BASE}")


if __name__ == "__main__":
    app()
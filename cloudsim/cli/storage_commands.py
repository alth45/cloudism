"""Perintah gaya `gcloud storage`: mb, rb, ls, cp, rm, stat dengan dukungan path gs://."""
import os
# pyrefly: ignore [missing-import]
import typer
import requests
from cloudsim.cli.auth_commands import get_token_and_key, API_BASE
from cloudsim.crypto.aes_custom import AES256CTR
from cloudsim.crypto.key_wrapping import generate_dek, wrap_key
from cloudsim.crypto.utils import encode_base64, decode_base64

app = typer.Typer(help="Manajemen bucket & objek gaya gcloud storage (gs://bucket/obj)")


def _get_headers(token: str):
    return {"Authorization": f"Bearer {token}"}


def _die(resp) -> None:
    """Cetak pesan error dari respons dan hentikan perintah."""
    try:
        msg = resp.json().get("detail", resp.text)
    except Exception:
        msg = resp.text
    typer.echo(f"Gagal ({resp.status_code}): {msg}", err=True)
    raise typer.Exit(code=1)


def parse_gs_uri(uri: str) -> tuple[str, str | None]:
    """Pecah 'gs://bucket[/identifier]' menjadi (bucket_name, identifier|None).
    Melempar ValueError jika format salah."""
    if not uri.startswith("gs://"):
        raise ValueError(f"URI tidak valid: '{uri}' (harus diawali gs://)")
    rest = uri[len("gs://"):].strip("/")
    if not rest:
        raise ValueError("Nama bucket kosong pada URI gs://")
    parts = rest.split("/", 1)
    bucket = parts[0]
    identifier = parts[1] if len(parts) > 1 and parts[1] else None
    return bucket, identifier


def _resolve_object(token: str, bucket: str, identifier: str) -> dict:
    """Resolve gs://bucket/identifier (ID atau nama file) menjadi metadata objek via API."""
    resp = requests.get(
        f"{API_BASE}/buckets/name/{bucket}/objects/{identifier}",
        headers=_get_headers(token)
    )
    if resp.status_code != 200:
        _die(resp)
    return resp.json()


def _bucket_id_by_name(token: str, name: str) -> str:
    resp = requests.get(f"{API_BASE}/buckets/name/{name}/id", headers=_get_headers(token))
    if resp.status_code != 200:
        _die(resp)
    return resp.json()["id"]


def _upload_file(token: str, key: bytes, filepath: str, bucket_id: str | None) -> dict:
    """Enkripsi lokal lalu upload (opsional ke bucket). Mengembalikan metadata.

    Mode shareable diaktifkan dengan env CLOUDSIM_SHARE_PASS: payload
    dienkripsi dengan DEK acak dan DEK dibungkus via PBKDF2/key-wrapping
    sehingga objek bisa dibagikan lewat `object share` (re-encryption).
    """
    filename = os.path.basename(filepath)
    with open(filepath, "rb") as f:
        plaintext = f.read()
    dek_wrapping = None
    dek = None
    share_pass = os.environ.get("CLOUDSIM_SHARE_PASS")
    if share_pass:
        dek = generate_dek()
        cipher = AES256CTR(dek)
        encrypted, nonce = cipher.encrypt(plaintext)
        dek_wrapping = wrap_key(dek, share_pass)
    else:
        cipher = AES256CTR(key)
        encrypted, nonce = cipher.encrypt(plaintext)
    req_data = {
        "encrypted_payload": encode_base64(encrypted),
        "nonce": encode_base64(nonce),
        "filename": filename,
        "mime_type": "application/octet-stream",
    }
    if bucket_id:
        req_data["bucket_id"] = bucket_id
    if dek_wrapping:
        req_data["dek_wrapping"] = dek_wrapping
    resp = requests.post(f"{API_BASE}/objects/upload", json=req_data, headers=_get_headers(token))
    if resp.status_code != 200:
        _die(resp)
    meta = resp.json()
    if dek is not None:
        from cloudsim.cli.object_commands import _remember_dek
        _remember_dek(meta["id"], dek)
    return meta


def _download_object(token: str, key: bytes, object_id: str, output: str | None) -> str:
    """Download ciphertext, dekripsi lokal, tulis ke file. Kembalikan path output."""
    resp = requests.get(f"{API_BASE}/objects/{object_id}/download", headers=_get_headers(token))
    if resp.status_code != 200:
        _die(resp)
    data = resp.json()
    from cloudsim.cli.object_commands import _decrypt_with_fallback
    plaintext, _method = _decrypt_with_fallback(data, key)
    filename = output or data["filename"]
    with open(filename, "wb") as f:
        f.write(plaintext)
    return filename


# ---------- mb: make bucket ----------
@app.command("mb")
def make_bucket(bucket_name: str = typer.Argument(..., help="Nama bucket (huruf kecil, angka, '-', '.', '_')")):
    """Buat bucket baru (mirip `gcloud storage mb`)."""
    token, _ = get_token_and_key()
    if not token:
        return
    resp = requests.post(f"{API_BASE}/buckets", json={"name": bucket_name}, headers=_get_headers(token))
    if resp.status_code != 200:
        _die(resp)
    b = resp.json()
    typer.echo(f"Bucket dibuat: gs://{b['name']}  (id={b['id']})")


# ---------- rb: remove bucket ----------
@app.command("rb")
def remove_bucket(bucket_name: str = typer.Argument(..., help="Nama bucket yang akan dihapus")):
    """Hapus bucket kosong (mirip `gcloud storage rb`). Bucket harus kosong dan milik Anda."""
    token, _ = get_token_and_key()
    if not token:
        return
    bucket_id = _bucket_id_by_name(token, bucket_name)
    resp = requests.delete(f"{API_BASE}/buckets/{bucket_id}", headers=_get_headers(token))
    if resp.status_code != 200:
        _die(resp)
    typer.echo(f"Bucket dihapus: gs://{bucket_name}")


# ---------- ls: list buckets / objects ----------
@app.command("ls")
def list_storage(uri: str = typer.Argument(None, help="Kosong = daftar bucket; gs://bucket = isi bucket")):
    """Daftar bucket (tanpa argumen) atau isi bucket (gs://bucket)."""
    token, _ = get_token_and_key()
    if not token:
        return
    if uri is None:
        resp = requests.get(f"{API_BASE}/buckets", headers=_get_headers(token))
        if resp.status_code != 200:
            _die(resp)
        buckets = resp.json()
        if not buckets:
            typer.echo("Tidak ada bucket. Buat dengan: cloudsim storage mb <nama>")
            return
        typer.echo(f"{'BUCKET':<30} {'ID':<14} {'DIBUAT'}")
        typer.echo("-" * 78)
        for b in buckets:
            typer.echo(f"{'gs://' + b['name']:<30} {b['id']:<14} {b['created_at']}")
        return

    bucket, _ = parse_gs_uri(uri)
    bucket_id = _bucket_id_by_name(token, bucket)
    resp = requests.get(f"{API_BASE}/objects/?bucket_id={bucket_id}", headers=_get_headers(token))
    if resp.status_code != 200:
        _die(resp)
    objects = resp.json()
    if not objects:
        typer.echo(f"(kosong) gs://{bucket}")
        return
    for obj in objects:
        typer.echo(f"gs://{bucket}/{obj['filename']}   {obj['id']}   {obj['size']} bytes")


# ---------- cp: upload/download ----------
@app.command("cp")
def copy(source: str = typer.Argument(..., help="File lokal ATAU gs://bucket/obj"),
         destination: str = typer.Argument(..., help="gs://bucket/ ATAU file lokal")):
    """Salin file: lokal -> gs://bucket/ (upload) atau gs://bucket/obj -> lokal (download)."""
    token, key = get_token_and_key()
    if not token or not key:
        typer.echo("Anda belum login. Silakan login dulu.")
        return

    src_is_gs = source.startswith("gs://")
    dst_is_gs = destination.startswith("gs://")
    if src_is_gs == dst_is_gs:
        typer.echo("cp membutuhkan tepat satu sisi gs://... (lokal <-> cloud)", err=True)
        raise typer.Exit(code=1)

    if not src_is_gs:
        # Upload: lokal -> gs://bucket/
        bucket, ident = parse_gs_uri(destination)
        bucket_id = _bucket_id_by_name(token, bucket)
        meta = _upload_file(token, key, source, bucket_id)
        name = ident or meta["filename"]
        typer.echo(f"Upload berhasil: gs://{bucket}/{name}  (id={meta['id']}, {meta['size']} bytes)")
    else:
        # Download: gs://bucket/obj -> lokal
        bucket, ident = parse_gs_uri(source)
        if ident is None:
            typer.echo("URI sumber harus menunjuk objek: gs://bucket/<nama_atau_id>", err=True)
            raise typer.Exit(code=1)
        obj_meta = _resolve_object(token, bucket, ident)
        out = _download_object(token, key, obj_meta["id"], destination)
        typer.echo(f"Download berhasil: gs://{bucket}/{obj_meta['filename']} -> {out}")


# ---------- rm: hapus objek ----------
@app.command("rm")
def remove(uri: str = typer.Argument(..., help="gs://bucket/<nama_atau_obj_id>")):
    """Hapus objek dari bucket (hanya owner)."""
    token, _ = get_token_and_key()
    if not token:
        return
    bucket, ident = parse_gs_uri(uri)
    if ident is None:
        typer.echo("URI harus menunjuk objek: gs://bucket/<nama_atau_id>", err=True)
        raise typer.Exit(code=1)
    obj_meta = _resolve_object(token, bucket, ident)
    resp = requests.delete(f"{API_BASE}/objects/{obj_meta['id']}", headers=_get_headers(token))
    if resp.status_code != 200:
        _die(resp)
    typer.echo(f"Dihapus: gs://{bucket}/{obj_meta['filename']}  (id={obj_meta['id']})")


# ---------- stat: metadata objek ----------
@app.command("stat")
def stat(uri: str = typer.Argument(..., help="gs://bucket/<nama_atau_obj_id>")):
    """Tampilkan metadata objek di bucket."""
    token, _ = get_token_and_key()
    if not token:
        return
    bucket, ident = parse_gs_uri(uri)
    if ident is None:
        typer.echo("URI harus menunjuk objek: gs://bucket/<nama_atau_id>", err=True)
        raise typer.Exit(code=1)
    meta = _resolve_object(token, bucket, ident)
    typer.echo(f"gs://{bucket}/{meta['filename']}")
    for k, v in meta.items():
        typer.echo(f"  {k}: {v}")


if __name__ == "__main__":
    app()

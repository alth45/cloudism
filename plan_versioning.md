# Plan Versioning Nyata Per Objek – CloudSim

## 1. Tujuan
Mengganti "version" semu (hardcode = 1) menjadi versioning nyata:
setiap upload/update terhadap nama objek di bucket yang sama menambah
versi baru; setiap versi punya `version_id` sendiri, immutable, bisa
dilist, di-download, dan versi lama bisa di-restore.

## 2. Desain Data
### Tabel baru `object_versions`
| Kolom | Tipe | Keterangan |
|-------|------|------------|
| version_id | TEXT PK | Format `ver-{12 hex}` (flag identitas versi) |
| object_id  | TEXT FK → objects.id (ON DELETE CASCADE) | Objek yang memiliki versi |
| version    | INTEGER | Nomor urut versi (1, 2, 3, ...) per objek |
| encrypted_payload / nonce / size / mime_type / filename | salinan snapshot ciphertext per versi |
| created_at | TEXT | waktu versi dibuat |
| created_by | TEXT | user pembuat versi |
| is_current | INTEGER 0/1 | versi aktif (yang ter-serve lewat endpoint biasa) |
| storage_line | INTEGER | baris di storage.txt (append-only) |
UNIQUE(object_id, version).

### Kolom baru di `objects`
- `current_version_id TEXT` — flag versi aktif objek (pointer ke object_versions).

## 3. Aturan Bisnis
- Upload baru dengan (bucket_id, filename) yang sama oleh owner = versi baru
  pada objek yang sama (mirip GCS versioning). Beda nama/bucket = objek baru v1.
- Restore versi lama TIDAK menghapus data: membuat versi baru lagi yang
  isinya salinan payload versi target (non-destructive), lalu jadi current.
- Versi lama tetap immutable & bisa di-download via `?version_id=`.
- Endpoint download/list/info lama tetap melayani versi current (kompatibel).
- Hapus objek = hapus semua versi (CASCADE).

## 4. Engine (`core/engine.py`)
- `upload_encrypted(...)`: cek existing (owner+filename+bucket) → bila ada,
  simpan sebagai versi N+1; update kolom objects + set current_version_id.
- `list_versions(object_id, user_id)`
- `get_version(version_id, user_id)`
- `download_version(object_id, user_id, version_id)`
- `restore_version(object_id, user_id, version_id)` → versi baru dari snapshot lama.

## 5. API (`routes/objects.py`)
| Metode | Path | Deskripsi |
|--------|------|-----------|
| GET | `/objects/{id}/versions` | daftar versi (ada flag `current`) |
| GET | `/objects/{id}/versions/{version_id}` | metadata satu versi |
| GET | `/objects/{id}/download?version_id=` | unduh versi tertentu |
| POST | `/objects/{id}/versions/{version_id}/restore` | restore versi lama (non-destructive) |

## 6. CLI (`cli/object_commands.py`)
- `cloudsim object versions <obj_id>`
- `cloudsim object download <obj_id> --version-id ver-...`
- `cloudsim object restore <obj_id> <version_id>`

## 7. Tes
TestVersioning di tests/test_versioning.py: auto-versioning saat re-upload,
isi list versions, download per versi, restore non-destructive, akses ACL,
kasus error (versi tidak dikenal, bukan owner restore → 403).

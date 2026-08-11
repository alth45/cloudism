
# Plan Bucket – CloudSim

## 1. Tujuan
Menambahkan dukungan **bucket** sebagai wadah logis untuk mengelompokkan objek, meniru layanan penyimpanan cloud seperti Google Cloud Storage (`gs://bucket/object`).

## 2. Desain Data

### 2.1 Tabel Baru `buckets`
| Kolom | Tipe | Keterangan |
|-------|------|------------|
| id | TEXT PK | Format `bkt-{8 hex}` |
| name | TEXT UNIQUE NOT NULL | Nama bucket (user-friendly) |
| owner_id | TEXT NOT NULL FK → users.id | Pemilik bucket |
| created_at | TEXT | ISO timestamp |

### 2.2 Perubahan Tabel `objects`
| Kolom Baru | Tipe | Keterangan |
|------------|------|------------|
| bucket_id | TEXT NULL FK → buckets.id | Bucket tempat objek berada (NULL = tanpa bucket) |

### 2.3 Aturan Bisnis
- Satu bucket hanya bisa dimiliki satu user.
- Nama bucket bersifat unik secara global (seperti di cloud sungguhan).
- Objek boleh tidak memiliki bucket (kompatibel dengan sistem lama).
- Operasi ACL tetap per-objek, tidak per-bucket.

## 3. Perubahan Engine (`core/engine.py`)

### 3.1 Method Baru
- `create_bucket(owner_id, name) → dict`  
  Buat bucket, kembalikan metadata bucket.
- `list_buckets(owner_id) → list[dict]`  
  Daftar bucket milik user (atau semua bucket yang bisa diakses? Saat ini hanya milik sendiri).
- `delete_bucket(bucket_id, owner_id) → bool`  
  Hapus bucket jika kosong dan user adalah pemilik.
- `get_bucket_id_by_name(name) → str | None`  
  Resolve nama bucket ke ID.

### 3.2 Modifikasi Method
- `upload_encrypted(...)`: tambahkan parameter opsional `bucket_id`. Jika diberikan, objek akan dikaitkan ke bucket tersebut.
- `list_accessible_objects(user_id, bucket_id=None)`: bisa filter berdasarkan bucket_id.
- `get_metadata(...)`: sertakan `bucket_id` dalam hasil jika ada.

## 4. Perubahan API

### 4.1 Endpoint Baru di `/buckets`
| Metode | Path | Deskripsi |
|--------|------|-----------|
| POST | `/buckets` | Buat bucket baru (body: `{"name": "..."}`) |
| GET | `/buckets` | List bucket user saat ini |
| DELETE | `/buckets/{bucket_id}` | Hapus bucket (jika kosong) |
| GET | `/buckets/{bucket_id}` | Info bucket + daftar objek di dalamnya (atau via `/objects?bucket_id=...`) |

### 4.2 Modifikasi Endpoint Objek
- `POST /objects/upload`: tambahkan field opsional `bucket_id` di `UploadRequest`.
- `GET /objects/`: tambahkan query parameter opsional `bucket_id` untuk filter.

## 5. Perubahan CLI

### 5.1 Perintah Baru (mirip `gcloud storage`)
- `cloudsim storage mb <bucket_name>` → buat bucket (make bucket).
- `cloudsim storage rb <bucket_name>` → hapus bucket kosong (remove bucket).
- `cloudsim storage ls [gs://bucket_name]` → list objek di bucket (jika argumen diberikan), atau semua objek jika tidak.
- `cloudsim storage cp <local> gs://bucket_name/` → upload ke bucket.
- `cloudsim storage cp gs://bucket_name/<obj_name|obj_id> <local>` → download dari bucket.
- `cloudsim storage rm gs://bucket_name/<obj_id>` → hapus objek di bucket.
- `cloudsim storage stat gs://bucket_name/<obj_id>` → metadata.

### 5.2 Penanganan Path
- Format: `gs://<bucket>/<identifier>`
- Identifier bisa nama file atau ID objek.
- Jika identifier adalah ID objek, langsung gunakan; jika nama file, perlu pencarian di bucket (oleh API).

### 5.3 Resolusi di CLI
CLI akan memecah string `gs://...` menjadi nama bucket dan nama objek. Untuk operasi yang membutuhkan object ID, CLI akan memanggil API untuk mencari objek berdasarkan nama di bucket (atau langsung menggunakan ID jika diberikan).

## 6. Langkah Implementasi

1. **Database**  
   - Buat file `schema_v2.sql` (atau alter schema dengan ALTER TABLE) untuk menambahkan tabel `buckets` dan kolom `bucket_id` di `objects`.  
   - Update `DatabaseManager` dengan method untuk CRUD bucket dan filter objek per bucket.

2. **Engine**  
   - Tambahkan method bucket management.  
   - Integrasikan `bucket_id` di `upload_encrypted` dan query list.

3. **API**  
   - Tambahkan router `buckets.py` di `api/routes/`.  
   - Daftarkan router di `app.py`.  
   - Modifikasi `objects.py` untuk menerima `bucket_id` dan filter.

4. **CLI**  
   - Tambahkan perintah `mb`, `rb`, dan modifikasi `cp`, `ls`, `rm`, `cat`, `stat` agar mendukung argumen `gs://`.
   - Implementasi parsing path `gs://` di utility function.

5. **Testing**  
   - Perbarui `test_e2e.py` dengan skenario bucket: buat bucket, upload ke dalamnya, list, download, hapus bucket.

6. **Dokumentasi**  
   - Update `README.md` dengan contoh perintah bucket.

## 7. Contoh Skenario Penggunaan Setelah Implementasi

```bash
# Buat bucket
cloudsim storage mb arsip-pribadi

# Upload ke bucket
cloudsim storage cp rahasia.txt gs://arsip-pribadi/

# List isi bucket
cloudsim storage ls gs://arsip-pribadi
# Output:
# gs://arsip-pribadi/rahasia.txt   obj-abc123   1024 bytes

# Stat objek di bucket
cloudsim storage stat gs://arsip-pribadi/rahasia.txt

# Download
cloudsim storage cp gs://arsip-pribadi/rahasia.txt hasil.txt

# Hapus objek
cloudsim storage rm gs://arsip-pribadi/rahasia.txt

# Hapus bucket (harus kosong)
cloudsim storage rb arsip-pribadi
```

## 8. Catatan
- Untuk menyederhanakan, pencarian objek berdasarkan nama di bucket akan dilakukan oleh API dengan query `SELECT * FROM objects WHERE bucket_id = ? AND filename = ?`. CLI cukup kirim nama file, API akan mencari ID-nya.
- Jika ada banyak objek dengan nama sama dalam satu bucket (mungkin karena versioning nanti), kita bisa ambil yang terbaru atau minta ID eksplisit.
- Fitur ini mempertahankan kompatibilitas dengan objek tanpa bucket (NULL `bucket_id`), sehingga sistem tetap berjalan seperti semula.

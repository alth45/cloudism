

# CloudSim – Simulator Cloud Storage Lokal

CloudSim adalah simulator penyimpanan cloud berbasis Python yang meniru perilaku layanan cloud sungguhan (seperti AWS S3 atau Google Cloud Storage) secara lokal. Data disimpan dalam file `storage.txt` dengan format JSON per baris yang menyerupai metadata dan payload cloud asli. Proyek ini dibangun untuk **belajar mekanisme internal cloud**: penyimpanan objek, kontrol akses, enkripsi custom, dan manajemen perintah.

## Fitur Utama

- **Penyimpanan Objek** – Setiap file disimpan sebagai objek dengan ID unik, timestamp, dan payload terenkripsi.
- **Bucket & URI `gs://`** – Manajemen bucket gaya Google Cloud Storage dengan validasi nama, resolusi path `gs://bucket/objek`, dan pemisahan objek per bucket.
- **Keamanan Custom** – Registrasi pengguna, autentikasi token JWT buatan sendiri, dan Access Control List (ACL) per objek.
- **Library Enkripsi Buatan** – Implementasi AES-256 mode CTR, PBKDF2 untuk derivasi kunci, dan Base64/PKCS7.
- **Re-encryption saat Sharing** – Envelope encryption gaya key-wrapping: objek shareable dienkripsi dengan DEK acak; saat dibagikan, DEK di-*wrap* ulang untuk tiap penerima memakai KEK hasil PBKDF2(passphrase). Server tidak pernah melihat plaintext maupun DEK.
- **API REST** – Endpoint CRUD untuk bucket, objek, autentikasi, dan manajemen pengguna (FastAPI).
- **CLI Interaktif** – Grup perintah `auth`, `object`, dan `storage` (`mb`, `rb`, `ls`, `cp`, `rm`, `stat`) mirip `gcloud storage`.
- **Client-side Encryption** – File dienkripsi di sisi client sebelum dikirim ke server; server tidak pernah melihat plaintext.
- **Basis Data Metadata** – SQLite untuk menyimpan metadata objek, pengguna, dan ACL.
- **Append-only Storage** – Log immutable di `storage.txt` untuk mendukung versioning dan audit.
- **Versioning Nyata per Objek** – Setiap versi punya flag `version_id` (`ver-...`) sendiri; upload ulang nama+bucket yang sama menambah versi baru (bukan menimpa), riwayat lama dapat diunduh, dan versi lama bisa di-*restore* secara non-destructive.


## Arsitektur

```
+-------------+      +-------------+      +-----------------+
|   CLI       | <--> |   API       | <--> |  Core Engine    |
| (Typer)     |      | (FastAPI)   |      | (manajemen objek,|
+-------------+      +-------------+      |  keamanan, dll)  |
                                          +--------+--------+
                                                   |
                                          +--------v--------+
                                          |  Database (SQLite)|
                                          +-----------------+
                                                   |
                                          +--------v--------+
                                          |  File Storage    |
                                          |  (storage.txt)   |
                                          +-----------------+

```
- **Core Engine** – Logika CRUD, enkripsi/dekripsi, ACL, key-wrapping (re-encryption), generator ID.
- **API** – Lapisan HTTP dengan autentikasi Bearer token (JWT manual), termasuk endpoint `/buckets` serta `/objects/{id}/share|revoke|shares`.
- **CLI** – Antarmuka terminal yang memanggil API dan menangani enkripsi lokal; grup `storage` menerima URI `gs://bucket/objek`.
- **Database** – Metadata bucket, objek, pengguna, hak akses, dan wrapped key per user (`object_keys`).
- **File Storage** – Payload terenkripsi dalam format append-only JSON baris.

## Teknologi

- Python 3.10+
- FastAPI + Uvicorn (REST API)
- Typer (CLI)
- SQLite (database)
- Pydantic (validasi)
- Standard library: `hashlib`, `hmac`, `json`, `os`, `base64` untuk custom crypto

## Instalasi

1. Clone repositori atau salin folder proyek.
2. Buat virtual environment (opsional):
   ```bash
   python -m venv venv
   venv\Scripts\activate      # Windows
   source venv/bin/activate   # Linux/Mac
   ```
3. Install dependensi:
   ```bash
   pip install -r requirements.txt
   ```

## Menjalankan Server API

Dari root proyek (tempat folder `cloudsim/` dan `plan.md`), jalankan:

```bash
uvicorn cloudsim.api.app:app --reload
```

Server akan berjalan di `http://127.0.0.1:8000`. Dokumentasi interaktif tersedia di `http://127.0.0.1:8000/docs`.

Atur environment variable `CLOUDSIM_API` jika ingin mengubah URL default CLI:
```bash
set CLOUDSIM_API=http://127.0.0.1:8000    # Windows
export CLOUDSIM_API=http://127.0.0.1:8000 # Linux/Mac
```

### Environment Variable Lainnya

| Variabel | Fungsi | Default |
|---|---|---|
| `CLOUDSIM_JWT_SECRET` | Secret key tetap untuk tanda tangan/verifikasi token JWT | Acak per proses |
| `CLOUDSIM_DB_PATH` | Lokasi database SQLite (mis. `":memory:"` untuk mode tes) | `cloudsim.db` |
| `CLOUDSIM_SHARE_PASS` | Passphrase pembagian untuk unwrap DEK pada download/`storage cp` objek shareable | Tidak diset (prompt interaktif) |

## Penggunaan CLI

### Perintah Autentikasi

```bash
# Registrasi (langsung login)
python -m cloudsim.cli.cli register
# Input: username, password

# Login
python -m cloudsim.cli.cli login
# Input: username, password

# Lihat sesi aktif
python -m cloudsim.cli.cli whoami

# Logout
python -m cloudsim.cli.cli logout
```

### Manajemen Objek

```bash
# Upload file (dienkripsi otomatis di client)
python -m cloudsim.cli.cli upload <path_file>

# Upload sebagai objek shareable (DEK acak + key-wrapping PBKDF2)
python -m cloudsim.cli.cli upload <path_file> --shareable
# Input: passphrase pembagian (konfirmasi 2x). Bisa juga via --passphrase "..."

# Daftar objek yang bisa diakses
python -m cloudsim.cli.cli list

# Lihat metadata
python -m cloudsim.cli.cli info <object_id>

# Download & dekripsi
python -m cloudsim.cli.cli download <object_id> -o <output_file>
# Untuk objek shareable: passphrase lewat --passphrase, env CLOUDSIM_SHARE_PASS, atau prompt

# Bagikan akses ke user lain (default: RE-ENCRYPTION / re-wrap DEK utk penerima)
python -m cloudsim.cli.cli share <object_id> <username> --perm read
# Input: passphrase khusus penerima; sampaikan lewat kanal aman
# Mode lama (hanya ACL, tanpa re-encryption):
python -m cloudsim.cli.cli share <object_id> <username> --no-reencrypt

# Daftar pembagian aktif (wrapped key per user)
python -m cloudsim.cli.cli shares <object_id>

# Cabut pembagian (hapus wrapped key + ACL penerima)
python -m cloudsim.cli.cli revoke <object_id> <username>

# Hapus objek (hanya owner)
python -m cloudsim.cli.cli delete <object_id>

# Daftar seluruh versi objek (flag current menunjukkan versi aktif)
python -m cloudsim.cli.cli versions <object_id>

# Unduh versi tertentu (versi lama immutable & tetap tersedia)
python -m cloudsim.cli.cli download <object_id> --version-id ver-abc123... -o lama.txt

# Restore versi lama menjadi versi aktif (dibuat versi baru; riwayat utuh)
python -m cloudsim.cli.cli restore <object_id> ver-abc123...
```

### Versioning Nyata per Objek

CloudSim kini menerapkan versioning nyata (mirip Google Cloud Storage):

1. **Flag `version_id`** – Setiap kali objek dibuat/di-update, sistem membuat record versi dengan ID unik `ver-{12 hex}` di tabel `object_versions`; kolom `objects.current_version_id` menunjuk versi aktif.
2. **Auto-versioning** – Upload ulang dengan `(owner, filename, bucket)` yang sama TIDAK menimpa data lama: nomor versi naik (v1 → v2 → …), snapshot ciphertext tiap versi disimpan immutable di DB maupun log append-only `storage.txt`.
3. **List & unduh riwayat** – `GET /objects/{id}/versions`, `GET /objects/{id}/versions/{vid}`, dan `GET /objects/{id}/download?version_id=ver-...` mengembalikan versi tertentu; tanpa parameter tetap melayani versi current (kompatibel).
4. **Restore versi lama** – `POST /objects/{id}/versions/{vid}/restore` (CLI: `restore`) menyalin versi target menjadi versi BARU lalu menandainya current — non-destructive, hanya owner.
5. **Cascade** – Menghapus objek ikut menghapus seluruh versinya (`ON DELETE CASCADE`).

Skema lama dimigrasi otomatis: tabel `object_versions` dibuat saat startup dan kolom `current_version_id` ditambahkan via `ALTER TABLE`.

### Re-encryption saat Sharing (Key-Wrapping + PBKDF2)

CloudSim menerapkan pola *envelope encryption* agar sharing dapat dilakukan tanpa menyerahkan kunci utama pengguna:

1. **Upload `--shareable`** – Client membangkitkan **DEK (Data Encryption Key) acak 256-bit**, mengenkripsi payload dengan DEK tersebut (AES-256-CTR), lalu menyimpan *wrapped key* milik owner: DEK dibungkus memakai **KEK = PBKDF2-HMAC-SHA256(passphrase, salt acak 16 byte, 100.000 iterasi)**.
2. **Share** – Saat membagikan ke user lain, client melakukan **re-encryption pada kuncinya saja**: DEK yang sama di-*wrap* ulang dengan KEK yang diturunkan dari passphrase pembagian untuk penerima. Payload tidak dienkripsi ulang, dan server hanya menerima ciphertext + wrapped key baru.
3. **Download oleh penerima** – Server mengirim ciphertext beserta wrapped key milik peminta. Penerima memasukkan passphrase → client menurunkan KEK → *unwrap* DEK → mendekripsi payload. Passphrase salah menghasilkan DEK sampah (dekripsi gagal/garbage), bukan error bocor.
4. **Revoke** – Wrapped key dan ACL penerima dihapus dari database; penerima tidak bisa lagi membuka objek.

Perbandingan dengan mode lama (`--no-reencrypt`): mode lama hanya menambah ACL, sehingga penerima harus memiliki kunci login owner — praktis hanya berguna sebagai simulasi. Dengan re-encryption, setiap penerima punya *saluran kunci sendiri* (per-user wrapped key) yang bisa dicabut individual.

Kompatibilitas mundur terjaga: objek tanpa `dek_wrapping` tetap mengikuti alur lama.

### Manajemen Bucket (`storage` — gaya `gcloud storage`)

```bash
# Buat bucket (nama: huruf kecil, angka, '-', '.', '_')
python -m cloudsim.cli.cli storage mb my-bucket

# Daftar semua bucket
python -m cloudsim.cli.cli storage ls

# Daftar isi sebuah bucket
python -m cloudsim.cli.cli storage ls gs://my-bucket

# Upload file lokal ke bucket (dengan nama objek kustom)
python -m cloudsim.cli.cli storage cp rahasia.txt gs://my-bucket/2026/rahasia.txt

# Download objek dari bucket
python -m cloudsim.cli.cli storage cp gs://my-bucket/2026/rahasia.txt ./hasil.txt

# Lihat metadata objek (berdasarkan nama objek atau object ID)
python -m cloudsim.cli.cli storage stat gs://my-bucket/2026/rahasia.txt

# Hapus objek
python -m cloudsim.cli.cli storage rm gs://my-bucket/2026/rahasia.txt

# Hapus bucket (harus kosong)
python -m cloudsim.cli.cli storage rb my-bucket
```

### Contoh Skenario

```bash
# Terminal 1: server
uvicorn cloudsim.api.app:app

# Terminal 2: client
python -m cloudsim.cli.cli register
Username: alice
Password: ****

python -m cloudsim.cli.cli upload rahasia.txt
Upload berhasil!
  ID        : obj-abc123...

python -m cloudsim.cli.cli list
ID               Nama File       Ukuran   Tipe                  Dibuat
----------------------------------------------------------------------------
obj-abc123...    rahasia.txt     2048     application/octet...  2026-08-11...

python -m cloudsim.cli.cli download obj-abc123... -o hasil.txt
File berhasil diunduh: hasil.txt

# Alur bucket gaya gcloud storage
python -m cloudsim.cli.cli storage mb data-alice
python -m cloudsim.cli.cli storage cp rahasia.txt gs://data-alice/arsip/rahasia.txt
python -m cloudsim.cli.cli storage ls gs://data-alice
python -m cloudsim.cli.cli storage stat gs://data-alice/arsip/rahasia.txt
python -m cloudsim.cli.cli storage cp gs://data-alice/arsip/rahasia.txt ./salinan.txt

# Alur sharing dengan re-encryption (key-wrapping + PBKDF2)
# Terminal 2 (alice, owner):
CLOUDSIM_SHARE_PASS=rahasia123 python -m cloudsim.cli.cli upload rahasia.txt --shareable
python -m cloudsim.cli.cli share obj-abc123... bob            # passphrase utk bob: "untuk-bob"
python -m cloudsim.cli.cli shares obj-abc123...               # daftar pembagian aktif

# Terminal 3 (bob, penerima):
CLOUDSIM_SHARE_PASS=untuk-bob python -m cloudsim.cli.cli download obj-abc123... -o hasil_bob.txt

# Alice mencabut akses bob:
python -m cloudsim.cli.cli revoke obj-abc123... bob
```

## Pengujian

Proyek dilengkapi pengujian end-to-end menggunakan `pytest` dan `TestClient` dari FastAPI, dengan **isolasi penuh** (database in-memory per tes + secret JWT tetap via fixture di `tests/conftest.py`).

```bash
# Install dependensi pengujian (jika belum)
pip install pytest httpx

# Jalankan semua pengujian
python -m pytest tests/ -v
```

Pengujian mencakup:
- Registrasi dua user
- Upload dengan enkripsi client-side
- Verifikasi download & dekripsi
- Uji akses tanpa izin (ditolak)
- Sharing objek
- Dekripsi oleh user lain (harus gagal karena kunci berbeda)
- Penghapusan objek
- Siklus hidup bucket lengkap (`mb`, `ls`, `cp`, `stat`, `rm`, `rb` via URI `gs://`)
- Objek tanpa bucket (mode legacy) masih berfungsi
- Validasi penolakan nama bucket tidak valid
- **Versioning nyata** (`tests/test_versioning.py`, `class TestObjectVersioning`): flag `version_id` di metadata/list, auto-versioning saat upload ulang nama+bucket sama, daftar versi dengan flag current, unduh versi lama (immutable), restore non-destructive menjadi versi baru, hanya owner yang boleh restore (403), versioning ter-scope bucket, dan cascade penghapusan seluruh versi saat objek dihapus.
- **Re-encryption share**: roundtrip wrap/unwrap DEK, determinisme PBKDF2, alur penuh owner→penerima (passphrase benar mendekripsi, passphrase salah menghasilkan sampah), kompatibilitas mundur mode `--no-reencrypt`, validasi 422 untuk `dek_wrapping` tidak valid, dan cascade penghapusan wrapped key saat objek dihapus (`class TestReEncryptionShare`)

> Catatan: `pytest.ini` menonaktifkan plugin pihak ketiga yang bermasalah (`-p no:libtmux`) agar koleksi tes tidak crash di lingkungan tertentu. File data `cloudsim/storage/storage.txt` bersifat append-only — setiap run tes menambahkan baris ciphertext baru (perilaku yang memang dirancang).

## Struktur Direktori

```
.
├── README.md              # Dokumentasi ini
├── plan.md                # Rencana awal proyek
├── plan_bucket.md         # Rencana fitur bucket & CLI storage
├── plan_command.md        # Rencana struktur perintah CLI
├── pytest.ini             # Konfigurasi pytest
├── requirements.txt       # Daftar package Python
├── cloudsim/              # Package utama
│   ├── __init__.py
│   ├── main.py            # Entry point (API/CLI)
│   ├── core/              # Engine inti
│   │   ├── engine.py      # CloudObjectManager
│   │   ├── security.py    # Auth, token, password
│   │   ├── acl.py         # Access Control List
│   │   └── id_generator.py
│   ├── crypto/            # Kriptografi custom
│   │   ├── aes_custom.py  # AES-256 CTR manual
│   │   ├── key_derivation.py # PBKDF2
│   │   ├── key_wrapping.py# Envelope encryption: generate DEK, wrap/unwrap via KEK PBKDF2
│   │   └── utils.py       # Base64, XOR, padding
│   ├── db/                # Database
│   │   ├── database.py    # SQLite manager (+ tabel buckets & object_keys)
│   │   └── schema.sql
│   ├── api/               # REST API
│   │   ├── app.py
│   │   ├── dependencies.py
│   │   └── routes/
│   │       ├── auth.py
│   │       ├── objects.py # CRUD objek + share re-encryption, revoke, shares
│   │       ├── buckets.py # CRUD bucket & resolusi gs://bucket/obj
│   │       └── admin.py
│   ├── cli/               # Command Line Interface
│   │   ├── cli.py
│   │   ├── auth_commands.py
│   │   ├── object_commands.py
│   │   └── storage_commands.py  # mb, rb, ls, cp, rm, stat
│   └── storage/           # Penyimpanan fisik
│       ├── storage.txt
│       └── storage_manager.py
└── tests/                 # Pengujian
    ├── conftest.py        # Fixture isolasi DB in-memory & JWT secret
    ├── test_e2e.py          # Skenario dasar, bucket, re-encryption share
    └── test_versioning.py     # Versioning nyata: versi baru, list/download per versi, restore
```

## Keamanan & Catatan Penting

- **Custom Crypto hanya untuk edukasi**. Jangan gunakan di lingkungan produksi.
- Enkripsi end-to-end: server hanya menyimpan ciphertext, kunci ada di client.
- Token JWT menggunakan secret key yang diatur via `CLOUDSIM_JWT_SECRET` (default acak per proses). Untuk production, set secret key tetap.
- Nama bucket divalidasi (huruf kecil, angka, `-`, `.`, `_`) dan bucket tidak boleh dihapus selama masih berisi objek.
- **Sharing dengan re-encryption (key-wrapping + PBKDF2)** sudah tersedia: objek `--shareable` dienkripsi dengan DEK per-objek; setiap penerima mendapat wrapped key sendiri yang diturunkan dari passphrase pembagian (PBKDF2-HMAC-SHA256, 100.000 iterasi, salt acak per wrapping). Server tidak pernah menyimpan DEK dalam bentuk terbuka dan pembagian dapat dicabut individual lewat `revoke`.
- Batasan model keamanan edukatif: tidak ada tag integritas (mis. HMAC/GCM) pada ciphertext maupun wrapped key, sehingga passphrase yang salah secara praktis menghasilkan plaintext sampah alih-alih error eksplisit; `storage cp` ke/dari bucket mendukung mode shareable penuh (upload shareable via env `CLOUDSIM_SHARE_PASS`, unwrap saat download).

## Lisensi

Proyek ini dibuat untuk keperluan edukasi. Bebas digunakan dan dimodifikasi.

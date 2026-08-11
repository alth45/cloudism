

# CloudSim – Simulator Cloud Storage Lokal

CloudSim adalah simulator penyimpanan cloud berbasis Python yang meniru perilaku layanan cloud sungguhan (seperti AWS S3 atau Google Cloud Storage) secara lokal. Data disimpan dalam file `storage.txt` dengan format JSON per baris yang menyerupai metadata dan payload cloud asli. Proyek ini dibangun untuk **belajar mekanisme internal cloud**: penyimpanan objek, kontrol akses, enkripsi custom, dan manajemen perintah.

## Fitur Utama

- **Penyimpanan Objek** – Setiap file disimpan sebagai objek dengan ID unik, timestamp, dan payload terenkripsi.
- **Keamanan Custom** – Registrasi pengguna, autentikasi token JWT buatan sendiri, dan Access Control List (ACL) per objek.
- **Library Enkripsi Buatan** – Implementasi AES-256 mode CTR, PBKDF2 untuk derivasi kunci, dan Base64/PKCS7.
- **API REST** – Endpoint CRUD untuk objek, autentikasi, dan manajemen pengguna (FastAPI).
- **CLI Interaktif** – Perintah terminal seperti `upload`, `download`, `list`, `delete`, `share`.
- **Client-side Encryption** – File dienkripsi di sisi client sebelum dikirim ke server; server tidak pernah melihat plaintext.
- **Basis Data Metadata** – SQLite untuk menyimpan metadata objek, pengguna, dan ACL.
- **Append-only Storage** – Log immutable di `storage.txt` untuk mendukung versioning dan audit.


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
- **Core Engine** – Logika CRUD, enkripsi/dekripsi, ACL, generator ID.
- **API** – Lapisan HTTP dengan autentikasi Bearer token (JWT manual).
- **CLI** – Antarmuka terminal yang memanggil API dan menangani enkripsi lokal.
- **Database** – Metadata objek, pengguna, dan hak akses.
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

# Daftar objek yang bisa diakses
python -m cloudsim.cli.cli list

# Lihat metadata
python -m cloudsim.cli.cli info <object_id>

# Download & dekripsi
python -m cloudsim.cli.cli download <object_id> -o <output_file>

# Bagikan akses ke user lain
python -m cloudsim.cli.cli share <object_id> <username> --perm read

# Hapus objek (hanya owner)
python -m cloudsim.cli.cli delete <object_id>
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
```

## Pengujian

Proyek dilengkapi pengujian end-to-end menggunakan `pytest` dan `TestClient` dari FastAPI.

```bash
# Install dependensi pengujian (jika belum)
pip install pytest httpx

# Jalankan semua pengujian
python -m pytest tests/test_e2e.py -v
```

Pengujian mencakup:
- Registrasi dua user
- Upload dengan enkripsi client-side
- Verifikasi download & dekripsi
- Uji akses tanpa izin (ditolak)
- Sharing objek
- Dekripsi oleh user lain (harus gagal karena kunci berbeda)
- Penghapusan objek

## Struktur Direktori

```
cloudsim/
├── plan.md                # Rencana awal proyek
├── README.md              # Dokumentasi ini
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
│   │   └── utils.py       # Base64, XOR, padding
│   ├── db/                # Database
│   │   ├── database.py    # SQLite manager
│   │   └── schema.sql
│   ├── api/               # REST API
│   │   ├── app.py
│   │   ├── dependencies.py
│   │   └── routes/
│   │       ├── auth.py
│   │       ├── objects.py
│   │       └── admin.py
│   ├── cli/               # Command Line Interface
│   │   ├── cli.py
│   │   ├── auth_commands.py
│   │   └── object_commands.py
│   └── storage/           # Penyimpanan fisik
│       ├── storage.txt
│       └── storage_manager.py
└── tests/                 # Pengujian
    ├── conftest.py
    └── test_e2e.py
```

## Keamanan & Catatan Penting

- **Custom Crypto hanya untuk edukasi**. Jangan gunakan di lingkungan produksi.
- Enkripsi end-to-end: server hanya menyimpan ciphertext, kunci ada di client.
- Token JWT menggunakan secret key yang diatur via `CLOUDSIM_SECRET` (default acak). Untuk production, set secret key tetap.
- Sharing objek saat ini hanya memberikan akses ke metadata dan ciphertext; enkripsi ulang dengan kunci penerima belum diimplementasikan (pelajaran lanjutan).

## Lisensi

Proyek ini dibuat untuk keperluan edukasi. Bebas digunakan dan dimodifikasi.

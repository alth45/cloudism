
# Plan Command GCP – CloudSim CLI

## Tujuan
Membuat CLI CloudSim semirip mungkin dengan perintah **`gcloud storage`** milik Google Cloud, sehingga pengguna bisa belajar perintah cloud sungguhan tanpa perlu akun GCP. Semua fitur yang sudah ada (registrasi, enkripsi, ACL) tetap berjalan, ditambah dukungan bucket untuk mengelompokkan objek.

## Struktur Perintah
Mengikuti pola `gcloud storage <group> <command>`:
- `cloudsim auth` → Autentikasi (register, login, logout, whoami)
- `cloudsim storage` → Manajemen storage (bucket dan objek)

Alias pendek tetap disediakan untuk kenyamanan (tanpa subcommand).

---

## 1. Autentikasi (`cloudsim auth`)

| Perintah | Fungsi | Contoh |
|----------|--------|--------|
| `auth register` | Daftar user baru dan langsung login | `cloudsim auth register` (interaktif) |
| `auth login` | Login ke akun | `cloudsim auth login` |
| `auth whoami` | Tampilkan user login | `cloudsim auth whoami` |
| `auth logout` | Hapus sesi lokal | `cloudsim auth logout` |

> **Alias langsung:** `cloudsim login`, `cloudsim register`, `cloudsim whoami`, `cloudsim logout`

---

## 2. Manajemen Bucket (`cloudsim storage`)

| Perintah | Fungsi | Contoh |
|----------|--------|--------|
| `storage mb <bucket>` | Buat bucket baru (make bucket) | `cloudsim storage mb arsip` |
| `storage rb <bucket>` | Hapus bucket kosong (remove bucket) | `cloudsim storage rb arsip` |
| `storage ls [gs://bucket]` | List bucket atau isi bucket | `cloudsim storage ls` (list bucket)<br>`cloudsim storage ls gs://arsip` (list isi) |
| `storage du [gs://bucket[/obj]]` | Tampilkan ukuran total | `cloudsim storage du gs://arsip` |

---

## 3. Manajemen Objek (`cloudsim storage`)

| Perintah | Fungsi | Contoh |
|----------|--------|--------|
| `storage cp <src> <dst>` | Copy file (upload/download/antar bucket) | `cloudsim storage cp lokal.txt gs://arsip/`<br>`cloudsim storage cp gs://arsip/lokal.txt ./` |
| `storage rm <cloud_path>` | Hapus objek | `cloudsim storage rm gs://arsip/lokal.txt` |
| `storage mv <src> <dst>` | Pindah/rename objek | `cloudsim storage mv gs://arsip/a.txt gs://arsip/b.txt` |
| `storage cat <cloud_path>` | Tampilkan isi objek ke stdout | `cloudsim storage cat gs://arsip/data.txt` |
| `storage stat <cloud_path>` | Metadata objek | `cloudsim storage stat gs://arsip/foto.png` |
| `storage acl get <cloud_path>` | Lihat ACL objek | `cloudsim storage acl get gs://arsip/rahasia` |
| `storage acl set <cloud_path> --entity=USER:<email> --role=<ROLE>` | Set ACL objek | `cloudsim storage acl set gs://arsip/rahasia --entity=USER:budi --role=READER` |

> **Catatan:**  
> - `<cloud_path>` selalu dalam format `gs://<bucket>/<object>` atau `obj-...` (tanpa bucket).  
> - Untuk `cp` dan `mv`, jika sumber adalah lokal dan tujuan adalah `gs://`, maka upload; sebaliknya, download.  
> - `mv` bisa berupa rename dalam bucket yang sama (ganti nama file).  
> - Perintah `acl` menggunakan flag `--entity` dan `--role` mirip GCP asli.

---

## 4. Alias Langsung (tanpa `storage`)

| Alias | Setara dengan |
|-------|---------------|
| `cloudsim ls [gs://...]` | `cloudsim storage ls` |
| `cloudsim cp <src> <dst>` | `cloudsim storage cp` |
| `cloudsim rm <path>` | `cloudsim storage rm` |
| `cloudsim mv <src> <dst>` | `cloudsim storage mv` |
| `cloudsim cat <path>` | `cloudsim storage cat` |
| `cloudsim stat <path>` | `cloudsim storage stat` |
| `cloudsim acl <get/set> ...` | `cloudsim storage acl ...` |
| `cloudsim mb <bucket>` | `cloudsim storage mb` |
| `cloudsim rb <bucket>` | `cloudsim storage rb` |
| `cloudsim du [gs://...]` | `cloudsim storage du` |

---

## 5. Parsing Path `gs://`
- Format: `gs://<bucket>[/<object_name_or_id>]`
- Jika `<object>` diawali `obj-`, anggap sebagai object ID langsung.
- Jika bukan `obj-`, anggap sebagai nama file di bucket tersebut.
- API menyediakan endpoint untuk mencari objek berdasarkan `(bucket_id, filename)`.
- Untuk perintah `ls` tanpa path, tampilkan semua bucket milik user. Dengan path `gs://bucket`, tampilkan semua objek di bucket itu.

---

## 6. Endpoint API Baru yang Dibutuhkan
| Metode | Path | Deskripsi |
|--------|------|-----------|
| POST | `/buckets` | Buat bucket (body: `name`) |
| GET | `/buckets` | List bucket user |
| DELETE | `/buckets/{bucket_id}` | Hapus bucket (jika kosong) |
| GET | `/buckets/{bucket_id}` | Info bucket |
| GET | `/objects?bucket_id=...&filename=...` | Cari objek berdasarkan bucket dan nama |
| PUT | `/objects/{id}/move` | Pindah/rename objek (body: `new_bucket_id?`, `new_filename?`) |

---

## 7. Rencana Implementasi di CLI
1. Tambahkan modul `cloudsim/cli/storage_commands.py` (sudah ada) dengan semua command di atas.
2. Update `cli.py` untuk mendaftarkan command-command baru.
3. Buat helper `parse_cloud_path(path)` → `(bucket, object)`.
4. Gunakan API request untuk resolve nama bucket ke ID (cache di sesi?).
5. Untuk `cp`/`mv`, deteksi apakah source/destination lokal atau cloud.
6. Untuk `acl`, gunakan flag `--entity` dan `--role` (pakai `typer.Option`).

---

## 8. Contoh Sesi Penuh
```bash
# Buat bucket
cloudsim mb proyek

# Upload
cloudsim cp laporan.pdf gs://proyek/

# Lihat isi
cloudsim ls gs://proyek
# gs://proyek/laporan.pdf   obj-abc...   2048 bytes

# Tampilkan isi file teks
cloudsim cat gs://proyek/readme.txt

# Statistik
cloudsim stat gs://proyek/laporan.pdf

# Ubah ACL
cloudsim acl set gs://proyek/laporan.pdf --entity=USER:budi --role=WRITER

# Pindahkan/rename
cloudsim mv gs://proyek/laporan.pdf gs://proyek/laporan-final.pdf

# Hapus objek
cloudsim rm gs://proyek/laporan-final.pdf

# Hapus bucket (harus kosong)
cloudsim rb proyek
```

Dengan mengikuti rencana ini, CloudSim akan terasa seperti laboratorium Google Cloud Storage yang sesungguhnya.


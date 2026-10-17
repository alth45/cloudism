import sqlite3
import os
from typing import Optional, List, Tuple

class DatabaseManager:
    """Mengelola koneksi dan operasi database SQLite."""
    
    def __init__(self, db_path: str = None):
        if db_path is None:
            # Default: simpan di folder data/ dalam project
            base_dir = os.path.dirname(os.path.abspath(__file__))
            data_dir = os.path.join(base_dir, "..", "data")
            os.makedirs(data_dir, exist_ok=True)
            db_path = os.path.join(data_dir, "cloudsim.db")
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row  # supaya hasil query seperti dict
        self.conn.execute("PRAGMA foreign_keys = ON")
        self._init_schema()

    def _init_schema(self):
        """Jalankan schema.sql untuk membuat tabel jika belum ada."""
        schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
        with open(schema_path, "r") as f:
            sql = f.read()
        # Aktifkan sementara pelemahan FK agar migrasi tabel lama berjalan lancar
        self.conn.execute("PRAGMA foreign_keys = OFF")
        self._migrate_legacy_schema()
        self.conn.executescript(sql)
        # Tambahkan kolom bucket_id pada tabel objects untuk database yang sudah ada.
        # SQLite tidak mendukung IF NOT EXISTS pada ALTER TABLE, jadi tangkap error.
        try:
            self.conn.execute(
                "ALTER TABLE objects ADD COLUMN bucket_id TEXT "
                "REFERENCES buckets(id) ON DELETE SET NULL"
            )
        except sqlite3.OperationalError:
            pass  # kolom sudah ada, lewati
        # Pastikan indeks bucket ada (untuk database yang sudah ada sebelum schema.sql diperbarui)
        try:
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_objects_bucket ON objects(bucket_id)")
        except sqlite3.OperationalError:
            pass
        # Kolom flag versi aktif pada tabel objects (untuk DB lama tanpa versioning).
        try:
            self.conn.execute(
                "ALTER TABLE objects ADD COLUMN current_version_id TEXT"
            )
        except sqlite3.OperationalError:
            pass  # kolom sudah ada, lewati
        self.conn.commit()
        self.conn.execute("PRAGMA foreign_keys = ON")

    def _migrate_legacy_schema(self):
        """Migrasi database lama: bangun ulang tabel `objects` tanpa kolom bucket_id
        agar schema.sql baru (yang membuat tabel dengan bucket_id) bisa diterapkan.
        Data objek tetap dipertahankan; bucket_id diisi NULL."""
        cur = self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='objects'"
        )
        if not cur.fetchone():
            return  # database baru, tidak perlu migrasi
        cols = [r[1] for r in self.conn.execute("PRAGMA table_info(objects)").fetchall()]
        if "bucket_id" in cols:
            return  # sudah bermigrasi
        # current_version_id hanya ada di schema baru; jangan ikut terbawa
        cols = [c for c in cols if c != "current_version_id"]
        legacy_select = ", ".join(
            c for c in ("id", "owner_id", "filename", "size", "mime_type",
                        "encrypted_payload", "iv", "nonce", "created_at",
                        "updated_at", "storage_line", "is_public")
            if c in cols
        ) or "id, owner_id, filename, size"
        self.conn.executescript(
            """
            PRAGMA legacy_alter_table = ON;
            DROP TABLE IF EXISTS objects_old;
            ALTER TABLE objects RENAME TO objects_old;
            """
        )
        # Buat ulang sesuai definisi baru di schema.sql (diambil dari file yang sama)
        self._create_objects_table_from_schema()
        self.conn.execute(
            f"""INSERT INTO objects ({legacy_select})
                SELECT {legacy_select} FROM objects_old"""
        )
        self.conn.execute("DROP TABLE objects_old")
        self.conn.execute("PRAGMA legacy_alter_table = OFF")
        self.conn.commit()

    def _create_objects_table_from_schema(self):
        """Ambil pernyataan CREATE TABLE objects dari schema.sql dan jalankan."""
        import re
        schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
        with open(schema_path, "r") as f:
            sql = f.read()
        m = re.search(r"CREATE TABLE IF NOT EXISTS objects \(.*?\);", sql, re.S)
        if m:
            self.conn.executescript(m.group(0))
    
    def close(self):
        self.conn.close()
    
    # ==================== USERS ====================
    def create_user(self, user_id: str, username: str, password_hash: str, 
                    password_salt: str, key_salt: str, role: str = "user") -> bool:
        try:
            self.conn.execute(
                "INSERT INTO users (id, username, password_hash, password_salt, key_salt, role) VALUES (?, ?, ?, ?, ?, ?)",
                (user_id, username, password_hash, password_salt, key_salt, role)
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False  # username sudah ada
    
    def get_user_by_username(self, username: str) -> Optional[sqlite3.Row]:
        cur = self.conn.execute("SELECT * FROM users WHERE username = ?", (username,))
        return cur.fetchone()
    
    def get_user_by_id(self, user_id: str) -> Optional[sqlite3.Row]:
        cur = self.conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        return cur.fetchone()
    
    def user_exists(self, username: str) -> bool:
        cur = self.conn.execute("SELECT 1 FROM users WHERE username = ?", (username,))
        return cur.fetchone() is not None
    
    # ==================== OBJECTS ====================
    def create_object(self, obj_id: str, owner_id: str, filename: str, size: int,
                      mime_type: str, encrypted_payload: str, iv: str, nonce: str,
                      created_at: str, is_public: bool = False, bucket_id: str = None) -> bool:
        try:
            self.conn.execute(
                """INSERT INTO objects (id, owner_id, filename, size, mime_type, encrypted_payload, iv, nonce, 
                   created_at, is_public, bucket_id) 
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (obj_id, owner_id, filename, size, mime_type, encrypted_payload, iv, nonce, 
                 created_at, 1 if is_public else 0, bucket_id)
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
    
    def get_object_by_id(self, obj_id: str) -> Optional[sqlite3.Row]:
        # Sertakan kolom `version` dari versi current (flag versioning nyata).
        cur = self.conn.execute(
            "SELECT o.*, COALESCE(cv.version, 1) AS version FROM objects o "
            "LEFT JOIN object_versions cv ON cv.object_id = o.id AND cv.is_current = 1 "
            "WHERE o.id = ?", (obj_id,))
        return cur.fetchone()
    
    def get_objects_by_owner(self, owner_id: str) -> List[sqlite3.Row]:
        cur = self.conn.execute("SELECT * FROM objects WHERE owner_id = ? ORDER BY created_at DESC", (owner_id,))
        return cur.fetchall()
    
    def get_public_objects(self) -> List[sqlite3.Row]:
        cur = self.conn.execute("SELECT * FROM objects WHERE is_public = 1 ORDER BY created_at DESC")
        return cur.fetchall()
    
    def get_objects_shared_with(self, user_id: str) -> List[sqlite3.Row]:
        """Ambil objek yang dibagikan ke user_id melalui ACL."""
        cur = self.conn.execute(
            """SELECT o.* FROM objects o 
               JOIN acl a ON o.id = a.object_id 
               WHERE a.user_id = ? 
               ORDER BY o.created_at DESC""",
            (user_id,)
        )
        return cur.fetchall()
    
    def update_object_public(self, obj_id: str, is_public: bool):
        self.conn.execute("UPDATE objects SET is_public = ? WHERE id = ?", (1 if is_public else 0, obj_id))
        self.conn.commit()
    
    def delete_object(self, obj_id: str) -> bool:
        cur = self.conn.execute("DELETE FROM objects WHERE id = ?", (obj_id,))
        self.conn.commit()
        return cur.rowcount > 0

    def list_accessible_objects(self, user_id: str, bucket_id: str = None) -> List[sqlite3.Row]:
        """Gabungan milik sendiri, publik, dan yang di-share.
        Jika bucket_id diberikan, filter hanya objek pada bucket tersebut."""
        # Bangun subquery secara eksplisit agar urutan binding mudah dibaca
        subs, params = [], []
        # Snapshot versi current untuk kolom `version` + flag current_version_id
        cv_join = ("LEFT JOIN object_versions cv ON cv.object_id = objects.id"
                   " AND cv.is_current = 1")
        if bucket_id is not None:
            subs.append(f"SELECT objects.*, COALESCE(cv.version, 1) AS version FROM objects {cv_join} WHERE owner_id = ? AND bucket_id = ?")
            params += [user_id, bucket_id]
            subs.append(f"SELECT objects.*, COALESCE(cv.version, 1) AS version FROM objects {cv_join} WHERE is_public = 1 AND bucket_id = ?")
            params += [bucket_id]
            subs.append(
                f"SELECT objects.*, COALESCE(cv.version, 1) AS version FROM objects "
                f"JOIN acl a ON objects.id = a.object_id {cv_join}"
                " WHERE a.user_id = ? AND objects.bucket_id = ?"
            )
            params += [user_id, bucket_id]
        else:
            subs.append(f"SELECT objects.*, COALESCE(cv.version, 1) AS version FROM objects {cv_join} WHERE owner_id = ?")
            params.append(user_id)
            subs.append(f"SELECT objects.*, COALESCE(cv.version, 1) AS version FROM objects {cv_join} WHERE is_public = 1")
            subs.append(f"SELECT objects.*, COALESCE(cv.version, 1) AS version FROM objects "
                        f"JOIN acl a ON objects.id = a.object_id {cv_join} WHERE a.user_id = ?")
            params.append(user_id)
        sql = "SELECT * FROM (" + " UNION ".join(subs) + ") ORDER BY created_at DESC"
        cur = self.conn.execute(sql, tuple(params))
        return cur.fetchall()

    def get_object_by_name_in_bucket(self, bucket_id: str, filename: str) -> Optional[sqlite3.Row]:
        """Cari objek berdasarkan nama file di dalam sebuah bucket (ambil terbaru)."""
        cur = self.conn.execute(
            "SELECT * FROM objects WHERE bucket_id = ? AND filename = ? ORDER BY created_at DESC LIMIT 1",
            (bucket_id, filename)
        )
        return cur.fetchone()

    def find_accessible_object_by_name(self, user_id: str, bucket_id: str, identifier: str) -> Optional[sqlite3.Row]:
        """Cari objek yang bisa diakses user di dalam bucket berdasarkan ID atau nama file.
        Identifier yang dimulai 'obj-' dianggap ID objek; selain itu dicari sebagai nama file."""
        if identifier.startswith("obj-"):
            obj = self.get_object_by_id(identifier)
            if obj and obj["bucket_id"] == bucket_id and self.check_access(identifier, user_id, "read"):
                return obj
            return None
        # Cari sebagai nama file pada objek yang bisa diakses user di bucket ini
        subs, params = [], []
        if bucket_id is not None:
            subs.append("SELECT objects.*, COALESCE(cv.version, 1) AS version FROM objects "
                        "LEFT JOIN object_versions cv ON cv.object_id = objects.id AND cv.is_current = 1 "
                        "WHERE owner_id = ? AND bucket_id = ?")
            params += [user_id, bucket_id]
            subs.append("SELECT objects.*, COALESCE(cv.version, 1) AS version FROM objects "
                        "LEFT JOIN object_versions cv ON cv.object_id = objects.id AND cv.is_current = 1 "
                        "WHERE is_public = 1 AND bucket_id = ?")
            params += [bucket_id]
            subs.append(
                "SELECT objects.*, COALESCE(cv.version, 1) AS version FROM objects "
                "JOIN acl a ON objects.id = a.object_id "
                "LEFT JOIN object_versions cv ON cv.object_id = objects.id AND cv.is_current = 1 "
                "WHERE a.user_id = ? AND objects.bucket_id = ?"
            )
            params += [user_id, bucket_id]
        else:
            subs.append("SELECT objects.*, COALESCE(cv.version, 1) AS version FROM objects "
                        "LEFT JOIN object_versions cv ON cv.object_id = objects.id AND cv.is_current = 1 "
                        "WHERE owner_id = ?")
            params.append(user_id)
            subs.append("SELECT objects.*, COALESCE(cv.version, 1) AS version FROM objects "
                        "LEFT JOIN object_versions cv ON cv.object_id = objects.id AND cv.is_current = 1 "
                        "WHERE is_public = 1")
            subs.append("SELECT objects.*, COALESCE(cv.version, 1) AS version FROM objects "
                        "JOIN acl a ON objects.id = a.object_id "
                        "LEFT JOIN object_versions cv ON cv.object_id = objects.id AND cv.is_current = 1 "
                        "WHERE a.user_id = ?")
            params.append(user_id)
        params.append(identifier)
        sql = ("SELECT * FROM (" + " UNION ".join(subs) + ") AS t WHERE filename = ?"
               " ORDER BY created_at DESC LIMIT 1")
        cur = self.conn.execute(sql, tuple(params))
        return cur.fetchone()

    # ==================== BUCKETS ====================
    def create_bucket(self, bucket_id: str, name: str, owner_id: str, created_at: str) -> bool:
        try:
            self.conn.execute(
                "INSERT INTO buckets (id, name, owner_id, created_at) VALUES (?, ?, ?, ?)",
                (bucket_id, name, owner_id, created_at)
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False  # nama sudah ada

    def get_bucket_by_id(self, bucket_id: str) -> Optional[sqlite3.Row]:
        cur = self.conn.execute("SELECT * FROM buckets WHERE id = ?", (bucket_id,))
        return cur.fetchone()

    def get_bucket_by_name(self, name: str) -> Optional[sqlite3.Row]:
        cur = self.conn.execute("SELECT * FROM buckets WHERE name = ?", (name,))
        return cur.fetchone()

    def get_buckets_by_owner(self, owner_id: str) -> List[sqlite3.Row]:
        cur = self.conn.execute(
            "SELECT * FROM buckets WHERE owner_id = ? ORDER BY created_at DESC",
            (owner_id,)
        )
        return cur.fetchall()

    def count_objects_in_bucket(self, bucket_id: str) -> int:
        cur = self.conn.execute("SELECT COUNT(*) as cnt FROM objects WHERE bucket_id = ?", (bucket_id,))
        row = cur.fetchone()
        return row["cnt"] if row else 0

    def get_bucket_objects(self, bucket_id: str) -> List[sqlite3.Row]:
        """Daftar semua objek (yang visible) di dalam sebuah bucket."""
        cur = self.conn.execute(
            "SELECT * FROM objects WHERE bucket_id = ? ORDER BY created_at DESC",
            (bucket_id,)
        )
        return cur.fetchall()

    def delete_bucket(self, bucket_id: str, owner_id: str) -> bool:
        """Hapus bucket jika kosong dan user adalah pemiliknya."""
        bucket = self.get_bucket_by_id(bucket_id)
        if not bucket:
            return False
        if bucket["owner_id"] != owner_id:
            return False  # bukan pemilik
        if self.count_objects_in_bucket(bucket_id) > 0:
            return False  # bucket tidak kosong
        cur = self.conn.execute("DELETE FROM buckets WHERE id = ?", (bucket_id,))
        self.conn.commit()
        return cur.rowcount > 0

    
    # ==================== OBJECT KEYS (key-wrapping / re-encryption) ====================
    def set_object_key(self, object_id: str, user_id: str, wrapped_key: str,
                       wrap_nonce: str, wrap_salt: str, iterations: int,
                       created_at: str) -> bool:
        """Simpan/perbarui DEK ter-bungkus untuk satu pasangan (objek, pengguna)."""
        try:
            self.conn.execute(
                """INSERT OR REPLACE INTO object_keys
                   (object_id, user_id, wrapped_key, wrap_nonce, wrap_salt, iterations, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (object_id, user_id, wrapped_key, wrap_nonce, wrap_salt, iterations, created_at)
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def get_object_key(self, object_id: str, user_id: str) -> Optional[sqlite3.Row]:
        cur = self.conn.execute(
            "SELECT * FROM object_keys WHERE object_id = ? AND user_id = ?",
            (object_id, user_id)
        )
        return cur.fetchone()

    def list_object_keys(self, object_id: str) -> List[sqlite3.Row]:
        cur = self.conn.execute(
            "SELECT * FROM object_keys WHERE object_id = ? ORDER BY created_at DESC",
            (object_id,)
        )
        return cur.fetchall()

    def delete_object_keys(self, object_id: str) -> int:
        """Hapus semua wrapped key milik sebuah objek. Mengembalikan jumlah baris terhapus."""
        cur = self.conn.execute("DELETE FROM object_keys WHERE object_id = ?", (object_id,))
        self.conn.commit()
        return cur.rowcount

    # ==================== OBJECT VERSIONS (versioning nyata) ====================
    def find_object_for_versioning(self, owner_id: str, filename: str,
                                   bucket_id: str = None) -> Optional[sqlite3.Row]:
        """Cari objek existing milik owner dengan nama & bucket yang sama.
        Dipakai untuk auto-versioning: upload ulang = versi baru objek yang sama."""
        if bucket_id is None:
            cur = self.conn.execute(
                "SELECT * FROM objects WHERE owner_id = ? AND filename = ? AND bucket_id IS NULL "
                "ORDER BY created_at DESC LIMIT 1",
                (owner_id, filename)
            )
        else:
            cur = self.conn.execute(
                "SELECT * FROM objects WHERE owner_id = ? AND filename = ? AND bucket_id = ? "
                "ORDER BY created_at DESC LIMIT 1",
                (owner_id, filename, bucket_id)
            )
        return cur.fetchone()

    def next_version_number(self, object_id: str) -> int:
        cur = self.conn.execute(
            "SELECT COALESCE(MAX(version), 0) AS maxv FROM object_versions WHERE object_id = ?",
            (object_id,)
        )
        row = cur.fetchone()
        return (row["maxv"] if row else 0) + 1

    def create_object_version(self, version_id: str, object_id: str, version: int,
                              filename: str, mime_type: str, size: int,
                              encrypted_payload: str, nonce: str,
                              created_at: str, created_by: str,
                              storage_line: int = None) -> bool:
        try:
            self.conn.execute(
                """INSERT INTO object_versions
                   (version_id, object_id, version, filename, mime_type, size,
                    encrypted_payload, nonce, created_at, created_by, is_current, storage_line)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)""",
                (version_id, object_id, version, filename, mime_type, size,
                 encrypted_payload, nonce, created_at, created_by, storage_line)
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def set_current_version(self, object_id: str, version_id: str) -> bool:
        """Pindahkan flag is_current ke satu versi, dan update pointer objects.current_version_id."""
        self.conn.execute("UPDATE object_versions SET is_current = 0 WHERE object_id = ?", (object_id,))
        cur = self.conn.execute("UPDATE object_versions SET is_current = 1 WHERE version_id = ?", (version_id,))
        self.conn.execute("UPDATE objects SET current_version_id = ? WHERE id = ?", (version_id, object_id))
        self.conn.commit()
        return cur.rowcount > 0

    def get_object_version(self, version_id: str) -> Optional[sqlite3.Row]:
        cur = self.conn.execute("SELECT * FROM object_versions WHERE version_id = ?", (version_id,))
        return cur.fetchone()

    def list_object_versions(self, object_id: str) -> List[sqlite3.Row]:
        cur = self.conn.execute(
            "SELECT * FROM object_versions WHERE object_id = ? ORDER BY version DESC",
            (object_id,)
        )
        return cur.fetchall()

    def count_object_versions(self, object_id: str) -> int:
        cur = self.conn.execute(
            "SELECT COUNT(*) AS cnt FROM object_versions WHERE object_id = ?", (object_id,)
        )
        row = cur.fetchone()
        return row["cnt"] if row else 0

    def update_object_payload(self, obj_id: str, encrypted_payload: str, nonce: str,
                              size: int, mime_type: str, updated_at: str,
                              storage_line: int = None):
        """Update baris objects agar selalu mencerminkan versi current."""
        self.conn.execute(
            """UPDATE objects SET encrypted_payload = ?, nonce = ?, size = ?,
               mime_type = ?, updated_at = ?, storage_line = ? WHERE id = ?""",
            (encrypted_payload, nonce, size, mime_type, updated_at, storage_line, obj_id)
        )
        self.conn.commit()

    # ==================== ACL ====================
    def set_acl(self, object_id: str, user_id: str, permission: str = "read") -> bool:
        try:
            self.conn.execute(
                "INSERT OR REPLACE INTO acl (object_id, user_id, permission) VALUES (?, ?, ?)",
                (object_id, user_id, permission)
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
    
    def get_acl(self, object_id: str, user_id: str) -> Optional[str]:
        """Dapatkan permission untuk user pada objek."""
        cur = self.conn.execute(
            "SELECT permission FROM acl WHERE object_id = ? AND user_id = ?",
            (object_id, user_id)
        )
        row = cur.fetchone()
        return row["permission"] if row else None
    
    def get_object_acl_all(self, object_id: str) -> List[sqlite3.Row]:
        cur = self.conn.execute("SELECT * FROM acl WHERE object_id = ?", (object_id,))
        return cur.fetchall()
    
    def remove_acl(self, object_id: str, user_id: str) -> bool:
        cur = self.conn.execute("DELETE FROM acl WHERE object_id = ? AND user_id = ?", (object_id, user_id))
        self.conn.commit()
        return cur.rowcount > 0
    
    def check_access(self, object_id: str, user_id: str, required_perm: str = "read") -> bool:
        """Cek apakah user punya akses required_perm ke objek. 
        Owner = admin penuh. Public = read untuk semua. ACL permission diperhitungkan."""
        obj = self.get_object_by_id(object_id)
        if obj is None:
            return False
        # Owner
        if obj["owner_id"] == user_id:
            return True
        # Public read
        if obj["is_public"] and required_perm == "read":
            return True
        # ACL
        acl_perm = self.get_acl(object_id, user_id)
        if acl_perm:
            if acl_perm == "admin":
                return True
            if required_perm == "read" and acl_perm in ("read", "write"):
                return True
            if required_perm == "write" and acl_perm == "write":
                return True
        return False

# Singleton database.
# Dukungan override untuk pengujian: set environment variable
# CLOUDSIM_DB_PATH=":memory:" sebelum modul diimpor agar seluruh proses
# (termasuk plugin pytest global yang mengimpor app lebih dulu) memakai
# database in-memory, bukan file cloudsim.db permanen.
_DEFAULT_DB_PATH = os.environ.get("CLOUDSIM_DB_PATH")

if _DEFAULT_DB_PATH == ":memory:":
    db = DatabaseManager(":memory:")
elif _DEFAULT_DB_PATH:
    os.makedirs(os.path.dirname(os.path.abspath(_DEFAULT_DB_PATH)), exist_ok=True)
    db = DatabaseManager(_DEFAULT_DB_PATH)
else:
    db = DatabaseManager()
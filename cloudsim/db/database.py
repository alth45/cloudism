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
        cur = self.conn.execute("SELECT * FROM objects WHERE id = ?", (obj_id,))
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
        if bucket_id is not None:
            subs.append("SELECT * FROM objects WHERE owner_id = ? AND bucket_id = ?")
            params += [user_id, bucket_id]
            subs.append("SELECT * FROM objects WHERE is_public = 1 AND bucket_id = ?")
            params += [bucket_id]
            subs.append(
                "SELECT o.* FROM objects o JOIN acl a ON o.id = a.object_id"
                " WHERE a.user_id = ? AND o.bucket_id = ?"
            )
            params += [user_id, bucket_id]
        else:
            subs.append("SELECT * FROM objects WHERE owner_id = ?")
            params.append(user_id)
            subs.append("SELECT * FROM objects WHERE is_public = 1")
            subs.append("SELECT o.* FROM objects o JOIN acl a ON o.id = a.object_id WHERE a.user_id = ?")
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
            subs.append("SELECT * FROM objects WHERE owner_id = ? AND bucket_id = ?")
            params += [user_id, bucket_id]
            subs.append("SELECT * FROM objects WHERE is_public = 1 AND bucket_id = ?")
            params += [bucket_id]
            subs.append(
                "SELECT o.* FROM objects o JOIN acl a ON o.id = a.object_id"
                " WHERE a.user_id = ? AND o.bucket_id = ?"
            )
            params += [user_id, bucket_id]
        else:
            subs.append("SELECT * FROM objects WHERE owner_id = ?")
            params.append(user_id)
            subs.append("SELECT * FROM objects WHERE is_public = 1")
            subs.append("SELECT o.* FROM objects o JOIN acl a ON o.id = a.object_id WHERE a.user_id = ?")
            params.append(user_id)
        params.append(identifier)
        sql = ("SELECT * FROM (" + " UNION ".join(subs) + ") WHERE filename = ?"
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

# Singleton database
db = DatabaseManager()
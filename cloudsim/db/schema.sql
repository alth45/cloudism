-- CloudSim Database Schema
-- Bucket (logical container for objects, mimicking GCS buckets)
CREATE TABLE IF NOT EXISTS buckets (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    owner_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);
-- Indeks untuk pencarian bucket
CREATE INDEX IF NOT EXISTS idx_buckets_owner ON buckets(owner_id);

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    key_salt TEXT NOT NULL,
    -- salt untuk derivasi kunci enkripsi pengguna
    role TEXT DEFAULT 'user' -- 'user' atau 'admin'
);
CREATE TABLE IF NOT EXISTS objects (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    filename TEXT NOT NULL,
    size INTEGER NOT NULL,
    mime_type TEXT DEFAULT 'application/octet-stream',
    encrypted_payload TEXT NOT NULL,
    -- base64 payload terenkripsi
    iv TEXT NOT NULL,
    -- initialization vector (base64)
    nonce TEXT NOT NULL,
    -- nonce untuk mode CTR (base64)
    created_at TEXT NOT NULL,
    updated_at TEXT,
    storage_line INTEGER,
    -- baris di storage.txt (opsional)
        is_public INTEGER DEFAULT 0,
    -- 0 = private, 1 = public
    bucket_id TEXT,
    -- wadah logis (FK ke buckets.id; NULL = objek tanpa bucket)
    current_version_id TEXT,
    -- pointer ke versi aktif (object_versions.version_id); diisi via migrasi ALTER untuk DB lama
    status TEXT NOT NULL DEFAULT 'active',
    -- 'active' | 'trashed' (soft delete; 'deleted' = hard delete langsung dari purge)
    trashed_at TEXT,
    -- ISO timestamp saat masuk trash (NULL jika belum pernah ditrash)
    purge_after TEXT,
    -- ISO timestamp batas retensi; setelah ini objek di-purge otomatis
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (bucket_id) REFERENCES buckets(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_objects_status ON objects(status);
CREATE TABLE IF NOT EXISTS acl (
    object_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    permission TEXT NOT NULL,
    -- 'read', 'write', 'admin'
    PRIMARY KEY (object_id, user_id),
    FOREIGN KEY (object_id) REFERENCES objects(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
-- Indeks untuk pencarian cepat
CREATE INDEX IF NOT EXISTS idx_objects_owner ON objects(owner_id);
CREATE INDEX IF NOT EXISTS idx_objects_public ON objects(is_public);
CREATE INDEX IF NOT EXISTS idx_objects_bucket ON objects(bucket_id);
CREATE INDEX IF NOT EXISTS idx_acl_object ON acl(object_id);
CREATE INDEX IF NOT EXISTS idx_acl_user ON acl(user_id);
-- Kunci objek ter-bungkus (re-encryption via key-wrapping/PBKDF2).
-- Setiap baris = satu DEK yang di-wrap memakai KEK turunan passphrase
-- pembagian, khusus untuk satu pengguna (recipient).
CREATE TABLE IF NOT EXISTS object_keys (
    object_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    wrapped_key TEXT NOT NULL,   -- DEK terenkripsi AES-256-CTR (base64)
    wrap_nonce TEXT NOT NULL,    -- nonce CTR untuk wrapping (base64)
    wrap_salt TEXT NOT NULL,     -- salt PBKDF2 (hex)
    iterations INTEGER NOT NULL DEFAULT 100000,
    created_at TEXT NOT NULL,
    PRIMARY KEY (object_id, user_id),
    FOREIGN KEY (object_id) REFERENCES objects(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_object_keys_user ON object_keys(user_id);
-- Versioning nyata per objek. Setiap upload/restore menambah baris versi baru
-- yang immutable; objects.current_version_id adalah flag versi aktif.
CREATE TABLE IF NOT EXISTS object_versions (
    version_id TEXT PRIMARY KEY,          -- ver-{12 hex}, flag identitas versi
    object_id TEXT NOT NULL,              -- objek induk
    version INTEGER NOT NULL,             -- nomor urut versi (1, 2, 3, ...)
    filename TEXT NOT NULL,
    mime_type TEXT DEFAULT 'application/octet-stream',
    size INTEGER NOT NULL,                -- ukuran payload base64
    encrypted_payload TEXT NOT NULL,      -- snapshot ciphertext versi ini
    nonce TEXT NOT NULL,                  -- nonce CTR versi ini
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,             -- user pembuat versi
    is_current INTEGER NOT NULL DEFAULT 0,-- 1 = versi aktif objek
    storage_line INTEGER,                 -- baris di storage.txt (append-only)
    UNIQUE (object_id, version),
    FOREIGN KEY (object_id) REFERENCES objects(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_object_versions_object ON object_versions(object_id);
CREATE INDEX IF NOT EXISTS idx_object_versions_current ON object_versions(object_id, is_current);
-- Audit log: catatan append-only "siapa melakukan apa terhadap objek mana, kapan".
-- actor_type: 'user' (terautentikasi), 'system' (mis. auto-purge), 'anonymous' (login gagal).
-- result: 'success' | 'denied' | 'failed'. Sumber kebenaran = tabel ini; salinan
-- immutable juga ditulis ke storage.txt (baris {"audit": ...}) sebagai jejak eksternal.
CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,              -- log-{12 hex}
    timestamp TEXT NOT NULL,          -- ISO 8601 UTC (kapan)
    actor_id TEXT,                    -- siapa: user_id (NULL utk system/anonymous)
    actor_username TEXT,              -- denormalisasi agar tetap terbaca meski user dihapus
    action TEXT NOT NULL,             -- apa: auth.login, object.upload, dst.
    resource_type TEXT NOT NULL,      -- 'object' | 'bucket' | 'auth'
    resource_id TEXT,                 -- obj-/bkt-... yang dikenai aksi
    resource_name TEXT,               -- nama file/bucket saat kejadian
    details TEXT,                     -- JSON: konteks tambahan (version, permission, ...)
    result TEXT NOT NULL DEFAULT 'success',
    source TEXT                       -- asal permintaan (IP client / 'cli')
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_resource ON audit_log(resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);

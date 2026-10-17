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
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (bucket_id) REFERENCES buckets(id) ON DELETE SET NULL
);
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
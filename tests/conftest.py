# pyrefly: ignore [missing-import]
"""Fixture pengujian dengan isolasi total.

Masalah yang diselesaikan:
1. Konflik secret key JWT — plugin pytest global dapat mengimpor aplikasi
   lebih dulu, sehingga singleton `auth_manager` memakai secret acak dan
   token hasil registrasi gagal diverifikasi. Solusi: secret key dibaca dari
   environment variable (lihat cloudsim/core/security.py) dan fixture ini
   selalu menyelaraskannya sebelum TestClient dibuat.
2. Kontaminasi database — singleton `db` membuka file cloudsim.db permanen
   sehingga user dari tes sebelumnya ikut terbawa ("Username sudah
   terdaftar"). Solusi: setiap tes mendapat DatabaseManager(":memory:") baru
   yang dipasang ke SEMUA modul yang menyimpan referensi `db`.
"""
import importlib
import sys

import pytest

TEST_JWT_SECRET = "test-secret-key-e2e"


def _db_dependents():
    """Semua modul cloudsim yang menyimpan atribut `db` (singleton)."""
    return [m for name, m in list(sys.modules.items())
            if name.startswith("cloudsim") and hasattr(m, "db")]


@pytest.fixture
def test_db():
    """Database SQLite in-memory baru, dipasang ke seluruh modul dependensi."""
    # importlib.import_module dipakai alih-alih `import a.b.c as x` karena
    # beberapa plugin pytest membuat entri sys.modules dengan __name__ tidak
    # konsisten sehingga sintaks `as` gagal di pytest 9.
    db_module = importlib.import_module("cloudsim.db.database")

    original = db_module.db
    db = db_module.DatabaseManager(":memory:")
    db_module.db = db
    # Selaraskan semua modul yang sudah mengimpor `db` (termasuk yang dimuat
    # lebih awal oleh plugin global).
    for mod in _db_dependents():
        mod.db = db
    yield db
    db_module.db = original
    for mod in _db_dependents():
        mod.db = original


@pytest.fixture
def client(test_db):
    """Buat TestClient FastAPI dengan secret key tetap & DB in-memory bersih."""
    sec_mod = importlib.import_module("cloudsim.core.security")
    sec_mod.auth_manager.secret_key = TEST_JWT_SECRET

    app = importlib.import_module("cloudsim.api.app").app
    # pyrefly: ignore [missing-import]
    from fastapi.testclient import TestClient

    with TestClient(app) as c:
        yield c

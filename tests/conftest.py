# pyrefly: ignore [missing-import]
import pytest
from cloudsim.db.database import DatabaseManager
from cloudsim.core.security import auth_manager
import cloudsim.db.database as db_module  # untuk override singleton

@pytest.fixture
def test_db():
    """Ganti database singleton dengan SQLite in-memory untuk testing."""
    # Simpan referensi database asli
    original_db = db_module.db
    # Buat database in-memory
    db = DatabaseManager(":memory:")
    db_module.db = db
    # Override juga di modul yang sudah mengimpor db
    import cloudsim.core.engine
    cloudsim.core.engine.db = db
    import cloudsim.api.routes.objects
    cloudsim.api.routes.objects.db = db
    import cloudsim.api.dependencies
    cloudsim.api.dependencies.db = db
    yield db
    # Kembalikan database asli
    db_module.db = original_db
    cloudsim.core.engine.db = original_db
    cloudsim.api.routes.objects.db = original_db
    cloudsim.api.dependencies.db = original_db

@pytest.fixture
def client(test_db):
    """Buat TestClient FastAPI dengan secret key tetap."""
    auth_manager.secret_key = "test-secret-key-e2e"
    from cloudsim.api.app import app
    # pyrefly: ignore [missing-import]
    from fastapi.testclient import TestClient
    with TestClient(app) as c:
        yield c
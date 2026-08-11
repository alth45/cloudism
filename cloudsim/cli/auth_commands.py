"""Perintah terkait autentikasi."""
import os
import json
import typer
import requests
from getpass import getpass
from cloudsim.crypto.key_derivation import pbkdf2_sha256

app = typer.Typer(help="Autentikasi")

CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".cloudsim")
CONFIG_FILE = os.path.join(CONFIG_DIR, "session.json")
API_BASE = os.environ.get("CLOUDSIM_API", "http://127.0.0.1:8000")

def ensure_config_dir():
    os.makedirs(CONFIG_DIR, exist_ok=True)

def derive_encryption_key(password: str, key_salt_hex: str) -> bytes:
    """Turunkan kunci enkripsi AES-256 dari password dan salt."""
    key_salt = bytes.fromhex(key_salt_hex)
    return pbkdf2_sha256(password, key_salt, iterations=100000, dklen=32)

def save_session(token: str, user_id: str, username: str, encryption_key: bytes, key_salt: str):
    """Simpan sesi termasuk kunci enkripsi."""
    ensure_config_dir()
    session = {
        "token": token,
        "user_id": user_id,
        "username": username,
        "encryption_key": encryption_key.hex(),
        "key_salt": key_salt
    }
    with open(CONFIG_FILE, "w") as f:
        json.dump(session, f)
    print(f"Login berhasil sebagai {username} (user_id: {user_id})")

def load_session() -> dict | None:
    """Muat data sesi dari file."""
    if not os.path.exists(CONFIG_FILE):
        return None
    with open(CONFIG_FILE, "r") as f:
        return json.load(f)

def clear_session():
    """Hapus sesi."""
    if os.path.exists(CONFIG_FILE):
        os.remove(CONFIG_FILE)
        print("Logout berhasil.")
    else:
        print("Tidak ada sesi aktif.")

def get_token() -> str | None:
    """Dapatkan token dari sesi."""
    session = load_session()
    return session["token"] if session else None

def get_token_and_key() -> tuple[str | None, bytes | None]:
    """Dapatkan token dan kunci enkripsi dari sesi."""
    session = load_session()
    if not session:
        return None, None
    token = session.get("token")
    key_hex = session.get("encryption_key")
    key = bytes.fromhex(key_hex) if key_hex else None
    return token, key

@app.command("register")
def register():
    """Registrasi pengguna baru dan langsung login."""
    username = input("Username: ")
    password = getpass("Password: ")
    password_confirm = getpass("Konfirmasi password: ")
    if password != password_confirm:
        print("Password tidak cocok.")
        return

    try:
        resp = requests.post(
            f"{API_BASE}/auth/register",
            json={"username": username, "password": password}
        )
        if resp.status_code == 200:
            data = resp.json()
            # Terima key_salt dari server dan turunkan kunci enkripsi
            encryption_key = derive_encryption_key(password, data["key_salt"])
            save_session(
                token=data["token"],
                user_id=data["user_id"],
                username=username,
                encryption_key=encryption_key,
                key_salt=data["key_salt"]
            )
        else:
            print(f"Gagal: {resp.json().get('detail', 'Unknown error')}")
    except requests.ConnectionError:
        print(f"Error: Tidak dapat terhubung ke server di {API_BASE}")

@app.command("login")
def login():
    """Login ke akun yang sudah ada."""
    username = input("Username: ")
    password = getpass("Password: ")

    try:
        resp = requests.post(
            f"{API_BASE}/auth/login",
            json={"username": username, "password": password}
        )
        if resp.status_code == 200:
            data = resp.json()
            # Turunkan kunci enkripsi dari password dan key_salt
            encryption_key = derive_encryption_key(password, data["key_salt"])
            save_session(
                token=data["token"],
                user_id=data["user_id"],
                username=username,
                encryption_key=encryption_key,
                key_salt=data["key_salt"]
            )
        else:
            print(f"Gagal: {resp.json().get('detail', 'Unknown error')}")
    except requests.ConnectionError:
        print(f"Error: Tidak dapat terhubung ke server di {API_BASE}")

@app.command("whoami")
def whoami():
    """Tampilkan pengguna yang sedang login."""
    session = load_session()
    if session:
        print(f"Login sebagai: {session['username']} (user_id: {session['user_id']})")
    else:
        print("Belum login. Jalankan 'cloudsim login' atau 'cloudsim register'.")

@app.command("logout")
def logout():
    """Logout dari sesi saat ini."""
    clear_session()

if __name__ == "__main__":
    app()
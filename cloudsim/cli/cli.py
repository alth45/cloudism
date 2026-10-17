"""Entry point CLI CloudSim."""
import typer
from cloudsim.cli import auth_commands, object_commands, storage_commands

app = typer.Typer(help="CloudSim CLI - Simulator Cloud Lokal")

app.add_typer(auth_commands.app, name="auth", help="Manajemen autentikasi")
app.add_typer(object_commands.app, name="object", help="Manajemen objek cloud")
app.add_typer(storage_commands.app, name="storage", help="Bucket & objek gaya gcloud storage (gs://...)")

# Alias untuk perintah tanpa subcommand
@app.command("login")
def login():
    """Login ke CloudSim."""
    auth_commands.login()

@app.command("register")
def register():
    """Registrasi pengguna baru."""
    auth_commands.register()

@app.command("whoami")
def whoami():
    """Lihat pengguna yang sedang login."""
    auth_commands.whoami()

@app.command("logout")
def logout():
    """Logout dari sesi saat ini."""
    auth_commands.logout()

@app.command("upload")
def upload(filepath: str = typer.Argument(..., help="Path file yang akan diunggah"),
           shareable: bool = typer.Option(False, "--shareable",
                                          help="Enkripsi via DEK + key-wrapping (re-encryption saat sharing)"),
           passphrase: str = typer.Option(None, "--passphrase",
                                          help="Passphrase pembungkus DEK")):
    """Unggah file ke cloud."""
    object_commands.upload(filepath, shareable, passphrase)

@app.command("list")
def list_objects():
    """Tampilkan daftar objek yang bisa diakses."""
    object_commands.list_objects()

@app.command("info")
def info(object_id: str = typer.Argument(..., help="ID objek")):
    """Lihat metadata objek."""
    object_commands.info(object_id)

@app.command("download")
def download(object_id: str = typer.Argument(..., help="ID objek"), 
             output: str = typer.Option(None, "--output", "-o", help="Path file output"),
             passphrase: str = typer.Option(None, "--passphrase",
                                            help="Passphrase pembagian utk membuka wrapped DEK")):
    """Unduh file dari cloud."""
    object_commands.download(object_id, output, passphrase)

@app.command("delete")
def delete(object_id: str = typer.Argument(..., help="ID objek")):
    """Hapus objek dari cloud."""
    object_commands.delete(object_id)

@app.command("share")
def share(object_id: str = typer.Argument(..., help="ID objek"),
          username: str = typer.Argument(..., help="Username tujuan"),
          permission: str = typer.Option("read", "--perm", "-p", help="Izin: read/write/admin"),
          passphrase: str = typer.Option(None, "--passphrase",
                                         help="Passphrase pembagian; DEK objek di-re-encrypt (key-wrapping/PBKDF2) utk penerima"),
          no_reencrypt: bool = typer.Option(False, "--no-reencrypt",
                                            help="Mode lama: hanya bagikan ACL, tanpa re-encryption")):
    """Bagikan akses objek ke pengguna lain (dengan re-encryption/key-wrapping)."""
    object_commands.share(object_id, username, permission, passphrase, no_reencrypt)


@app.command("revoke")
def revoke(object_id: str = typer.Argument(..., help="ID objek"),
           username: str = typer.Argument(..., help="Username yang dicabut aksesnya")):
    """Cabut akses user pada objek (ACL + wrapped key ikut dihapus)."""
    object_commands.revoke(object_id, username)


@app.command("shares")
def shares(object_id: str = typer.Argument(..., help="ID objek")):
    """Daftar pengguna yang memegang wrapped key pada objek."""
    object_commands.shares(object_id)

if __name__ == "__main__":
    app()
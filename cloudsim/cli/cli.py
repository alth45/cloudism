"""Entry point CLI CloudSim."""
import typer
from cloudsim.cli import auth_commands, object_commands

app = typer.Typer(help="CloudSim CLI - Simulator Cloud Lokal")

app.add_typer(auth_commands.app, name="auth", help="Manajemen autentikasi")
app.add_typer(object_commands.app, name="object", help="Manajemen objek cloud")

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
def upload(filepath: str = typer.Argument(..., help="Path file yang akan diunggah")):
    """Unggah file ke cloud."""
    object_commands.upload(filepath)

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
             output: str = typer.Option(None, "--output", "-o", help="Path file output")):
    """Unduh file dari cloud."""
    object_commands.download(object_id, output)

@app.command("delete")
def delete(object_id: str = typer.Argument(..., help="ID objek")):
    """Hapus objek dari cloud."""
    object_commands.delete(object_id)

@app.command("share")
def share(object_id: str = typer.Argument(..., help="ID objek"),
          username: str = typer.Argument(..., help="Username tujuan"),
          permission: str = typer.Option("read", "--perm", "-p", help="Izin: read/write/admin")):
    """Bagikan akses objek ke pengguna lain."""
    object_commands.share(object_id, username, permission)

if __name__ == "__main__":
    app()
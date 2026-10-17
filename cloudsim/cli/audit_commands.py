"""Perintah `audit` — lihat catatan aksi siapa, apa, kapan."""
import typer
import requests
from datetime import datetime

from cloudsim.cli.auth_commands import get_token, API_BASE


app = typer.Typer(help="Audit log (catatan aksi siapa, apa, kapan)")


def _headers() -> dict:
    token = get_token()
    if not token:
        print("Belum login. Jalankan 'cloudsim login' atau 'cloudsim register'.")
        raise typer.Exit(code=1)
    return {"Authorization": f"Bearer {token}"}


def _fmt_ts(ts: str | None) -> str:
    """Format timestamp ISO-8601 menjadi lokal yang ringkas."""
    if not ts:
        return "-"
    try:
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is not None:
            dt = dt.astimezone()
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return ts


def _print_table(items: list[dict]) -> None:
    if not items:
        print("(tidak ada entri audit log)")
        return
    rows = []
    for e in items:
        actor = e.get("actor_username") or e.get("actor_id") or "-"
        res = e.get("resource_name") or e.get("resource_id") or "-"
        details = e.get("details") or {}
        note = ", ".join(f"{k}={v}" for k, v in details.items()) or ""
        rows.append((_fmt_ts(e.get("timestamp")), actor, e.get("action", "-"),
                     res, e.get("result", "-"), note))
    headers = ("Waktu", "Siapa", "Aksi", "Objek/Bucket", "Hasil", "Detail")
    widths = [max(len(str(r[i])) for r in (rows + [headers])) for i in range(len(headers))]
    line = "  ".join(str(h).ljust(widths[i]) for i, h in enumerate(headers))
    print(line)
    print("-" * len(line))
    for r in rows:
        print("  ".join(str(v).ljust(widths[i]) for i, v in enumerate(r)))


@app.command("log")
def audit_log(
    action: str = typer.Option(None, "--action", "-a",
                               help="Filter aksi (cocok awalan, mis. 'object.' atau 'auth.login')"),
    actor: str = typer.Option(None, "--actor", help="Filter ID pelaku (khusus admin)"),
    resource: str = typer.Option(None, "--resource", "-r", help="Filter ID sumber daya"),
    since: str = typer.Option(None, "--since", help="Batas bawah waktu, format ISO-8601"),
    until: str = typer.Option(None, "--until", help="Batas atas waktu, format ISO-8601"),
    limit: int = typer.Option(50, "--limit", "-n", min=1, max=1000, help="Jumlah entri"),
):
    """Tampilkan audit log (admin: semua aksi; user biasa: aksinya sendiri)."""
    params = {"limit": limit}
    if action:
        params["action"] = action
    if actor:
        params["actor_id"] = actor
    if resource:
        params["resource_id"] = resource
    if since:
        params["since"] = since
    if until:
        params["until"] = until
    try:
        resp = requests.get(f"{API_BASE}/audit", params=params, headers=_headers())
        if resp.status_code != 200:
            print(f"Gagal: {resp.json().get('detail', resp.text)}")
            raise typer.Exit(code=1)
        data = resp.json()
        _print_table(data.get("items", []))
        print(f"\nMenampilkan {data.get('count', 0)} dari {data.get('total', 0)} entri.")
    except requests.ConnectionError:
        print(f"Error: Tidak dapat terhubung ke server di {API_BASE}")
        raise typer.Exit(code=1)


@app.command("mine")
def audit_mine(
    action: str = typer.Option(None, "--action", "-a", help="Filter aksi (cocok awalan)"),
    limit: int = typer.Option(50, "--limit", "-n", min=1, max=1000, help="Jumlah entri"),
):
    """Tampilkan riwayat aksimu sendiri."""
    params = {"limit": limit}
    if action:
        params["action"] = action
    try:
        resp = requests.get(f"{API_BASE}/audit/mine", params=params, headers=_headers())
        if resp.status_code != 200:
            print(f"Gagal: {resp.json().get('detail', resp.text)}")
            raise typer.Exit(code=1)
        data = resp.json()
        _print_table(data.get("items", []))
        print(f"\nMenampilkan {data.get('count', 0)} dari {data.get('total', 0)} entri.")
    except requests.ConnectionError:
        print(f"Error: Tidak dapat terhubung ke server di {API_BASE}")
        raise typer.Exit(code=1)


@app.command("object")
def audit_object(
    object_id: str = typer.Argument(..., help="ID objek"),
    limit: int = typer.Option(50, "--limit", "-n", min=1, max=1000, help="Jumlah entri"),
):
    """Riwayat aksi pada satu objek (upload, download, share, trash, dst)."""
    try:
        resp = requests.get(f"{API_BASE}/audit/objects/{object_id}/audit",
                            params={"limit": limit}, headers=_headers())
        if resp.status_code != 200:
            print(f"Gagal: {resp.json().get('detail', resp.text)}")
            raise typer.Exit(code=1)
        data = resp.json()
        _print_table(data.get("items", []))
    except requests.ConnectionError:
        print(f"Error: Tidak dapat terhubung ke server di {API_BASE}")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()

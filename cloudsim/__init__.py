import sys
import argparse
from cloudsim.core.engine import CloudObjectManager
from cloudsim.core.security import AuthManager
from cloudsim.core.id_generator import generate_user_id

def run_api():
    """Menjalankan server REST API (placeholder)."""
    print("Menjalankan CloudSim API server... (implementasi FastAPI akan ditambahkan)")
    # Nanti: import uvicorn, cloudsim.api.app
    # uvicorn.run("cloudsim.api.app:app", host="127.0.0.1", port=8000, reload=True)

def run_cli():
    """Menjalankan CLI interaktif (placeholder)."""
    print("Masuk ke CloudSim CLI. Ketik 'help' untuk bantuan.")
    # Nanti: panggil cloudsim.cli.cli.app()

def main():
    parser = argparse.ArgumentParser(description="CloudSim - Simulator Cloud Lokal")
    parser.add_argument("mode", nargs="?", default="cli", choices=["cli", "api"],
                        help="Mode operasi: 'cli' untuk command line, 'api' untuk server REST")
    args = parser.parse_args()

    if args.mode == "api":
        run_api()
    else:
        run_cli()

if __name__ == "__main__":
    main()
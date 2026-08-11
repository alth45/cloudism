import json
import os
import threading
from typing import Optional, List, Dict

class StorageManager:
    """Mengelola penyimpanan objek di file teks berbasis baris (append-only).
    Setiap baris adalah JSON yang merepresentasikan satu record objek atau penghapusan.
    """

    def __init__(self, filepath: str = None):
        if filepath is None:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            self.filepath = os.path.join(base_dir, "storage.txt")
        else:
            self.filepath = filepath
        # Pastikan direktori ada
        os.makedirs(os.path.dirname(self.filepath), exist_ok=True)
        # Buat file kosong jika belum ada
        if not os.path.exists(self.filepath):
            open(self.filepath, 'w').close()
        self._lock = threading.Lock()

    def append_record(self, record: Dict) -> int:
        """Menambahkan record ke akhir file secara atomik.
        Mengembalikan nomor baris (1-indexed) di mana record disimpan.
        """
        with self._lock:
            # Hitung jumlah baris yang ada (hanya baris non-kosong)
            line_count = 0
            try:
                with open(self.filepath, 'r') as f:
                    for line in f:
                        if line.rstrip('\n'):
                            line_count += 1
            except FileNotFoundError:
                pass

            # Tulis record baru
            with open(self.filepath, 'a', encoding='utf-8') as f:
                f.write(json.dumps(record) + '\n')
            return line_count + 1

    def read_record(self, line_number: int) -> Optional[Dict]:
        """Membaca record dari baris tertentu (1-indexed). Mengembalikan dict atau None."""
        with self._lock:
            try:
                with open(self.filepath, 'r', encoding='utf-8') as f:
                    for i, line in enumerate(f, start=1):
                        if i == line_number:
                            line = line.strip()
                            if not line:
                                return None
                            return json.loads(line)
            except (FileNotFoundError, json.JSONDecodeError):
                return None
        return None

    def get_all_records(self) -> List[Dict]:
        """Mengembalikan semua record (untuk keperluan debugging/recovery)."""
        records = []
        with self._lock:
            try:
                with open(self.filepath, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                records.append(json.loads(line))
                            except json.JSONDecodeError:
                                continue
            except FileNotFoundError:
                pass
        return records

    def count_records(self) -> int:
        """Menghitung jumlah total record di file."""
        count = 0
        with self._lock:
            try:
                with open(self.filepath, 'r') as f:
                    for line in f:
                        if line.rstrip('\n'):
                            count += 1
            except FileNotFoundError:
                pass
        return count
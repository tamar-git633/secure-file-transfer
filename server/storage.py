import ntpath
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

FILES_DIR = Path(__file__).resolve().parent / "received_files"
TEMP_SUFFIX = ".tmp"
FORBIDDEN_CHARS = set('<>:"/\\|?*')
FIRST_PRINTABLE_CHAR = 32
RESERVED_NAMES = {"CON", "PRN", "AUX", "NUL"}
RESERVED_NAMES |= {f"COM{i}" for i in range(1, 10)}
RESERVED_NAMES |= {f"LPT{i}" for i in range(1, 10)}


class StorageError(Exception):
    pass


@dataclass
class Client:
    id: bytes
    name: str
    public_key: bytes | None = None
    aes_key: bytes | None = None
    last_seen: datetime | None = None


@dataclass
class FileRecord:
    client_id: bytes
    file_name: str
    path_name: str
    verified: bool = False


# Returns a safe file name for saving on the server, raises StorageError
# for anything that could escape the client's folder or is invalid on Windows
def sanitize_file_name(name):
    if ".." in name:
        raise StorageError(f"File name '{name}' contains '..'")
    base = ntpath.basename(name)
    if not base:
        raise StorageError("File name is empty")
    if any(c in FORBIDDEN_CHARS or ord(c) < FIRST_PRINTABLE_CHAR
           for c in base):
        raise StorageError(f"File name '{base}' has invalid characters")
    if base[-1] in ". ":
        raise StorageError(f"File name '{base}' ends with dot or space")
    if base.split(".")[0].upper() in RESERVED_NAMES:
        raise StorageError(f"File name '{base}' is reserved on Windows")
    return base


# Keeps registered clients and received files in memory.
# All access goes through a lock because every client runs in its own thread.
class ClientStore:
    def __init__(self, files_dir=FILES_DIR, db=None):
        self._files_dir = Path(files_dir).resolve()
        self._db = db
        self._lock = threading.Lock()
        self._clients_by_id = {}
        self._clients_by_name = {}
        self._files = {}

    def register(self, name):
        with self._lock:
            if name in self._clients_by_name:
                return None
            client = Client(uuid.uuid4().bytes, name, last_seen=datetime.now())
            self._clients_by_id[client.id] = client
            self._clients_by_name[name] = client
            self._save_client(client)
            return client

    def get_by_id(self, client_id):
        with self._lock:
            return self._clients_by_id.get(client_id)

    def get_by_name(self, name):
        with self._lock:
            return self._clients_by_name.get(name)

    def set_public_key(self, client_id, public_key):
        self._update_client(client_id, public_key=public_key)

    def set_aes_key(self, client_id, aes_key):
        self._update_client(client_id, aes_key=aes_key)

    def touch(self, client_id):
        self._update_client(client_id)

    def _update_client(self, client_id, **fields):
        with self._lock:
            client = self._clients_by_id.get(client_id)
            if client is None:
                raise StorageError("Unknown client")
            for key, value in fields.items():
                setattr(client, key, value)
            client.last_seen = datetime.now()
            self._save_client(client)

    # Returns (final path, temp path) for a file of this client.
    # Creates the client's folder if needed.
    def file_paths(self, client_id, file_name):
        safe_name = sanitize_file_name(file_name)
        client_dir = self._files_dir / client_id.hex()
        client_dir.mkdir(parents=True, exist_ok=True)
        final_path = (client_dir / safe_name).resolve()
        if final_path.parent != client_dir.resolve():
            raise StorageError(f"File name '{file_name}' escapes folder")
        temp_path = final_path.with_name(safe_name + TEMP_SUFFIX)
        return final_path, temp_path

    def add_file(self, client_id, file_name, path):
        record = FileRecord(client_id, file_name, str(path))
        with self._lock:
            self._files[(client_id, file_name)] = record
            if self._db:
                self._db.save_file(record)
        return record

    def get_file(self, client_id, file_name):
        with self._lock:
            return self._files.get((client_id, file_name))

    def set_verified(self, client_id, file_name):
        with self._lock:
            record = self._files.get((client_id, file_name))
            if record is None:
                raise StorageError(f"No file '{file_name}' for client")
            record.verified = True
            if self._db:
                self._db.save_file(record)

    # Deletes the file from disk (including a leftover temp file)
    # and forgets its record
    def remove_file(self, client_id, file_name):
        with self._lock:
            record = self._files.pop((client_id, file_name), None)
            if record and self._db:
                self._db.delete_file(record)
        try:
            final_path, temp_path = self.file_paths(client_id, file_name)
        except StorageError:
            return
        final_path.unlink(missing_ok=True)
        temp_path.unlink(missing_ok=True)

    def _save_client(self, client):
        if self._db:
            self._db.save_client(client)

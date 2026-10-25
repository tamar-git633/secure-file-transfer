import sqlite3
import threading
from datetime import datetime
from pathlib import Path

from storage import Client, FileRecord, StorageError

DB_FILE = Path(__file__).resolve().parent / "defensive.db"
TIME_FORMAT = "seconds"

CREATE_CLIENTS = """
CREATE TABLE IF NOT EXISTS clients (
    ID BLOB PRIMARY KEY CHECK (length(ID) = 16),
    Name TEXT NOT NULL UNIQUE CHECK (length(Name) BETWEEN 1 AND 255),
    PublicKey BLOB CHECK (PublicKey IS NULL OR length(PublicKey) = 160),
    LastSeen TEXT,
    AESKey BLOB CHECK (AESKey IS NULL OR length(AESKey) = 32)
)"""

CREATE_FILES = """
CREATE TABLE IF NOT EXISTS files (
    ID BLOB NOT NULL REFERENCES clients (ID),
    FileName TEXT NOT NULL CHECK (length(FileName) BETWEEN 1 AND 255),
    PathName TEXT NOT NULL,
    Verified INTEGER NOT NULL DEFAULT 0 CHECK (Verified IN (0, 1)),
    PRIMARY KEY (ID, FileName)
)"""

SAVE_CLIENT = """
INSERT INTO clients (ID, Name, PublicKey, LastSeen, AESKey)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT (ID) DO UPDATE SET
    Name = excluded.Name,
    PublicKey = excluded.PublicKey,
    LastSeen = excluded.LastSeen,
    AESKey = excluded.AESKey"""

SAVE_FILE = """
INSERT INTO files (ID, FileName, PathName, Verified)
VALUES (?, ?, ?, ?)
ON CONFLICT (ID, FileName) DO UPDATE SET
    PathName = excluded.PathName,
    Verified = excluded.Verified"""


# Keeps clients and received files in defensive.db (SQLite), so the server
# can load them again after a restart. Every query uses parameters.
class Database:
    def __init__(self, path=DB_FILE):
        self._lock = threading.Lock()
        try:
            self._conn = sqlite3.connect(path, check_same_thread=False)
        except sqlite3.Error as e:
            raise StorageError(f"Database error: {e}") from None
        try:
            with self._conn:
                self._conn.execute("PRAGMA foreign_keys = ON")
                self._conn.execute(CREATE_CLIENTS)
                self._conn.execute(CREATE_FILES)
        except sqlite3.Error as e:
            self._conn.close()
            raise StorageError(f"Database error: {e}") from None

    def close(self):
        self._conn.close()

    def load_clients(self):
        rows = self._query(
            "SELECT ID, Name, PublicKey, LastSeen, AESKey FROM clients")
        return [Client(client_id, name, public_key, aes_key,
                       _parse_time(last_seen))
                for client_id, name, public_key, last_seen, aes_key in rows]

    def load_files(self):
        rows = self._query(
            "SELECT ID, FileName, PathName, Verified FROM files")
        return [FileRecord(client_id, file_name, path_name, bool(verified))
                for client_id, file_name, path_name, verified in rows]

    def save_client(self, client):
        last_seen = (client.last_seen.isoformat(timespec=TIME_FORMAT)
                     if client.last_seen else None)
        self._execute(SAVE_CLIENT, (client.id, client.name, client.public_key,
                                    last_seen, client.aes_key))

    def save_file(self, record):
        self._execute(SAVE_FILE, (record.client_id, record.file_name,
                                  record.path_name, int(record.verified)))

    def delete_file(self, record):
        self._execute("DELETE FROM files WHERE ID = ? AND FileName = ?",
                      (record.client_id, record.file_name))

    def _query(self, sql):
        try:
            with self._lock:
                return self._conn.execute(sql).fetchall()
        except sqlite3.Error as e:
            raise StorageError(f"Database error: {e}") from None

    def _execute(self, sql, params):
        try:
            with self._lock, self._conn:
                self._conn.execute(sql, params)
        except sqlite3.Error as e:
            raise StorageError(f"Database error: {e}") from None


def _parse_time(text):
    return datetime.fromisoformat(text) if text else None

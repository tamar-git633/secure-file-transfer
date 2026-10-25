# Tests for database.py
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from database import Database
from storage import ClientStore, StorageError

PUBLIC_KEY = bytes(range(160))
AES_KEY = bytes(range(32))


class DatabaseTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp_dir.name)
        self.db_path = self.root / "defensive.db"
        self.files_dir = self.root / "received_files"
        self.databases = []

    def tearDown(self):
        for db in self.databases:
            db.close()
        self.tmp_dir.cleanup()

    def open_store(self):
        db = Database(self.db_path)
        self.databases.append(db)
        return ClientStore(self.files_dir, db)

    def rows(self, sql):
        conn = sqlite3.connect(self.db_path)
        try:
            return conn.execute(sql).fetchall()
        finally:
            conn.close()


class SchemaTest(DatabaseTestCase):
    def test_tables_and_columns(self):
        self.open_store()
        clients = [row[1] for row in self.rows("PRAGMA table_info(clients)")]
        files = [row[1] for row in self.rows("PRAGMA table_info(files)")]
        self.assertEqual(clients,
                         ["ID", "Name", "PublicKey", "LastSeen", "AESKey"])
        self.assertEqual(files, ["ID", "FileName", "PathName", "Verified"])

    def test_opening_twice_keeps_data(self):
        self.open_store().register("alice")
        self.assertEqual(self.open_store().client_count, 1)

    def test_corrupt_file(self):
        self.db_path.write_bytes(b"this is not a database" * 100)
        with self.assertRaises(StorageError):
            Database(self.db_path)


class ClientsTableTest(DatabaseTestCase):
    def test_register_is_saved(self):
        client = self.open_store().register("alice")
        rows = self.rows("SELECT ID, Name, PublicKey, AESKey FROM clients")
        self.assertEqual(rows, [(client.id, "alice", None, None)])

    def test_keys_and_last_seen_are_saved(self):
        store = self.open_store()
        client = store.register("alice")
        store.set_public_key(client.id, PUBLIC_KEY)
        store.set_aes_key(client.id, AES_KEY)
        (public_key, aes_key, last_seen), = self.rows(
            "SELECT PublicKey, AESKey, LastSeen FROM clients")
        self.assertEqual(public_key, PUBLIC_KEY)
        self.assertEqual(aes_key, AES_KEY)
        self.assertIsNotNone(last_seen)

    def test_touch_writes_once_per_second(self):
        store = self.open_store()
        client = store.register("alice")
        writes = []
        db = self.databases[-1]
        real_save = db.save_client
        db.save_client = lambda c: (writes.append(c.last_seen), real_save(c))
        for _ in range(500):
            store.touch(client.id)
        self.assertLessEqual(len(writes), 2)
        (last_seen,), = self.rows("SELECT LastSeen FROM clients")
        self.assertEqual(last_seen,
                         client.last_seen.isoformat(timespec="seconds"))

    def test_touch_unknown_client(self):
        with self.assertRaises(StorageError):
            self.open_store().touch(bytes(16))

    def test_restart_loads_clients(self):
        store = self.open_store()
        client = store.register("alice")
        store.set_public_key(client.id, PUBLIC_KEY)
        restarted = self.open_store()
        loaded = restarted.get_by_name("alice")
        self.assertEqual(loaded.id, client.id)
        self.assertEqual(loaded.public_key, PUBLIC_KEY)
        self.assertIs(restarted.get_by_id(client.id), loaded)
        self.assertIsNotNone(loaded.last_seen)

    def test_name_taken_after_restart(self):
        self.open_store().register("alice")
        self.assertIsNone(self.open_store().register("alice"))

    def test_sql_injection_in_name(self):
        name = "x'); DROP TABLE clients; --"
        self.open_store().register(name)
        self.assertEqual(self.rows("SELECT Name FROM clients"), [(name,)])

    def test_failed_save_leaves_memory_unchanged(self):
        store = self.open_store()
        client = store.register("alice")
        with self.assertRaises(StorageError):
            store.set_public_key(client.id, b"too short")
        self.assertIsNone(store.get_by_id(client.id).public_key)

    def test_concurrent_registration(self):
        store = self.open_store()
        results = []
        threads = [threading.Thread(
            target=lambda i=i: results.append(store.register(f"c{i % 5}")))
            for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sum(r is not None for r in results), 5)
        self.assertEqual(len(self.rows("SELECT ID FROM clients")), 5)


class FilesTableTest(DatabaseTestCase):
    def setUp(self):
        super().setUp()
        self.store = self.open_store()
        self.client = self.store.register("alice")

    def save_file(self, name, data=b"data"):
        final_path, _ = self.store.file_paths(self.client.id, name)
        final_path.write_bytes(data)
        self.store.add_file(self.client.id, name, final_path)
        return final_path

    def test_path_is_relative_to_server_folder(self):
        self.save_file("a.bin")
        (path_name, verified), = self.rows(
            "SELECT PathName, Verified FROM files")
        self.assertEqual(path_name,
                         f"received_files/{self.client.id.hex()}/a.bin")
        self.assertEqual(verified, 0)

    def test_verified_is_saved(self):
        self.save_file("a.bin")
        self.store.set_verified(self.client.id, "a.bin")
        self.assertEqual(self.rows("SELECT Verified FROM files"), [(1,)])

    def test_remove_deletes_row(self):
        self.save_file("a.bin")
        self.store.remove_file(self.client.id, "a.bin")
        self.assertEqual(self.rows("SELECT * FROM files"), [])

    def test_restart_loads_files(self):
        self.save_file("a.bin")
        self.store.set_verified(self.client.id, "a.bin")
        restarted = self.open_store()
        record = restarted.get_file(self.client.id, "a.bin")
        self.assertTrue(record.verified)
        self.assertEqual(restarted.file_count, 1)

    def test_restart_drops_missing_files(self):
        path = self.save_file("a.bin")
        path.unlink()
        restarted = self.open_store()
        self.assertIsNone(restarted.get_file(self.client.id, "a.bin"))
        self.assertEqual(self.rows("SELECT * FROM files"), [])

    def test_send_again_updates_row(self):
        self.save_file("a.bin")
        self.store.set_verified(self.client.id, "a.bin")
        self.save_file("a.bin", b"new")
        self.assertEqual(self.rows("SELECT Verified FROM files"), [(0,)])


if __name__ == "__main__":
    unittest.main()

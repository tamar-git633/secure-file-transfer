import tempfile
import threading
import unittest
from pathlib import Path

from storage import ClientStore, StorageError, sanitize_file_name


class SanitizeFileNameTest(unittest.TestCase):
    def test_valid_names(self):
        for name in ("file.pdf", "my file.docx", "a", "report-2026_v2.txt",
                     ".hidden", "no_extension"):
            with self.subTest(name=name):
                self.assertEqual(sanitize_file_name(name), name)

    def test_full_path_keeps_only_name(self):
        self.assertEqual(sanitize_file_name(r"c:\doc\file02.docx"),
                         "file02.docx")
        self.assertEqual(sanitize_file_name("dir/sub/file.bin"), "file.bin")

    def test_rejected_names(self):
        for name in ("", "..", r"..\x", "../x", r"a\..\b", "a..b.txt",
                     "dir/", "c:\\", "x?", "a*b", "a<b", "a>b", 'a"b',
                     "a|b", "tab\tname", "name.", "name ", "CON",
                     "con.txt", "NUL", "COM1.log", "lpt9"):
            with self.subTest(name=name), self.assertRaises(StorageError):
                sanitize_file_name(name)


class ClientStoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.store = ClientStore(self.tmp_dir.name)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_register(self):
        client = self.store.register("alice")
        self.assertEqual(len(client.id), 16)
        self.assertEqual(client.name, "alice")
        self.assertIsNone(client.public_key)
        self.assertIsNotNone(client.last_seen)
        self.assertIs(self.store.get_by_id(client.id), client)
        self.assertIs(self.store.get_by_name("alice"), client)

    def test_duplicate_name(self):
        self.store.register("alice")
        self.assertIsNone(self.store.register("alice"))

    def test_unique_ids(self):
        first = self.store.register("alice")
        second = self.store.register("bob")
        self.assertNotEqual(first.id, second.id)

    def test_unknown_client(self):
        self.assertIsNone(self.store.get_by_id(bytes(16)))
        self.assertIsNone(self.store.get_by_name("nobody"))
        with self.assertRaises(StorageError):
            self.store.set_public_key(bytes(16), b"k")

    def test_set_keys_updates_last_seen(self):
        client = self.store.register("alice")
        before = client.last_seen
        self.store.set_public_key(client.id, b"p" * 160)
        self.store.set_aes_key(client.id, b"a" * 32)
        self.assertEqual(client.public_key, b"p" * 160)
        self.assertEqual(client.aes_key, b"a" * 32)
        self.assertGreaterEqual(client.last_seen, before)

    def test_concurrent_register_same_name(self):
        results = []

        def worker():
            results.append(self.store.register("same"))

        threads = [threading.Thread(target=worker) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sum(r is not None for r in results), 1)


class FileStoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.store = ClientStore(self.tmp_dir.name)
        self.client = self.store.register("alice")

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_file_paths(self):
        final_path, temp_path = self.store.file_paths(self.client.id,
                                                      "a.bin")
        client_dir = Path(self.tmp_dir.name).resolve() / self.client.id.hex()
        self.assertEqual(final_path, client_dir / "a.bin")
        self.assertEqual(temp_path, client_dir / "a.bin.tmp")
        self.assertTrue(client_dir.is_dir())

    def test_file_paths_rejects_traversal(self):
        with self.assertRaises(StorageError):
            self.store.file_paths(self.client.id, r"..\..\evil.exe")

    def test_add_and_verify(self):
        record = self.store.add_file(self.client.id, "a.bin", "path")
        self.assertFalse(record.verified)
        self.store.set_verified(self.client.id, "a.bin")
        self.assertTrue(self.store.get_file(self.client.id, "a.bin").verified)

    def test_verify_unknown_file(self):
        with self.assertRaises(StorageError):
            self.store.set_verified(self.client.id, "missing.bin")

    def test_remove_file_deletes_from_disk(self):
        final_path, temp_path = self.store.file_paths(self.client.id,
                                                      "a.bin")
        final_path.write_bytes(b"data")
        temp_path.write_bytes(b"partial")
        self.store.add_file(self.client.id, "a.bin", final_path)
        self.store.remove_file(self.client.id, "a.bin")
        self.assertFalse(final_path.exists())
        self.assertFalse(temp_path.exists())
        self.assertIsNone(self.store.get_file(self.client.id, "a.bin"))

    def test_remove_missing_file_is_safe(self):
        self.store.remove_file(self.client.id, "never_sent.bin")
        self.store.remove_file(self.client.id, r"..\bad")


class FakeDb:
    def __init__(self):
        self.calls = []

    def load_clients(self):
        return []

    def load_files(self):
        return []

    def save_client(self, client):
        self.calls.append(("client", client.name))

    def save_file(self, record):
        self.calls.append(("file", record.file_name, record.verified))

    def delete_file(self, record):
        self.calls.append(("delete", record.file_name))


class DbHookTest(unittest.TestCase):
    def test_changes_reach_db(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = FakeDb()
            store = ClientStore(tmp, db)
            client = store.register("alice")
            store.add_file(client.id, "a.bin", "p")
            store.set_verified(client.id, "a.bin")
            store.remove_file(client.id, "a.bin")
            self.assertEqual(db.calls, [
                ("client", "alice"),
                ("file", "a.bin", False),
                ("file", "a.bin", True),
                ("delete", "a.bin"),
            ])


if __name__ == "__main__":
    unittest.main()

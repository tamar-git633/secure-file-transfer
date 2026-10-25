# Tests for config.py
import os
import tempfile
import unittest

from config import DEFAULT_PORT, read_port


class ReadPortTest(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp_dir.name, "port.info")

    def tearDown(self):
        self.tmp_dir.cleanup()

    def write(self, data):
        with open(self.path, "wb") as f:
            f.write(data)

    def assert_default_with_warning(self):
        with self.assertLogs("config", level="WARNING"):
            self.assertEqual(read_port(self.path), DEFAULT_PORT)

    def test_valid_port(self):
        self.write(b"1234")
        self.assertEqual(read_port(self.path), 1234)

    def test_valid_port_with_whitespace(self):
        self.write(b"  8080\r\n")
        self.assertEqual(read_port(self.path), 8080)

    def test_utf8_bom_is_ignored(self):
        self.write(b"\xef\xbb\xbf1250\r\n")
        self.assertEqual(read_port(self.path), 1250)

    def test_missing_file(self):
        self.assert_default_with_warning()

    def test_path_is_none(self):
        self.path = None
        self.assert_default_with_warning()

    def test_empty_file(self):
        self.write(b"")
        self.assert_default_with_warning()

    def test_not_a_number(self):
        self.write(b"abc")
        self.assert_default_with_warning()

    def test_negative(self):
        self.write(b"-5")
        self.assert_default_with_warning()

    def test_zero(self):
        self.write(b"0")
        self.assert_default_with_warning()

    def test_out_of_range(self):
        self.write(b"99999")
        self.assert_default_with_warning()

    def test_non_ascii(self):
        self.write("١٢٣٤".encode())
        self.assert_default_with_warning()

    def test_file_too_large(self):
        self.write(b"1" * 1000)
        self.assert_default_with_warning()

    def test_path_is_directory(self):
        self.path = self.tmp_dir.name
        self.assert_default_with_warning()


if __name__ == "__main__":
    unittest.main()

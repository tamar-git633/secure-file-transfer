import os
import unittest

from cksum import Cksum, memcrc


class CksumTest(unittest.TestCase):
    def test_known_value(self):
        self.assertEqual(memcrc(b"123456789"), 930766865)

    def test_empty(self):
        self.assertEqual(memcrc(b""), 4294967295)

    def test_single_char(self):
        self.assertEqual(memcrc(b"a"), 1220704766)

    def test_text_with_newline(self):
        self.assertEqual(memcrc(b"hello\n"), 3015617425)

    def test_incremental_equals_whole(self):
        data = os.urandom(100_000)
        checksum = Cksum()
        for start in range(0, len(data), 4096):
            checksum.update(data[start:start + 4096])
        self.assertEqual(checksum.digest(), memcrc(data))

    def test_empty_updates_do_not_change_result(self):
        checksum = Cksum()
        checksum.update(b"")
        checksum.update(b"123456789")
        checksum.update(b"")
        self.assertEqual(checksum.digest(), 930766865)

    def test_digest_can_be_called_twice(self):
        checksum = Cksum()
        checksum.update(b"123456789")
        self.assertEqual(checksum.digest(), checksum.digest())

    def test_length_affects_result(self):
        self.assertNotEqual(memcrc(b"\x00"), memcrc(b"\x00\x00"))


if __name__ == "__main__":
    unittest.main()

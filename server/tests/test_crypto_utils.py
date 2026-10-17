import os
import tempfile
import unittest

import crypto_utils
from cksum import Cksum, memcrc
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad
from crypto_utils import CryptoError

PRIVATE_KEY = RSA.generate(1024, e=17)
PUBLIC_KEY_DER = PRIVATE_KEY.public_key().export_key("DER")


def aes_encrypt(key, data):
    cipher = AES.new(key, AES.MODE_CBC, iv=bytes(16))
    return cipher.encrypt(pad(data, 16))


class RsaTest(unittest.TestCase):
    def test_public_key_is_160_bytes(self):
        self.assertEqual(len(PUBLIC_KEY_DER), 160)

    def test_encrypt_aes_key(self):
        aes_key = crypto_utils.generate_aes_key()
        self.assertEqual(len(aes_key), 32)
        encrypted = crypto_utils.encrypt_with_public_key(
            PUBLIC_KEY_DER, aes_key
        )
        self.assertEqual(len(encrypted), 128)
        decrypted = PKCS1_OAEP.new(PRIVATE_KEY).decrypt(encrypted)
        self.assertEqual(decrypted, aes_key)

    def test_keys_are_random(self):
        self.assertNotEqual(
            crypto_utils.generate_aes_key(), crypto_utils.generate_aes_key()
        )

    def test_garbage_public_key(self):
        with self.assertRaises(CryptoError):
            crypto_utils.encrypt_with_public_key(b"\x00" * 160, b"data")

    def test_private_key_rejected(self):
        with self.assertRaises(CryptoError):
            crypto_utils.encrypt_with_public_key(
                PRIVATE_KEY.export_key("DER"), b"data"
            )

    def test_wrong_key_size_rejected(self):
        key = RSA.generate(2048).public_key().export_key("DER")
        with self.assertRaises(CryptoError):
            crypto_utils.encrypt_with_public_key(key, b"data")


class EncryptedSizeTest(unittest.TestCase):
    def test_formula_matches_real_encryption(self):
        key = crypto_utils.generate_aes_key()
        for size in (0, 1, 15, 16, 17, 100_000, 65536, 65537):
            expected = len(aes_encrypt(key, b"x" * size))
            self.assertEqual(crypto_utils.encrypted_size(size), expected)

    def test_examples(self):
        self.assertEqual(crypto_utils.encrypted_size(0), 16)
        self.assertEqual(crypto_utils.encrypted_size(15), 16)
        self.assertEqual(crypto_utils.encrypted_size(16), 32)
        self.assertEqual(crypto_utils.encrypted_size(100_000), 100_016)


class StreamingDecryptTest(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.src = os.path.join(self.tmp_dir.name, "file.enc")
        self.dst = os.path.join(self.tmp_dir.name, "file.out")
        self.key = crypto_utils.generate_aes_key()

    def tearDown(self):
        self.tmp_dir.cleanup()

    def write_src(self, data):
        with open(self.src, "wb") as f:
            f.write(data)

    def read_dst(self):
        with open(self.dst, "rb") as f:
            return f.read()

    def round_trip(self, size):
        plain = os.urandom(size)
        self.write_src(aes_encrypt(self.key, plain))
        checksum = Cksum()
        written = crypto_utils.decrypt_file_streaming(
            self.key, self.src, self.dst, checksum.update
        )
        self.assertEqual(written, size)
        self.assertEqual(self.read_dst(), plain)
        self.assertEqual(checksum.digest(), memcrc(plain))

    def test_sizes(self):
        chunk = crypto_utils.DECRYPT_CHUNK_SIZE
        for size in (0, 1, 15, 16, 17, 100_000, chunk - 1, chunk, chunk + 1,
                     3 * chunk):
            with self.subTest(size=size):
                self.round_trip(size)

    def test_without_callback(self):
        plain = b"hello world"
        self.write_src(aes_encrypt(self.key, plain))
        crypto_utils.decrypt_file_streaming(self.key, self.src, self.dst)
        self.assertEqual(self.read_dst(), plain)

    def test_empty_encrypted_file(self):
        self.write_src(b"")
        with self.assertRaises(CryptoError):
            crypto_utils.decrypt_file_streaming(self.key, self.src, self.dst)

    def test_size_not_block_multiple(self):
        self.write_src(b"x" * 17)
        with self.assertRaises(CryptoError):
            crypto_utils.decrypt_file_streaming(self.key, self.src, self.dst)

    def test_bad_padding_removes_output(self):
        cipher = AES.new(self.key, AES.MODE_CBC, iv=bytes(16))
        self.write_src(cipher.encrypt(bytes(32)))
        with self.assertRaises(CryptoError):
            crypto_utils.decrypt_file_streaming(self.key, self.src, self.dst)
        self.assertFalse(os.path.exists(self.dst))


if __name__ == "__main__":
    unittest.main()

from pathlib import Path

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad
from protocol import AES_KEY_SIZE

RSA_KEY_BITS = 1024
AES_BLOCK_SIZE = AES.block_size
ZERO_IV = bytes(AES_BLOCK_SIZE)
DECRYPT_CHUNK_SIZE = 64 * 1024


class CryptoError(Exception):
    pass


def generate_aes_key():
    return get_random_bytes(AES_KEY_SIZE)


# Encrypts data with the client's RSA public key (X.509 DER format)
def encrypt_with_public_key(public_key_der, data):
    try:
        key = RSA.import_key(public_key_der)
    except (ValueError, IndexError, TypeError):
        raise CryptoError("Invalid public key") from None
    if key.has_private() or key.size_in_bits() != RSA_KEY_BITS:
        raise CryptoError(f"Public key must be RSA {RSA_KEY_BITS} bit")
    return PKCS1_OAEP.new(key).encrypt(data)


# Size of the AES-CBC output for a file of the given size (PKCS7 padding)
def encrypted_size(orig_size):
    return (orig_size // AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE


# Decrypts AES-256-CBC data with a zero IV piece by piece.
# The last block is held back until finish() so the padding can be removed.
class AesStreamDecryptor:
    def __init__(self, key):
        if len(key) != AES_KEY_SIZE:
            raise CryptoError(f"AES key must be {AES_KEY_SIZE} bytes")
        self._cipher = AES.new(key, AES.MODE_CBC, iv=ZERO_IV)
        self._pending = b""
        self._finished = False

    def update(self, chunk):
        if self._finished:
            raise CryptoError("Decryptor already finished")
        data = self._pending + chunk
        ready = len(data) - len(data) % AES_BLOCK_SIZE
        if ready == len(data):
            ready = max(0, ready - AES_BLOCK_SIZE)
        self._pending = data[ready:]
        return self._cipher.decrypt(data[:ready])

    def finish(self):
        if self._finished:
            raise CryptoError("Decryptor already finished")
        self._finished = True
        if len(self._pending) != AES_BLOCK_SIZE:
            raise CryptoError("Encrypted size is not a multiple of 16")
        try:
            return unpad(self._cipher.decrypt(self._pending), AES_BLOCK_SIZE)
        except ValueError:
            raise CryptoError("Bad padding, wrong key?") from None


# Decrypts src_path into dst_path chunk by chunk.
# on_chunk is called with every decrypted chunk. Returns the plain size.
def decrypt_file_streaming(key, src_path, dst_path, on_chunk=None):
    decryptor = AesStreamDecryptor(key)
    written = 0
    try:
        with open(src_path, "rb") as src, open(dst_path, "wb") as dst:
            while chunk := src.read(DECRYPT_CHUNK_SIZE):
                written += _write(dst, decryptor.update(chunk), on_chunk)
            written += _write(dst, decryptor.finish(), on_chunk)
    except BaseException:
        Path(dst_path).unlink(missing_ok=True)
        raise
    return written


def _write(dst, data, on_chunk):
    if data:
        dst.write(data)
        if on_chunk:
            on_chunk(data)
    return len(data)

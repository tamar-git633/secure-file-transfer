# Checks that the C++ client crypto matches the server
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from cksum import memcrc
from crypto_utils import (
    decrypt_file_streaming,
    encrypt_with_public_key,
    generate_aes_key,
)

ROOT = Path(__file__).resolve().parents[2]
TESTS_BIN = ROOT / "client" / "tests" / "bin"
DEFAULT_TOOL = TESTS_BIN / "Release" / "ClientTests.exe"
FILE_SIZE = 150_000


def run_tool(tool, command, work_dir):
    result = subprocess.run([str(tool), command, str(work_dir)],
                            capture_output=True, text=True, check=False)
    print(result.stdout, end="")
    if result.returncode != 0:
        raise RuntimeError(f"C++ {command} failed: {result.stderr}")


def check(condition, message):
    print(("OK   " if condition else "FAIL ") + message)
    return condition


def main():
    tool = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_TOOL
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        run_tool(tool, "keygen", work)
        public_der = (work / "public.der").read_bytes()

        aes_key = generate_aes_key()
        (work / "aes.enc").write_bytes(
            encrypt_with_public_key(public_der, aes_key))
        plain = os.urandom(FILE_SIZE)
        (work / "plain.bin").write_bytes(plain)
        print("Python: encrypted AES key with the C++ public key")

        run_tool(tool, "encrypt", work)

        decrypted_size = decrypt_file_streaming(
            aes_key, work / "cipher.bin", work / "result.bin")
        cipher_size = (work / "cipher.bin").stat().st_size
        cpp_crc = int((work / "crc.txt").read_text())

        results = [
            check(len(public_der) == 160, "public key from C++ is 160 bytes"),
            check((work / "aes.key").read_bytes() == aes_key,
                  "C++ decrypted the AES key from Python"),
            check(cipher_size == (FILE_SIZE // 16 + 1) * 16,
                  "encrypted size matches the formula"),
            check(decrypted_size == FILE_SIZE
                  and (work / "result.bin").read_bytes() == plain,
                  "server code decrypted the C++ file correctly"),
            check(cpp_crc == memcrc(plain), "C++ cksum equals server cksum"),
        ]
    print("\nInterop check " + ("passed" if all(results) else "FAILED"))
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())

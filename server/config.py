# Reading the server port from port.info
import logging
from pathlib import Path

DEFAULT_PORT = 1369
MIN_PORT = 1
MAX_PORT = 65535
MAX_PORT_FILE_SIZE = 16
UTF8_BOM = b"\xef\xbb\xbf"
PORT_FILE = Path(__file__).resolve().parent / "port.info"

logger = logging.getLogger(__name__)


def _use_default(reason):
    logger.warning("%s, using default port %d", reason, DEFAULT_PORT)
    return DEFAULT_PORT


def read_port(path=PORT_FILE):
    if path is None:
        return _use_default("No port file given")

    if not Path(path).is_file():
        return _use_default(f"{path} not found")

    try:
        with open(path, "rb") as f:
            raw = f.read(MAX_PORT_FILE_SIZE + 1)
    except OSError as e:
        return _use_default(f"Cannot read {path} ({e.strerror})")

    raw = raw.removeprefix(UTF8_BOM)
    if len(raw) > MAX_PORT_FILE_SIZE:
        return _use_default(f"{path} is too large")

    try:
        text = raw.decode("ascii").strip()
    except UnicodeDecodeError:
        return _use_default(f"{path} contains non ASCII data")

    if not text.isdigit():
        return _use_default(f"Invalid port '{text}' in {path}")

    port = int(text)
    if not MIN_PORT <= port <= MAX_PORT:
        return _use_default(f"Port {port} is out of range")

    return port

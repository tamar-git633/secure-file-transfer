import logging
import socket
import sys
import threading

from client_session import ClientSession
from config import read_port
from protocol import SERVER_VERSION
from storage import ClientStore

ACCEPT_POLL_INTERVAL = 0.2

logger = logging.getLogger(__name__)


# Listens for clients and starts a thread with a ClientSession for each one
class Server:
    def __init__(self, port, store):
        self._store = store
        self._stopped = threading.Event()
        self._sock = socket.create_server(("", port))
        self._sock.settimeout(ACCEPT_POLL_INTERVAL)
        self.port = self._sock.getsockname()[1]

    def serve_forever(self):
        logger.info("Server version %d listening on port %d",
                    SERVER_VERSION, self.port)
        with self._sock:
            while not self._stopped.is_set():
                try:
                    conn, address = self._sock.accept()
                except TimeoutError:
                    continue
                session = ClientSession(conn, address, self._store)
                threading.Thread(target=session.run,
                                 name=f"client-{address[1]}",
                                 daemon=True).start()
        logger.info("Server stopped")

    def stop(self):
        self._stopped.set()


# Reads the port, starts listening and serves clients until stopped
def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(threadName)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    port = read_port()
    try:
        server = Server(port, ClientStore())
    except OSError as e:
        logger.error("Cannot listen on port %d: %s", port, e)
        return 1
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    return 0


if __name__ == "__main__":
    sys.exit(main())

import logging
import sys
import tempfile

import file_receiver
from client_session import ClientSession, ConnectionClosedError
from protocol import ProtocolError, RequestCode
from storage import ClientStore

from server import Server

HANDLER_NAMES = {
    RequestCode.REGISTER: "_handle_register",
    RequestCode.SEND_PUBLIC_KEY: "_handle_public_key",
    RequestCode.RECONNECT: "_handle_reconnect",
    RequestCode.SEND_FILE: "_handle_file_packet",
    RequestCode.CRC_OK: "_handle_crc_ok",
}


# Runs the real server, but one request code fails the first <times> calls:
# it answers 1607, or with "drop" the server closes the connection.
# A failing file upload fails on its last packet, like the real server.
# Usage (from the server folder):
#   py -3.12 -m tests.error_server <port> <code> <times> [drop]
def main():
    port = int(sys.argv[1])
    code = RequestCode(int(sys.argv[2]))
    failures_left = [int(sys.argv[3])]
    drop = len(sys.argv) > 4 and sys.argv[4] == "drop"

    def should_fail():
        if failures_left[0] > 0:
            failures_left[0] -= 1
            return True
        return False

    if code == RequestCode.SEND_FILE and not drop:
        real_complete = file_receiver.FileReceiver.complete

        def failing_complete(self):
            if should_fail():
                raise ProtocolError("Forced failure of the file upload")
            return real_complete(self)

        file_receiver.FileReceiver.complete = failing_complete
    else:
        name = HANDLER_NAMES[code]
        real_handler = getattr(ClientSession, name)

        def failing_handler(self, header):
            if should_fail():
                if drop:
                    self._sock.close()
                    raise ConnectionClosedError()
                raise ProtocolError(f"Forced failure of request {code}")
            return real_handler(self, header)

        setattr(ClientSession, name, failing_handler)

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s: %(message)s",
                        datefmt="%H:%M:%S")
    with tempfile.TemporaryDirectory() as files_dir:
        try:
            Server(port, ClientStore(files_dir)).serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()

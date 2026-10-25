# Server that fails chosen requests, for testing the client
import logging
import sys
import tempfile

import file_receiver
from client_session import ClientSession, ConnectionClosedError
from protocol import ProtocolError, RequestCode, ResponseCode
from storage import ClientStore

from server import Server

HANDLER_NAMES = {
    RequestCode.REGISTER: "_handle_register",
    RequestCode.SEND_PUBLIC_KEY: "_handle_public_key",
    RequestCode.RECONNECT: "_handle_reconnect",
    RequestCode.SEND_FILE: "_handle_file_packet",
    RequestCode.CRC_OK: "_handle_crc_ok",
}
GARBLED_BYTES = 10


def main():
    port = int(sys.argv[1])
    code = RequestCode(int(sys.argv[2]))
    failures_left = [int(sys.argv[3])]
    mode = sys.argv[4] if len(sys.argv) > 4 else ""

    def should_fail():
        if failures_left[0] > 0:
            failures_left[0] -= 1
            return True
        return False

    if code == RequestCode.SEND_FILE and mode == "garble":
        real_send = ClientSession._send

        def garbled_send(self, response_code, payload):
            if response_code == ResponseCode.FILE_RECEIVED and should_fail():
                payload = payload[:-GARBLED_BYTES]
            real_send(self, response_code, payload)

        ClientSession._send = garbled_send
    elif code == RequestCode.SEND_FILE and mode != "drop":
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
                if mode == "drop":
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

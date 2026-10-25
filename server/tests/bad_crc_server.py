# Server that sends wrong CRC answers, for testing the client
import logging
import sys
import tempfile

import client_session
from protocol import build_file_received_payload
from storage import ClientStore

from server import Server

CRC_MASK = 0xFFFFFFFF


def main():
    port = int(sys.argv[1])
    bad_left = [int(sys.argv[2])]

    def wrong_cksum_payload(client_id, content_size, file_name, cksum):
        if bad_left[0] > 0:
            bad_left[0] -= 1
            cksum = (cksum + 1) & CRC_MASK
        return build_file_received_payload(client_id, content_size,
                                           file_name, cksum)

    client_session.build_file_received_payload = wrong_cksum_payload
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

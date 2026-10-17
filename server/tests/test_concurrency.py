import os
import threading
import unittest
from pathlib import Path

from cksum import memcrc

from tests.fake_client import (
    CRC_OK,
    FILE_RECEIVED_CODE,
    name_field,
    parse_file_received,
)
from tests.test_server import RSA_KEY, ServerTestCase

CLIENT_COUNT = 8
ACK = 1604


class ConcurrentClientsTest(ServerTestCase):
    def run_client(self, index, results):
        name = f"client{index}"
        data = os.urandom(50_000 + index * 37_000)
        try:
            with self.connect() as client:
                client.register(name)
                client.send_public_key(name, RSA_KEY)
                _, code, payload = client.send_file(data, "data.bin",
                                                    packet_size=8192)
                crc = parse_file_received(payload)[3]
                ack = client.request(CRC_OK, name_field("data.bin"))[1]
                results[index] = (code, crc == memcrc(data), ack,
                                  client.client_id, data)
        except (OSError, ValueError) as e:
            results[index] = e

    def test_clients_in_parallel(self):
        results = [None] * CLIENT_COUNT
        threads = [threading.Thread(target=self.run_client, args=(i, results))
                   for i in range(CLIENT_COUNT)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        ids = set()
        for index, result in enumerate(results):
            with self.subTest(client=index):
                self.assertIsInstance(result, tuple, result)
                code, crc_ok, ack, client_id, data = result
                self.assertEqual(code, FILE_RECEIVED_CODE)
                self.assertTrue(crc_ok)
                self.assertEqual(ack, ACK)
                saved = Path(self.tmp_dir.name) / client_id.hex() / "data.bin"
                self.assertEqual(saved.read_bytes(), data)
                self.assertTrue(
                    self.store.get_file(client_id, "data.bin").verified)
                ids.add(client_id)
        self.assertEqual(len(ids), CLIENT_COUNT)


if __name__ == "__main__":
    unittest.main()

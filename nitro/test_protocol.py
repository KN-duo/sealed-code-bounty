import json
import socket
import struct
import unittest

from protocol import ProtocolError, recv_frame, send_frame


class ProtocolTests(unittest.TestCase):
    def pair(self):
        return socket.socketpair()

    def test_round_trip_and_request_id(self):
        left, right = self.pair()
        with left, right:
            send_frame(left, {"request_id": "r-1", "status": 200})
            self.assertEqual(recv_frame(right), {"request_id": "r-1", "status": 200})

    def test_rejects_zero_and_oversize(self):
        for size in (0, 101):
            left, right = self.pair()
            with left, right:
                left.sendall(struct.pack("!I", size))
                with self.assertRaises(ProtocolError):
                    recv_frame(right, max_bytes=100)

    def test_rejects_truncated_and_non_object_frames(self):
        cases = [b"{", json.dumps([1, 2]).encode()]
        for payload in cases:
            left, right = self.pair()
            with left, right:
                left.sendall(struct.pack("!I", len(payload)) + payload)
                left.shutdown(socket.SHUT_WR)
                with self.assertRaises(ProtocolError):
                    recv_frame(right)


if __name__ == "__main__":
    unittest.main()


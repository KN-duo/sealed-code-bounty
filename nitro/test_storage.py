"""Offline tests only: fake S3, anonymous local socket pairs, no credentials."""

import base64
import contextlib
import hashlib
import io
import json
import socket
import struct
import threading
import unittest
from unittest.mock import patch

from protocol import recv_frame, send_frame
from storage_broker import KEY_PREFIX, S3ObjectStore, SessionAllowance, StorageBroker, serve
from storage_client import exchange, run
from storage_protocol import (
    DeadlineSocket, MAX_OBJECT_BYTES, MAX_STORAGE_FRAME_BYTES, StorageError,
    validate_request,
)

SYNTHETIC_BODY = b'{"sealed":"synthetic-ciphertext","version":1}'
RECEIPT = hashlib.sha256(SYNTHETIC_BODY).hexdigest()


def request(body=SYNTHETIC_BODY):
    return {
        "op": "put", "receipt": hashlib.sha256(body).hexdigest(),
        "body_b64": base64.b64encode(body).decode("ascii"),
    }


class FakeAwsError(Exception):
    def __init__(self, code):
        self.response = {"Error": {"Code": code}}
        super().__init__("DO_NOT_LOG_RESPONSE_BODY")


class FakeS3:
    def __init__(self):
        self.objects = {}
        self.calls = []
        self.put_errors = []
        self.get_error = None
        self.declared_length = None
        self.streams = []

    def get_object(self, **kwargs):
        self.calls.append(("get", kwargs))
        if self.get_error:
            raise self.get_error
        if kwargs["Key"] not in self.objects:
            raise FakeAwsError("NoSuchKey")
        body = self.objects[kwargs["Key"]]
        stream = io.BytesIO(body)
        self.streams.append(stream)
        return {
            "Body": stream,
            "ContentLength": self.declared_length if self.declared_length is not None else len(body),
        }

    def put_object(self, **kwargs):
        self.calls.append(("put", kwargs))
        if self.put_errors:
            raise self.put_errors.pop(0)
        if kwargs["Key"] in self.objects:
            raise FakeAwsError("PreconditionFailed")
        self.objects[kwargs["Key"]] = kwargs["Body"]
        return {}


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.s3 = FakeS3()
        self.store = S3ObjectStore(self.s3, "scb-test-bucket", "123456789012")
        self.broker = StorageBroker(self.store)

    def key(self, receipt=RECEIPT):
        return KEY_PREFIX + receipt + ".json"

    def test_put_get_and_restart_use_exact_bytes_and_fixed_s3_parameters(self):
        self.assertEqual(self.broker.dispatch(request()), {"ok": True})
        put = self.s3.calls[0][1]
        self.assertEqual(put["Key"], self.key())
        self.assertEqual(put["Bucket"], "scb-test-bucket")
        self.assertEqual(put["ExpectedBucketOwner"], "123456789012")
        self.assertEqual(put["IfNoneMatch"], "*")
        self.assertEqual(put["ServerSideEncryption"], "AES256")
        self.assertEqual(put["ChecksumSHA256"], base64.b64encode(bytes.fromhex(RECEIPT)).decode())
        self.assertEqual(self.s3.objects[self.key()], SYNTHETIC_BODY)
        restarted = StorageBroker(S3ObjectStore(self.s3, "scb-test-bucket", "123456789012"))
        self.assertEqual(restarted.dispatch({"op": "get", "receipt": RECEIPT}), {
            "ok": True, "body_b64": request()["body_b64"],
        })
        self.assertTrue(self.s3.streams[-1].closed)

    def test_duplicate_put_verifies_existing_bytes_without_overwrite(self):
        self.broker.dispatch(request())
        self.assertEqual(self.broker.dispatch(request()), {"ok": True})
        self.assertEqual([op for op, _ in self.s3.calls], ["put", "put", "get"])
        self.assertEqual(len(self.s3.objects), 1)

    def test_corrupted_existing_record_is_never_overwritten_or_acknowledged(self):
        self.s3.objects[self.key()] = b"substituted encrypted record"
        self.assertEqual(self.broker.dispatch(request()), {"ok": False, "error": "hash_mismatch"})
        self.assertEqual(self.s3.objects[self.key()], b"substituted encrypted record")

    def test_put_wrong_hash_never_calls_s3(self):
        value = request()
        value["receipt"] = "0" * 64
        self.assertEqual(self.broker.dispatch(value), {"ok": False, "error": "hash_mismatch"})
        self.assertEqual(self.s3.calls, [])

    def test_get_rejects_substitution_and_missing_objects(self):
        value = {"op": "get", "receipt": RECEIPT}
        self.assertEqual(self.broker.dispatch(value), {"ok": False, "error": "not_found"})
        self.s3.objects[self.key()] = b"substitution"
        self.assertEqual(self.broker.dispatch(value), {"ok": False, "error": "hash_mismatch"})
        self.assertTrue(self.s3.streams[-1].closed)

    def test_conflict_is_retried_once_with_precondition(self):
        self.s3.put_errors = [FakeAwsError("ConditionalRequestConflict")]
        self.assertEqual(self.broker.dispatch(request()), {"ok": True})
        self.assertEqual(len(self.s3.calls), 2)
        self.assertTrue(all(args["IfNoneMatch"] == "*" for _, args in self.s3.calls))
        self.s3.put_errors = [FakeAwsError("ConditionalRequestConflict")] * 2
        self.assertEqual(self.broker.dispatch(request()), {"ok": False, "error": "unavailable"})
        self.assertEqual(len(self.s3.calls), 4)

    def test_oversize_object_rejected_before_aws_call(self):
        self.assertEqual(self.broker.dispatch(request(b"a" * (MAX_OBJECT_BYTES + 1))), {
            "ok": False, "error": "too_large",
        })
        self.assertEqual(self.s3.calls, [])

    def test_exact_maximum_roundtrip(self):
        value = request(b"a" * MAX_OBJECT_BYTES)
        self.assertEqual(self.broker.dispatch(value), {"ok": True})
        self.assertEqual(self.broker.dispatch({"op": "get", "receipt": value["receipt"]}), {
            "ok": True, "body_b64": value["body_b64"],
        })

    def test_oversize_get_rejects_declared_and_streamed_lengths_and_closes(self):
        self.s3.objects[self.key()] = b"a" * (MAX_OBJECT_BYTES + 1)
        for declared_length in (MAX_OBJECT_BYTES + 1, 1):
            with self.subTest(declared_length=declared_length):
                self.s3.declared_length = declared_length
                self.assertEqual(self.broker.dispatch({"op": "get", "receipt": RECEIPT}), {
                    "ok": False, "error": "too_large",
                })
                self.assertTrue(self.s3.streams[-1].closed)

    def test_truncated_get_is_not_acknowledged(self):
        self.s3.objects[self.key()] = SYNTHETIC_BODY
        self.s3.declared_length = len(SYNTHETIC_BODY) + 1
        self.assertEqual(self.broker.dispatch({"op": "get", "receipt": RECEIPT}), {
            "ok": False, "error": "unavailable",
        })
        self.assertTrue(self.s3.streams[-1].closed)

    def test_submission_request_schema_rejects_unknown_operations_and_overrides(self):
        invalid = [
            [], None, {}, {"op": "delete", "receipt": RECEIPT},
            {"op": "list", "receipt": RECEIPT}, {"op": [], "receipt": RECEIPT},
            {"op": "get", "receipt": RECEIPT, "Bucket": "elsewhere"},
            {"op": "get", "receipt": RECEIPT, "Key": "../secret"},
            {"op": "get", "receipt": RECEIPT, "url": "https://example.invalid"},
            {"op": "get", "receipt": "../" + RECEIPT},
            {"op": "get", "receipt": RECEIPT.upper()},
            {"op": "get", "receipt": RECEIPT + "\n"},
            {"op": "get", "receipt": 12}, {"op": "put", "receipt": RECEIPT},
            {"op": "put", "receipt": RECEIPT, "body_b64": "%%%"},
            {"op": "put", "receipt": RECEIPT, "body_b64": "ß"},
            {"op": "put", "receipt": RECEIPT, "body_b64": "Zh=="},
        ]
        for value in invalid:
            with self.subTest(value=value):
                self.assertEqual(self.broker.dispatch(value), {"ok": False, "error": "invalid_request"})
        self.assertEqual(self.s3.calls, [])

    def test_errors_are_redacted_and_nothing_is_logged(self):
        self.s3.get_error = FakeAwsError("SecretErrorWithCredentials")
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            result = self.broker.dispatch({"op": "get", "receipt": RECEIPT})
        self.assertEqual(result, {"ok": False, "error": "unavailable"})
        self.assertEqual((out.getvalue(), err.getvalue()), ("", ""))

    def test_session_allowance_counts_retries_and_blocks_before_aws(self):
        broker = StorageBroker(self.store, SessionAllowance(10, len(SYNTHETIC_BODY)))
        self.assertEqual(broker.dispatch(request()), {"ok": True})
        self.assertEqual(broker.dispatch(request()), {"ok": False, "error": "storage_full"})
        self.assertEqual(len(self.s3.calls), 1)
        self.assertTrue(broker.dispatch({"op": "get", "receipt": RECEIPT})["ok"])
        broker = StorageBroker(self.store, SessionAllowance(1, 1024))
        broker.dispatch({"op": "get", "receipt": RECEIPT})
        before = len(self.s3.calls)
        self.assertEqual(broker.dispatch({"op": "get", "receipt": RECEIPT}), {
            "ok": False, "error": "unavailable",
        })
        self.assertEqual(len(self.s3.calls), before)


class HelperTests(unittest.TestCase):
    def invoke(self, payload, transport=lambda req, port: {"ok": True}):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stderr(err):
            run(io.BytesIO(payload), out, transport)
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(out.getvalue().count("\n"), 1)
        return json.loads(out.getvalue())

    def test_stdin_bounds_syntax_and_duplicate_keys(self):
        for payload in (b"", b"[]", b"{}{}", b"\xff", b'{"op":"get","op":"put"}'):
            self.assertEqual(self.invoke(payload), {"ok": False, "error": "invalid_request"})
        self.assertEqual(self.invoke(b" " * (MAX_STORAGE_FRAME_BYTES + 1)), {
            "ok": False, "error": "too_large",
        })

    def test_configured_port_and_parent_errors_never_leak(self):
        seen = []
        def transport(value, port):
            seen.append((value, port))
            raise RuntimeError("DO_NOT_LOG_BODY")
        with patch.dict("os.environ", {"SCB_STORAGE_VSOCK_PORT": "5012"}):
            self.assertEqual(self.invoke(json.dumps(request()).encode(), transport), {
                "ok": False, "error": "unavailable",
            })
        self.assertEqual(seen, [(request(), 5012)])

    def test_parent_response_is_checked_for_hash_shape_and_error_redaction(self):
        get = json.dumps({"op": "get", "receipt": RECEIPT}).encode()
        cases = [
            ({"ok": True, "body_b64": base64.b64encode(b"substitution").decode()}, "hash_mismatch"),
            ({"ok": True, "body_b64": base64.b64encode(b"a" * (MAX_OBJECT_BYTES + 1)).decode()}, "too_large"),
            ({"ok": True, "body_b64": request()["body_b64"], "secret": "DO_NOT_ECHO"}, "unavailable"),
            ({"ok": False, "error": "DO_NOT_ECHO"}, "unavailable"),
            ({"ok": False, "error": []}, "unavailable"),
            ({"ok": 1, "body_b64": request()["body_b64"]}, "unavailable"),
        ]
        for response, error in cases:
            with self.subTest(error=error):
                self.assertEqual(self.invoke(get, lambda *_: response), {"ok": False, "error": error})

    def test_unknown_parent_put_fields_are_not_printed(self):
        self.assertEqual(self.invoke(json.dumps(request()).encode(), lambda *_: {
            "ok": True, "secret": "DO_NOT_ECHO",
        }), {"ok": False, "error": "unavailable"})

    def test_put_get_over_socketpair(self):
        fake = FakeS3()
        broker = StorageBroker(S3ObjectStore(fake, "scb-test-bucket", "123456789012"))
        for value in (request(), {"op": "get", "receipt": RECEIPT}):
            left, right = socket.socketpair()
            worker = threading.Thread(target=broker.handle, args=(right,))
            with left, right:
                worker.start()
                try:
                    response = exchange(left, value)
                    self.assertTrue(response["ok"])
                    if value["op"] == "get":
                        self.assertEqual(response["body_b64"], request()["body_b64"])
                finally:
                    worker.join(timeout=2)
                self.assertFalse(worker.is_alive())

    def test_disconnect_after_successful_put_can_retry_without_overwrite(self):
        fake = FakeS3()
        broker = StorageBroker(S3ObjectStore(fake, "scb-test-bucket", "123456789012"))
        left, right = socket.socketpair()
        send_frame(left, request())
        left.close()
        with right:
            broker.handle(right)
        self.assertEqual(fake.objects[KEY_PREFIX + RECEIPT + ".json"], SYNTHETIC_BODY)
        self.assertEqual(broker.dispatch(request()), {"ok": True})
        self.assertEqual(len(fake.objects), 1)

    def test_invalid_frame_does_not_reach_s3(self):
        for payload in (struct.pack("!I", MAX_STORAGE_FRAME_BYTES + 1), b"\0\0\0\x04{"):
            fake = FakeS3()
            broker = StorageBroker(S3ObjectStore(fake, "scb-test-bucket", "123456789012"))
            left, right = socket.socketpair()
            with left, right:
                left.sendall(payload)
                left.shutdown(socket.SHUT_WR)
                broker.handle(right)
                self.assertEqual(recv_frame(left), {"ok": False, "error": "invalid_request"})
            self.assertEqual(fake.calls, [])

    def test_whole_frame_deadline_cannot_be_extended_by_small_reads(self):
        class Channel:
            def settimeout(self, _):
                pass
            def recv(self, _):
                return b"a"
        with patch("storage_protocol.time.monotonic", side_effect=[1, 5, 12]):
            wire = DeadlineSocket(Channel(), timeout=10)
            self.assertEqual(wire.recv(1), b"a")
            with self.assertRaises(TimeoutError):
                wire.recv(1)

    def test_bounded_workers_and_wrong_peer_are_rejected(self):
        entered, release = threading.Event(), threading.Event()
        class Channel:
            closed = False
            def close(self):
                self.closed = True
            def __enter__(self):
                return self
            def __exit__(self, *_):
                self.close()
        handled = []
        class Broker:
            def handle(self, channel):
                handled.append(channel)
                entered.set()
                release.wait(2)
        channels = [Channel(), Channel(), Channel()]
        class Listener:
            index = 0
            def accept(self):
                if self.index == 3:
                    release.set()
                    raise StopIteration
                if self.index == 1:
                    self_entered = entered.wait(2)
                    if not self_entered:
                        raise RuntimeError("worker did not enter")
                index = self.index
                self.index += 1
                return channels[index], (16 if index < 2 else 17, 9999)
        with self.assertRaises(StopIteration):
            serve(Listener(), Broker(), enclave_cid=16, workers=1)
        self.assertEqual(handled, [channels[0]])
        self.assertTrue(all(channel.closed for channel in channels))


if __name__ == "__main__":
    unittest.main()

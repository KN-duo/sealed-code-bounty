"""Offline adversarial tests for bounded artifact reads; no AWS credentials."""

import base64
import io
import json
import unittest

from storage_broker import S3ObjectStore, SessionAllowance, StorageBroker
from storage_client import run
from storage_protocol import ARTIFACT_CHUNK_BYTES, ARTIFACT_LIMITS
from test_storage import FakeAwsError

HASH = "a" * 64
CHUNK = ARTIFACT_CHUNK_BYTES


def request(kind="manifest", offset=0):
    return {"op": "get_artifact", "kind": kind, "sha256": HASH, "offset": offset}


class ArtifactS3:
    def __init__(self, data=b'{"schema": "synthetic"}'):
        self.data = data
        self.calls, self.streams = [], []
        self.overrides = {}
        self.override_body = None
        self.error = None

    def get_object(self, **kwargs):
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        start, end = map(int, kwargs["Range"][6:].split("-"))
        if start >= len(self.data):
            raise FakeAwsError("InvalidRange")
        end = min(end, len(self.data) - 1)
        data = self.data[start:end + 1] if self.override_body is None else self.override_body
        stream = io.BytesIO(data)
        self.streams.append(stream)
        return {
            "Body": stream, "ContentRange": f"bytes {start}-{end}/{len(self.data)}",
            "ContentLength": end - start + 1, **self.overrides,
        }


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.s3 = ArtifactS3()
        self.store = S3ObjectStore(self.s3, "scb-test-bucket", "123456789012")
        self.broker = StorageBroker(self.store)

    def test_manifest_uses_fixed_key_bucket_owner_and_range(self):
        response = self.broker.dispatch(request())
        self.assertEqual(response, {
            "ok": True, "body_b64": base64.b64encode(self.s3.data).decode(),
            "offset": 0, "total_bytes": len(self.s3.data),
        })
        self.assertEqual(self.s3.calls, [{
            "Bucket": "scb-test-bucket", "ExpectedBucketOwner": "123456789012",
            "Key": f"scb/manifests/{HASH}.json", "Range": "bytes=0-65535",
        }])
        self.assertTrue(self.s3.streams[0].closed)

    def test_environment_chunks_include_short_final_chunk(self):
        self.s3.data = b"x" * CHUNK + b"tail"
        responses = [self.broker.dispatch(request("environment", offset)) for offset in (0, CHUNK)]
        self.assertEqual([base64.b64decode(item["body_b64"]) for item in responses], [b"x" * CHUNK, b"tail"])
        self.assertEqual([item["offset"] for item in responses], [0, CHUNK])
        self.assertEqual([item["total_bytes"] for item in responses], [CHUNK + 4] * 2)
        self.assertEqual([call["Range"] for call in self.s3.calls], [
            f"bytes=0-{CHUNK - 1}", f"bytes={CHUNK}-{2 * CHUNK - 1}",
        ])
        self.assertTrue(all(call["Key"] == f"scb/envs/{HASH}.tar.gz" for call in self.s3.calls))
        self.assertTrue(all(stream.closed for stream in self.s3.streams))

    def test_exact_manifest_limit_and_nonzero_offset(self):
        self.s3.data = b"x" * ARTIFACT_LIMITS["manifest"]
        for offset in (0, 1, len(self.s3.data) - 1):
            response = self.broker.dispatch(request(offset=offset))
            self.assertTrue(response["ok"])
            self.assertEqual(base64.b64decode(response["body_b64"]), self.s3.data[offset:])
            self.assertEqual(self.s3.calls[-1]["Range"], f"bytes={offset}-65535")

    def test_final_byte_at_environment_cap(self):
        cap = ARTIFACT_LIMITS["environment"]
        # Simulate a large object without allocating its entire contents.
        self.s3.data = b"x"
        self.s3.overrides = {"ContentRange": f"bytes {cap - 1}-{cap - 1}/{cap}", "ContentLength": 1}
        original = self.s3.get_object
        def get_object(**kwargs):
            saved = kwargs.copy()
            kwargs["Range"] = "bytes=0-0"
            result = original(**kwargs)
            self.s3.calls[-1] = saved
            return result
        self.s3.get_object = get_object
        response = self.broker.dispatch(request("environment", cap - 1))
        self.assertTrue(response["ok"])
        self.assertEqual(response["offset"], cap - 1)
        self.assertEqual(self.s3.calls[0]["Range"], f"bytes={cap - 1}-{cap - 1}")

    def test_invalid_request_fields_never_call_s3(self):
        cases = [
            {**request(), "url": "https://example.invalid"},
            {**request(), "key": "../secret"}, {**request(), "bucket": "elsewhere"},
            {**request(), "Range": "bytes=0-99999999999"},
            {**request(), "kind": "submission"}, {**request(), "kind": []},
            {**request(), "sha256": "../" + HASH}, {**request(), "sha256": HASH.upper()},
            {**request(), "sha256": HASH + "\n"},
        ]
        cases += [{**request(), "offset": offset} for offset in (-1, 1.0, True, "0", None, 65536, 10**100)]
        cases += [request("environment", ARTIFACT_LIMITS["environment"])]
        for value in cases:
            with self.subTest(value=value):
                self.assertEqual(self.broker.dispatch(value), {"ok": False, "error": "invalid_request"})
        self.assertEqual(self.s3.calls, [])

    def test_bad_content_ranges_close_streams(self):
        total = len(self.s3.data)
        invalid = [None, 5, "", "bytes */10", "bytes 0-1/*", "bytes 0-1/0",
                   f"bytes 1-{total - 1}/{total}", f"bytes 0-{total - 2}/{total}",
                   f"bytes 0-{total}/{total}", f"bytes 00-{total - 1}/{total}",
                   f"bytes 0-{total - 1}/{total}\n", "bytes 0-0/999999999999999999999999"]
        for content_range in invalid:
            with self.subTest(content_range=content_range):
                self.s3.overrides = {"ContentRange": content_range}
                self.assertEqual(self.broker.dispatch(request()), {"ok": False, "error": "unavailable"})
                self.assertTrue(self.s3.streams[-1].closed)

    def test_oversized_total_rejected_even_for_small_first_chunk(self):
        for kind, cap in ARTIFACT_LIMITS.items():
            self.s3.overrides = {"ContentRange": f"bytes 0-{len(self.s3.data) - 1}/{cap + 1}"}
            self.assertEqual(self.broker.dispatch(request(kind)), {"ok": False, "error": "too_large"})
            self.assertTrue(self.s3.streams[-1].closed)

    def test_declared_length_must_match_range(self):
        for length in (None, True, -1, 0, "22", len(self.s3.data) - 1, len(self.s3.data) + 1):
            self.s3.overrides = {"ContentLength": length}
            self.assertEqual(self.broker.dispatch(request()), {"ok": False, "error": "unavailable"})
            self.assertTrue(self.s3.streams[-1].closed)

    def test_truncated_and_excess_stream_bytes_are_rejected(self):
        for data, error in [(b"", "unavailable"), (self.s3.data[:-1], "unavailable"),
                            (self.s3.data + b"x", "too_large"), (b"x" * (CHUNK + 1), "too_large")]:
            self.s3.override_body = data
            self.assertEqual(self.broker.dispatch(request()), {"ok": False, "error": error})
            self.assertTrue(self.s3.streams[-1].closed)

    def test_empty_missing_and_out_of_object_offsets_fail(self):
        self.assertEqual(self.broker.dispatch(request(offset=len(self.s3.data))), {
            "ok": False, "error": "unavailable",
        })
        self.s3.data = b""
        self.assertEqual(self.broker.dispatch(request()), {"ok": False, "error": "unavailable"})
        self.s3.error = FakeAwsError("NoSuchKey")
        self.assertEqual(self.broker.dispatch(request()), {"ok": False, "error": "not_found"})
        self.s3.error = FakeAwsError("DO_NOT_LOG")
        self.assertEqual(self.broker.dispatch(request()), {"ok": False, "error": "unavailable"})

    def test_stream_read_failure_closes_stream(self):
        class BrokenStream(io.BytesIO):
            def read(self, _):
                raise OSError("DO_NOT_LOG")
        stream = BrokenStream()
        self.s3.overrides = {"Body": stream}
        self.assertEqual(self.broker.dispatch(request()), {"ok": False, "error": "unavailable"})
        self.assertTrue(stream.closed)

    def test_artifact_reads_share_request_allowance(self):
        broker = StorageBroker(self.store, SessionAllowance(1, 1))
        self.assertTrue(broker.dispatch(request())["ok"])
        self.assertEqual(broker.dispatch(request()), {"ok": False, "error": "unavailable"})
        self.assertEqual(len(self.s3.calls), 1)


class ArtifactHelperTests(unittest.TestCase):
    def invoke(self, value, response):
        out = io.StringIO()
        run(io.BytesIO(json.dumps(value).encode()), out, lambda *_: response)
        return json.loads(out.getvalue())

    def test_valid_chunk_passes_without_claiming_hash_authentication(self):
        # This hash intentionally does not match: only the full Rust assembly
        # can be authenticated, never an independently fetched chunk.
        response = {"ok": True, "body_b64": "eA==", "offset": 0, "total_bytes": 1}
        self.assertEqual(self.invoke(request(), response), response)

    def test_parent_metadata_and_chunk_length_are_untrusted(self):
        good = {"ok": True, "body_b64": "eA==", "offset": 0, "total_bytes": 1}
        responses = [
            {**good, "secret": "DO_NOT_ECHO"}, {**good, "offset": True},
            {**good, "offset": 1}, {**good, "offset": -1}, {**good, "offset": "0"},
            {**good, "total_bytes": True}, {**good, "total_bytes": 0},
            {**good, "total_bytes": -1}, {**good, "total_bytes": 2},
            {**good, "total_bytes": "1"}, {**good, "body_b64": ""},
        ]
        for response in responses:
            self.assertEqual(self.invoke(request(), response), {"ok": False, "error": "unavailable"})
        self.assertEqual(self.invoke(request(), {**good, "total_bytes": 65537}), {
            "ok": False, "error": "too_large",
        })

    def test_chunk_must_be_exact_size_until_final_chunk(self):
        response = {
            "ok": True, "body_b64": base64.b64encode(b"x" * CHUNK).decode(),
            "offset": 0, "total_bytes": CHUNK + 1,
        }
        self.assertEqual(self.invoke(request("environment"), response), response)
        response["body_b64"] = base64.b64encode(b"x" * (CHUNK - 1)).decode()
        self.assertEqual(self.invoke(request("environment"), response), {"ok": False, "error": "unavailable"})
        response.update(body_b64="eA==", offset=CHUNK)
        self.assertEqual(self.invoke(request("environment", CHUNK), response), response)


if __name__ == "__main__":
    unittest.main()

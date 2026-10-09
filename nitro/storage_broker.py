#!/usr/bin/env python3
"""Fixed-bucket S3 bridge for encrypted submissions and committed CTF artifacts."""

import base64
import hashlib
import json
import os
import re
import socket
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

from protocol import ProtocolError, recv_frame, send_frame
from storage_protocol import (
    ARTIFACT_CHUNK_BYTES, ARTIFACT_LIMITS, DeadlineSocket, MAX_OBJECT_BYTES,
    MAX_STORAGE_FRAME_BYTES, StorageError, check_hash, error_response,
    validate_artifact_request, validate_receipt, validate_request,
)

KEY_PREFIX = "scb/submissions/"
ARTIFACT_KEYS = {
    "manifest": ("scb/manifests/", ".json"),
    "environment": ("scb/envs/", ".tar.gz"),
}
CONTENT_RANGE_RE = re.compile(
    r"bytes (0|[1-9][0-9]{0,9})-(0|[1-9][0-9]{0,9})/(0|[1-9][0-9]{0,9})\Z",
    re.ASCII,
)


def aws_error_code(exc):
    response = getattr(exc, "response", {})
    error = response.get("Error", {}) if isinstance(response, dict) else {}
    return error.get("Code", "") if isinstance(error, dict) else ""


class S3ObjectStore:
    """Inject an S3 client for offline tests; bucket and owner are operator config."""

    def __init__(self, client, bucket, owner):
        if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket):
            raise ValueError("invalid bucket configuration")
        if not re.fullmatch(r"[0-9]{12}", owner):
            raise ValueError("invalid bucket owner configuration")
        self.client = client
        self.bucket = bucket
        self.owner = owner

    def arguments(self, receipt):
        validate_receipt(receipt)
        return {
            "Bucket": self.bucket,
            "Key": KEY_PREFIX + receipt + ".json",
            "ExpectedBucketOwner": self.owner,
        }

    def get(self, receipt):
        try:
            response = self.client.get_object(**self.arguments(receipt))
        except Exception as exc:
            if aws_error_code(exc) in ("NoSuchKey", "404", "NotFound"):
                raise StorageError("not_found") from None
            raise StorageError("unavailable") from None
        stream = response["Body"]
        try:
            length = response.get("ContentLength")
            if type(length) is not int or length < 0:
                raise StorageError("unavailable")
            if length > MAX_OBJECT_BYTES:
                raise StorageError("too_large")
            chunks = []
            received = 0
            while True:
                chunk = stream.read(min(65536, MAX_OBJECT_BYTES + 1 - received))
                if not chunk:
                    break
                received += len(chunk)
                if received > MAX_OBJECT_BYTES:
                    raise StorageError("too_large")
                chunks.append(chunk)
            if received != length:
                raise StorageError("unavailable")
            body = b"".join(chunks)
            check_hash(receipt, body)
            return body
        except StorageError:
            raise
        except Exception:
            raise StorageError("unavailable") from None
        finally:
            stream.close()

    def put(self, receipt, body):
        # Request validation happens before entry; retain checks for direct callers.
        if len(body) > MAX_OBJECT_BYTES:
            raise StorageError("too_large")
        check_hash(receipt, body)
        arguments = self.arguments(receipt)
        for attempt in range(2):
            try:
                self.client.put_object(
                    **arguments, Body=body, ContentLength=len(body),
                    ContentType="application/json", IfNoneMatch="*",
                    ServerSideEncryption="AES256",
                    ChecksumSHA256=base64.b64encode(hashlib.sha256(body).digest()).decode("ascii"),
                )
                return
            except Exception as exc:
                code = aws_error_code(exc)
                if code in ("PreconditionFailed", "412"):
                    # A retry must verify existing bytes, not merely trust metadata.
                    if self.get(receipt) != body:
                        raise StorageError("hash_mismatch")
                    return
                if code in ("ConditionalRequestConflict", "409") and attempt == 0:
                    continue
                raise StorageError("unavailable") from None

    def get_artifact(self, kind, sha256, offset):
        validate_artifact_request(kind, sha256, offset)
        cap = ARTIFACT_LIMITS[kind]
        prefix, suffix = ARTIFACT_KEYS[kind]
        end = min(offset + ARTIFACT_CHUNK_BYTES, cap) - 1
        try:
            response = self.client.get_object(
                Bucket=self.bucket, ExpectedBucketOwner=self.owner,
                Key=prefix + sha256 + suffix, Range=f"bytes={offset}-{end}",
            )
        except Exception as exc:
            if aws_error_code(exc) in ("NoSuchKey", "404", "NotFound"):
                raise StorageError("not_found") from None
            raise StorageError("unavailable") from None
        stream = response.get("Body")
        try:
            content_range = response.get("ContentRange")
            match = CONTENT_RANGE_RE.fullmatch(content_range) if isinstance(content_range, str) else None
            if match is None:
                raise StorageError("unavailable")
            start, actual_end, total = map(int, match.groups())
            if total > cap:
                raise StorageError("too_large")
            if not 0 <= offset < total or start != offset or actual_end != min(end, total - 1):
                raise StorageError("unavailable")
            expected = actual_end - start + 1
            length = response.get("ContentLength")
            if type(length) is not int or length != expected:
                raise StorageError("unavailable")
            # Read one extra byte to reject excess data as well as truncation.
            # Never trust an SDK/parent's declared length as the only cap.
            chunks, received = [], 0
            while received <= expected:
                chunk = stream.read(min(65536, expected + 1 - received))
                if not chunk:
                    break
                received += len(chunk)
                if received > expected:
                    raise StorageError("too_large")
                chunks.append(chunk)
            if received != expected:
                raise StorageError("unavailable")
            return b"".join(chunks), total
        except StorageError:
            raise
        except Exception:
            raise StorageError("unavailable") from None
        finally:
            if stream is not None:
                stream.close()


class SessionAllowance:
    """Process-local admission limits; deliberately NOT a global cost/byte quota."""

    def __init__(self, max_requests=1024, max_put_bytes=16 * 1024 * 1024):
        if max_requests < 1 or max_put_bytes < 1:
            raise ValueError("invalid session allowance")
        self.requests = max_requests
        self.put_bytes = max_put_bytes
        self.lock = threading.Lock()

    def admit(self, op, body):
        with self.lock:
            if self.requests <= 0:
                raise StorageError("unavailable")
            self.requests -= 1
            if op == "put":
                if len(body) > self.put_bytes:
                    raise StorageError("storage_full")
                # Failed writes and retries count too. Restarting resets these limits.
                self.put_bytes -= len(body)


class StorageBroker:
    def __init__(self, store, allowance=None):
        self.store = store
        self.allowance = allowance or SessionAllowance()

    def dispatch(self, request):
        try:
            op, receipt, body = validate_request(request)
            self.allowance.admit(op, body)
            if op == "put":
                self.store.put(receipt, body)
                return {"ok": True}
            if op == "get_artifact":
                body, total = self.store.get_artifact(request["kind"], receipt, request["offset"])
                return {
                    "ok": True, "body_b64": base64.b64encode(body).decode("ascii"),
                    "offset": request["offset"], "total_bytes": total,
                }
            body = self.store.get(receipt)
            return {"ok": True, "body_b64": base64.b64encode(body).decode("ascii")}
        except StorageError as exc:
            return error_response(exc.code)
        except Exception:
            return error_response("unavailable")

    def handle(self, channel):
        wire = DeadlineSocket(channel)
        try:
            request = recv_frame(wire, MAX_STORAGE_FRAME_BYTES)
            response = self.dispatch(request)
        except (ProtocolError, ValueError, RecursionError):
            response = error_response("invalid_request")
        except Exception:
            response = error_response("unavailable")
        try:
            send_frame(wire, response, MAX_STORAGE_FRAME_BYTES)
        except Exception:
            # Disconnects are safe: a completed conditional put can be retried.
            pass


def serve(server, broker, enclave_cid=16, workers=2):
    if not 1 <= workers <= 8:
        raise ValueError("invalid worker count")
    slots = threading.BoundedSemaphore(workers)

    def serve_one(channel):
        try:
            with channel:
                broker.handle(channel)
        finally:
            slots.release()

    with ThreadPoolExecutor(max_workers=workers) as pool:
        while True:
            channel, peer = server.accept()
            # Kernel-reported CID and a bounded executor prevent arbitrary peers
            # from reaching S3 or filling an unbounded work queue.
            if peer[0] != enclave_cid or not slots.acquire(blocking=False):
                channel.close()
                continue
            try:
                pool.submit(serve_one, channel)
            except Exception:
                channel.close()
                slots.release()
                raise


def main():
    try:
        # Only the parent installs boto3 or receives AWS credentials.
        import boto3
        from botocore.config import Config

        bucket = os.environ["SCB_STORAGE_BUCKET"]
        owner = os.environ["SCB_STORAGE_BUCKET_OWNER"]
        region = os.environ.get("AWS_REGION", "eu-north-1")
        port = int(os.environ.get("SCB_STORAGE_VSOCK_PORT", "5001"))
        enclave_cid = int(os.environ.get("SCB_ENCLAVE_CID", "16"))
        workers = int(os.environ.get("SCB_STORAGE_WORKERS", "2"))
        if not 1 <= port <= 0xFFFFFFFF or not 4 <= enclave_cid < 0xFFFFFFFF:
            raise ValueError("invalid vsock configuration")
        # Endpoint discovery/override is not part of the request protocol.
        client = boto3.client("s3", region_name=region, config=Config(
            connect_timeout=2, read_timeout=3,
            retries={"mode": "standard", "total_max_attempts": 1},
            max_pool_connections=workers,
        ))
        allowance = SessionAllowance(
            int(os.environ.get("SCB_STORAGE_MAX_REQUESTS", "1024")),
            int(os.environ.get("SCB_STORAGE_MAX_PUT_BYTES", str(16 * 1024 * 1024))),
        )
        broker = StorageBroker(S3ObjectStore(client, bucket, owner), allowance)
        with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as server:
            server.bind((socket.VMADDR_CID_ANY, port))
            server.listen(8)
            serve(server, broker, enclave_cid, workers)
    except KeyboardInterrupt:
        return 0
    except Exception:
        # Deliberately omit exception text: SDK errors may contain sensitive data.
        print(json.dumps({"scope": "storage-broker", "error": "unavailable"}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

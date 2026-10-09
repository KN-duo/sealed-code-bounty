"""Bounded encrypted submissions and public CTF artifacts; no arbitrary URLs."""

import base64
import binascii
import hashlib
import re
import time

MAX_OBJECT_BYTES = 512 * 1024
ARTIFACT_CHUNK_BYTES = 512 * 1024
ARTIFACT_LIMITS = {"manifest": 64 * 1024, "environment": 128 * 1024 * 1024}
MAX_STORAGE_FRAME_BYTES = 1024 * 1024
STORAGE_TIMEOUT_S = 10.0
ERRORS = frozenset({
    "not_found", "too_large", "hash_mismatch", "storage_full", "unavailable",
    "invalid_request",
})
RECEIPT_RE = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)


class StorageError(Exception):
    def __init__(self, code):
        self.code = code if code in ERRORS else "unavailable"
        super().__init__(self.code)


def error_response(code):
    return {"ok": False, "error": code if code in ERRORS else "unavailable"}


def validate_receipt(receipt):
    if not isinstance(receipt, str) or not RECEIPT_RE.fullmatch(receipt):
        raise StorageError("invalid_request")


def decode_body(value):
    if not isinstance(value, str):
        raise StorageError("invalid_request")
    if len(value) > 4 * ((MAX_OBJECT_BYTES + 2) // 3):
        raise StorageError("too_large")
    try:
        body = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise StorageError("invalid_request") from None
    if len(body) > MAX_OBJECT_BYTES:
        raise StorageError("too_large")
    if base64.b64encode(body).decode("ascii") != value:
        raise StorageError("invalid_request")
    return body


def check_hash(receipt, body):
    if hashlib.sha256(body).hexdigest() != receipt:
        raise StorageError("hash_mismatch")


def validate_artifact_request(kind, sha256, offset):
    if not isinstance(kind, str) or kind not in ARTIFACT_LIMITS:
        raise StorageError("invalid_request")
    validate_receipt(sha256)
    if type(offset) is not int or not 0 <= offset < ARTIFACT_LIMITS[kind]:
        raise StorageError("invalid_request")


def validate_request(request):
    if not isinstance(request, dict):
        raise StorageError("invalid_request")
    op = request.get("op")
    if op == "get_artifact":
        if request.keys() != {"op", "kind", "sha256", "offset"}:
            raise StorageError("invalid_request")
        validate_artifact_request(request["kind"], request["sha256"], request["offset"])
        return op, request["sha256"], None
    if op not in ("get", "put"):
        raise StorageError("invalid_request")
    expected = {"op", "receipt", "body_b64"} if op == "put" else {"op", "receipt"}
    if request.keys() != expected:
        raise StorageError("invalid_request")
    receipt = request["receipt"]
    validate_receipt(receipt)
    body = decode_body(request["body_b64"]) if op == "put" else None
    if body is not None:
        check_hash(receipt, body)
    return op, receipt, body


def validate_response(request, response):
    """Treat the parent response as untrusted, including its error strings."""
    if not isinstance(response, dict):
        raise StorageError("unavailable")
    if response.get("ok") is False:
        if (response.keys() != {"ok", "error"}
                or not isinstance(response.get("error"), str)
                or response["error"] not in ERRORS):
            raise StorageError("unavailable")
        return response
    if response.get("ok") is not True:
        raise StorageError("unavailable")
    if request["op"] == "put":
        if response != {"ok": True}:
            raise StorageError("unavailable")
    elif request["op"] == "get_artifact":
        if response.keys() != {"ok", "body_b64", "offset", "total_bytes"}:
            raise StorageError("unavailable")
        total, offset = response["total_bytes"], response["offset"]
        if (type(total) is not int or type(offset) is not int
                or offset != request["offset"] or not 0 <= offset < total):
            raise StorageError("unavailable")
        if total > ARTIFACT_LIMITS[request["kind"]]:
            raise StorageError("too_large")
        body = decode_body(response["body_b64"])
        if len(body) != min(ARTIFACT_CHUNK_BYTES, total - offset):
            raise StorageError("unavailable")
        # A chunk has no independent digest. The Rust caller checks the complete
        # assembled object's SHA-256 against its on-chain commitment.
    else:
        if response.keys() != {"ok", "body_b64"}:
            raise StorageError("unavailable")
        body = decode_body(response["body_b64"])
        check_hash(request["receipt"], body)
    return response


class DeadlineSocket:
    """A whole-frame deadline prevents drip-fed frames from occupying a worker."""

    def __init__(self, channel, timeout=STORAGE_TIMEOUT_S):
        self.channel = channel
        self.deadline = time.monotonic() + timeout

    def remaining(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("storage deadline")
        self.channel.settimeout(remaining)

    def recv(self, size):
        self.remaining()
        return self.channel.recv(size)

    def sendall(self, data):
        self.remaining()
        self.channel.sendall(data)

#!/usr/bin/env python3
"""Enclave helper for encrypted records and public, hash-committed CTF artifacts.

One bounded JSON stdin request produces one bounded JSON stdout response. The
Rust caller authenticates assembled artifact bytes; this helper only validates
chunk framing and lengths. Submission records retain their whole-record hash.
"""

import json
import os
import socket
import sys

from protocol import recv_frame, send_frame
from storage_protocol import (
    DeadlineSocket, MAX_STORAGE_FRAME_BYTES, STORAGE_TIMEOUT_S, StorageError,
    error_response, validate_request, validate_response,
)

PARENT_CID = 3


def exchange(channel, request):
    validate_request(request)
    wire = DeadlineSocket(channel)
    send_frame(wire, request, MAX_STORAGE_FRAME_BYTES)
    response = recv_frame(wire, MAX_STORAGE_FRAME_BYTES)
    return validate_response(request, response)


def forward(request, port):
    validate_request(request)
    # No HTTP/TCP fallback or user-selected parent address.
    with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as channel:
        channel.settimeout(STORAGE_TIMEOUT_S)
        channel.connect((PARENT_CID, port))
        return exchange(channel, request)


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise StorageError("invalid_request")
        value[key] = item
    return value


def run(stdin, stdout, transport=forward):
    try:
        payload = stdin.read(MAX_STORAGE_FRAME_BYTES + 1)
        if len(payload) > MAX_STORAGE_FRAME_BYTES:
            raise StorageError("too_large")
        request = json.loads(payload, object_pairs_hook=_unique_object)
        validate_request(request)
        port = int(os.environ.get("SCB_STORAGE_VSOCK_PORT", "5001"))
        if not 1 <= port <= 0xFFFFFFFF:
            raise StorageError("unavailable")
        response = validate_response(request, transport(request, port))
    except StorageError as exc:
        response = error_response(exc.code)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        response = error_response("invalid_request")
    except Exception:
        # Never print OS errors, stack traces, request bodies, or S3 responses.
        response = error_response("unavailable")
    stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
    stdout.flush()


if __name__ == "__main__":
    run(sys.stdin.buffer, sys.stdout)

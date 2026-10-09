"""Fail-closed framing shared by the Nitro parent and enclave proxies."""

import json
import struct

MAX_FRAME_BYTES = 8 * 1024 * 1024
HEADER = struct.Struct("!I")


class ProtocolError(Exception):
    pass


def _read_exact(sock, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ProtocolError("connection closed mid-frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def recv_frame(sock, max_bytes: int = MAX_FRAME_BYTES) -> dict:
    (size,) = HEADER.unpack(_read_exact(sock, HEADER.size))
    if size == 0 or size > max_bytes:
        raise ProtocolError(f"invalid frame size: {size}")
    try:
        value = json.loads(_read_exact(sock, size))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("frame is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ProtocolError("frame must be a JSON object")
    return value


def send_frame(sock, value: dict, max_bytes: int = MAX_FRAME_BYTES) -> None:
    payload = json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode()
    if not payload or len(payload) > max_bytes:
        raise ProtocolError(f"invalid frame size: {len(payload)}")
    sock.sendall(HEADER.pack(len(payload)) + payload)


#!/usr/bin/env python3
"""Vsock-only enclave entrypoint forwarding an allowlisted API to scb-runner."""

import base64
import http.client
import os
import socket

from protocol import ProtocolError, recv_frame, send_frame

VSOCK_PORT = int(os.environ.get("SCB_VSOCK_PORT", "5000"))
RUNNER_HOST = "127.0.0.1"
RUNNER_PORT = int(os.environ.get("PORT", "8443"))
TIMEOUT = float(os.environ.get("SCB_PROXY_TIMEOUT_S", "310"))
ALLOWED = {
    ("GET", "/internal/healthz"),
    ("POST", "/internal/attestation"),
    ("GET", "/internal/enclave-pubkey"),
    ("GET", "/internal/operator-pubkey"),
    ("POST", "/internal/seal_bounty"),
    ("POST", "/internal/upload"),
    ("POST", "/internal/verify"),
}


def handle(conn) -> None:
    request_id = "unknown"
    try:
        req = recv_frame(conn)
        request_id = req.get("request_id")
        method, path = req.get("method"), req.get("path")
        if not isinstance(request_id, str) or not (1 <= len(request_id) <= 128):
            raise ProtocolError("invalid request_id")
        if (method, path) not in ALLOWED:
            raise ProtocolError("endpoint is not allowed")
        body = base64.b64decode(req.get("body_b64", ""), validate=True)
        upstream = http.client.HTTPConnection(RUNNER_HOST, RUNNER_PORT, timeout=TIMEOUT)
        upstream.request(method, path, body=body, headers={"content-type": "application/json"})
        response = upstream.getresponse()
        response_body = response.read()
        send_frame(conn, {
            "request_id": request_id,
            "status": response.status,
            "body_b64": base64.b64encode(response_body).decode(),
        })
    except Exception as exc:
        # Never echo request bodies, plaintext submissions, or upstream output.
        send_frame(conn, {"request_id": request_id, "status": 400, "error": type(exc).__name__})


def main() -> None:
    server = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    server.bind((socket.VMADDR_CID_ANY, VSOCK_PORT))
    server.listen(16)
    while True:
        conn, _ = server.accept()
        with conn:
            conn.settimeout(TIMEOUT)
            handle(conn)


if __name__ == "__main__":
    main()


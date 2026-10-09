#!/usr/bin/env python3
"""Loopback HTTP-to-vsock proxy for a single Nitro enclave."""

import base64
import json
import os
import socket
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from protocol import MAX_FRAME_BYTES, ProtocolError, recv_frame, send_frame

ENCLAVE_CID = int(os.environ.get("SCB_ENCLAVE_CID", "16"))
VSOCK_PORT = int(os.environ.get("SCB_VSOCK_PORT", "5000"))
LISTEN_PORT = int(os.environ.get("SCB_PARENT_PORT", "8443"))
TIMEOUT = float(os.environ.get("SCB_PROXY_TIMEOUT_S", "310"))
MAX_HTTP_BODY = 6 * 1024 * 1024
ALLOWED_PATHS = {
    "/internal/healthz", "/internal/enclave-pubkey", "/internal/operator-pubkey",
    "/internal/seal_bounty", "/internal/upload", "/internal/verify",
}


class Handler(BaseHTTPRequestHandler):
    server_version = "scb-parent-proxy"

    def do_GET(self):
        self._forward()

    def do_POST(self):
        self._forward()

    def _forward(self):
        if self.path not in ALLOWED_PATHS:
            return self._json(404, {"error": "not found"})
        try:
            length = int(self.headers.get("content-length", "0"))
        except ValueError:
            return self._json(400, {"error": "invalid content-length"})
        if length < 0 or length > MAX_HTTP_BODY:
            return self._json(413, {"error": "request body too large"})
        body = self.rfile.read(length)
        request_id = str(uuid.uuid4())
        try:
            with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as channel:
                channel.settimeout(TIMEOUT)
                channel.connect((ENCLAVE_CID, VSOCK_PORT))
                send_frame(channel, {
                    "request_id": request_id,
                    "method": self.command,
                    "path": self.path,
                    "body_b64": base64.b64encode(body).decode(),
                })
                response = recv_frame(channel, MAX_FRAME_BYTES)
            if response.get("request_id") != request_id:
                raise ProtocolError("response request_id mismatch")
            status = int(response.get("status", 502))
            payload = base64.b64decode(response.get("body_b64", ""), validate=True)
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        except (OSError, ProtocolError, ValueError):
            self._json(502, {"error": "enclave unavailable", "request_id": request_id})

    def _json(self, status, value):
        payload = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):
        # No bodies, query strings, secrets, or response content.
        print(json.dumps({"scope": "parent-proxy", "message": fmt % args}))


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", LISTEN_PORT), Handler).serve_forever()


#!/usr/bin/env python3
"""Fetch the fixed KMS ciphertext and decrypt it through Nitro recipient auth.

Stdout is a single 32-byte secret for the Rust parent process. Diagnostics are
generic and never include subprocess output, credentials, or request data.
"""

import base64
import re
import socket
import subprocess
import sys

from protocol import recv_frame, send_frame

PARENT_CID = 3
PARENT_PORT = 5002
KMS_PROXY_PORT = 8000
REGION = "eu-north-1"
KMS_TOOL = "/app/kmstool_enclave_cli"
PLAINTEXT_RE = re.compile(rb"\APLAINTEXT: ([A-Za-z0-9+/]+={0,2})\s*\Z")


def load_key():
    with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as channel:
        channel.settimeout(10)
        channel.connect((PARENT_CID, PARENT_PORT))
        send_frame(channel, {"op": "get_master_ciphertext"}, 1024)
        response = recv_frame(channel, 16 * 1024)

    if (set(response) != {"ok", "ciphertext_b64", "region", "access_key_id",
                         "secret_access_key", "session_token"}
            or response.get("ok") is not True
            or response.get("region") != REGION):
        raise ValueError("invalid bootstrap response")
    ciphertext = response["ciphertext_b64"]
    access = response["access_key_id"]
    secret = response["secret_access_key"]
    token = response["session_token"]
    if not all(isinstance(item, str) and item for item in (ciphertext, access, secret, token)):
        raise ValueError("invalid bootstrap fields")
    if len(ciphertext) > 8192 or len(access) > 256 or len(secret) > 512 or len(token) > 4096:
        raise ValueError("bootstrap field exceeds limit")
    base64.b64decode(ciphertext, validate=True)

    result = subprocess.run(
        [KMS_TOOL, "decrypt", "--region", REGION,
         "--proxy-port", str(KMS_PROXY_PORT),
         "--aws-access-key-id", access,
         "--aws-secret-access-key", secret,
         "--aws-session-token", token,
         "--ciphertext", ciphertext],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        timeout=20, check=False, close_fds=True,
        env={"PATH": "/usr/bin:/bin", "LD_LIBRARY_PATH": "/app/lib"})
    access = secret = token = ""
    ciphertext = ""
    output = bytearray(result.stdout)
    result.stdout = b""
    try:
        if result.returncode != 0:
            raise ValueError("attested KMS decrypt failed")
        match = PLAINTEXT_RE.fullmatch(output)
        if match is None:
            raise ValueError("invalid KMS tool response")
        plaintext = bytearray(base64.b64decode(match.group(1), validate=True))
        try:
            if len(plaintext) != 32:
                raise ValueError("unexpected KMS key length")
            sys.stdout.buffer.write(plaintext)
            sys.stdout.buffer.flush()
        finally:
            plaintext[:] = b"\0" * len(plaintext)
    finally:
        output[:] = b"\0" * len(output)
        response.clear()


if __name__ == "__main__":
    try:
        load_key()
    except Exception:
        print("attested KMS bootstrap unavailable", file=sys.stderr)
        sys.exit(1)

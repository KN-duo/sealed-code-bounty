#!/usr/bin/env python3
"""Parent-side, fixed-purpose bootstrap for the enclave's KMS data key.

The parent can create and store only a KMS-encrypted data key. It returns that
ciphertext and short-lived instance-profile credentials to the enclave; KMS
releases the plaintext only through a recipient-attested decrypt request.
"""

import base64
import json
import os
import socket
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

from protocol import MAX_FRAME_BYTES, ProtocolError, recv_frame, send_frame

OBJECT_KEY = "scb/keys/master-data-key.v1"
ENCLAVE_CID = int(os.environ.get("SCB_ENCLAVE_CID", "16"))
PORT = int(os.environ.get("SCB_KEY_VSOCK_PORT", "5002"))
REGION = os.environ.get("AWS_REGION", "eu-north-1")
REQUEST = {"op": "get_master_ciphertext"}


class KeyBroker:
    def __init__(self, s3, kms, bucket, owner, key_arn, session):
        self.s3 = s3
        self.kms = kms
        self.bucket = bucket
        self.owner = owner
        self.key_arn = key_arn
        self.session = session
        self._lock = threading.Lock()

    def _ciphertext(self):
        args = {"Bucket": self.bucket, "Key": OBJECT_KEY,
                "ExpectedBucketOwner": self.owner}
        try:
            obj = self.s3.get_object(**args)
            try:
                body = obj["Body"].read(8193)
                if len(body) > 8192 or obj.get("ContentLength") != len(body):
                    raise ValueError("invalid encrypted key object")
                value = json.loads(body)
                encoded = value.get("ciphertext_b64") if isinstance(value, dict) else None
                decoded = base64.b64decode(encoded, validate=True)
                if value.get("version") != 1 or not 1 <= len(decoded) <= 6144:
                    raise ValueError("invalid encrypted key object")
                return encoded
            finally:
                obj["Body"].close()
        except Exception as exc:
            code = _error_code(exc)
            if code not in ("NoSuchKey", "404", "NotFound"):
                raise

        # KMS never returns a plaintext data key from this operation.
        generated = self.kms.generate_data_key_without_plaintext(
            KeyId=self.key_arn, KeySpec="AES_256")
        ciphertext = generated.get("CiphertextBlob")
        if not isinstance(ciphertext, bytes) or not ciphertext:
            raise ValueError("KMS returned no encrypted data key")
        encoded = base64.b64encode(ciphertext).decode("ascii")
        body = json.dumps({"version": 1, "ciphertext_b64": encoded},
                          separators=(",", ":")).encode("ascii")
        try:
            self.s3.put_object(
                **args, Body=body, ContentLength=len(body),
                ContentType="application/json", IfNoneMatch="*",
                ServerSideEncryption="AES256")
            return encoded
        except Exception as exc:
            if _error_code(exc) not in ("PreconditionFailed", "412", "ConditionalRequestConflict", "409"):
                raise
            # Concurrent first boots: use the winner's persisted key.
            obj = self.s3.get_object(**args)
            try:
                body = obj["Body"].read(8193)
                value = json.loads(body)
                encoded = value.get("ciphertext_b64") if isinstance(value, dict) else None
                decoded = base64.b64decode(encoded, validate=True)
                if (len(body) > 8192 or obj.get("ContentLength") != len(body)
                        or value.get("version") != 1 or not 1 <= len(decoded) <= 6144):
                    raise ValueError("invalid encrypted key object")
                return encoded
            finally:
                obj["Body"].close()

    def response(self):
        # Serialize initial creation to avoid avoidable KMS requests; S3's
        # conditional write remains the cross-process correctness boundary.
        with self._lock:
            ciphertext = self._ciphertext()
        credentials = self.session.get_credentials()
        if credentials is None:
            raise ValueError("instance profile credentials unavailable")
        frozen = credentials.get_frozen_credentials()
        return {
            "ok": True,
            "ciphertext_b64": ciphertext,
            "region": REGION,
            "access_key_id": frozen.access_key,
            "secret_access_key": frozen.secret_key,
            "session_token": frozen.token or "",
        }


def _error_code(exc):
    response = getattr(exc, "response", {})
    error = response.get("Error", {}) if isinstance(response, dict) else {}
    return error.get("Code", "") if isinstance(error, dict) else ""


def main():
    try:
        import boto3
        from botocore.config import Config

        bucket, owner = os.environ["SCB_STORAGE_BUCKET"], os.environ["SCB_STORAGE_BUCKET_OWNER"]
        key_arn = os.environ["SCB_MASTER_KMS_KEY_ARN"]
        timeout = Config(connect_timeout=2, read_timeout=4,
                         retries={"mode": "standard", "total_max_attempts": 2})
        session = boto3.Session(region_name=REGION)
        broker = KeyBroker(
            session.client("s3", config=timeout),
            session.client("kms", config=timeout), bucket, owner, key_arn, session)
        with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as server:
            server.bind((socket.VMADDR_CID_ANY, PORT))
            server.listen(4)
            while True:
                channel, peer = server.accept()
                if peer[0] != ENCLAVE_CID:
                    channel.close()
                    continue
                with channel:
                    channel.settimeout(5)
                    try:
                        request = recv_frame(channel, 1024)
                        if request != REQUEST:
                            raise ProtocolError("invalid key bootstrap request")
                        reply = broker.response()
                    except Exception:
                        # Never serialize SDK errors, credentials or ciphertext.
                        reply = {"ok": False, "error": "bootstrap_unavailable"}
                    send_frame(channel, reply, MAX_FRAME_BYTES)
    except KeyboardInterrupt:
        return 0
    except Exception:
        print(json.dumps({"scope": "key-broker", "error": "unavailable"}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

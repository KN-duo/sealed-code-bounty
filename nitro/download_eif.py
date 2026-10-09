#!/usr/bin/env python3
"""Download the pinned verifier EIF and verify its reviewed SHA-384 digest."""

import hashlib
import os
from pathlib import Path
import tempfile

import boto3
from botocore.config import Config

BUCKET = "${storage_bucket}"
OBJECT_KEY = "${enclave_eif_s3_key}"
EXPECTED_SHA384 = "${enclave_eif_sha384}"
REGION = "${aws_region}"
BUCKET_OWNER = "${storage_bucket_owner}"
DESTINATION = Path("/var/lib/scb/verifier.eif")
MAX_EIF_BYTES = 1024 * 1024 * 1024


def main() -> None:
    if (len(EXPECTED_SHA384) != 96
            or any(c not in "0123456789abcdef" for c in EXPECTED_SHA384)
            or EXPECTED_SHA384 in ("0" * 96, "f" * 96)):
        raise RuntimeError("invalid configured EIF digest")
    DESTINATION.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix="verifier.eif.", dir=DESTINATION.parent)
    digest = hashlib.sha384()
    try:
        with os.fdopen(fd, "wb") as output:
            response = boto3.client("s3", region_name=REGION, config=Config(
                connect_timeout=5, read_timeout=30,
                retries={"mode": "standard", "total_max_attempts": 2})).get_object(
                Bucket=BUCKET, Key=OBJECT_KEY, ExpectedBucketOwner=BUCKET_OWNER
            )
            stream = response["Body"]
            try:
                expected_length = response.get("ContentLength", 0)
                if type(expected_length) is not int or not 0 < expected_length <= MAX_EIF_BYTES:
                    raise RuntimeError("EIF object has an invalid size")
                received = 0
                while True:
                    chunk = stream.read(1024 * 1024)
                    if not chunk:
                        break
                    received += len(chunk)
                    if received > expected_length:
                        raise RuntimeError("EIF stream exceeds its declared size")
                    digest.update(chunk)
                    output.write(chunk)
                if received != expected_length:
                    raise RuntimeError("EIF stream was truncated")
            finally:
                stream.close()
            output.flush()
            os.fsync(output.fileno())
        if digest.hexdigest() != EXPECTED_SHA384:
            raise RuntimeError("downloaded EIF digest does not match reviewed configuration")
        os.chmod(temporary, 0o400)
        os.replace(temporary, DESTINATION)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    main()

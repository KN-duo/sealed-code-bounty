#!/usr/bin/env python3
"""Validate and optionally publish committed CTF artifacts; default is dry-run.

Requires Node for the shared manifest validator and AWS CLI only for --publish.
This operator tool uploads objects only; it does not post a Solana bounty.
Existing keys are never overwritten, and any upload error stops the operation.
"""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

MAX_MANIFEST_BYTES = 64 * 1024
MAX_ENVIRONMENT_BYTES = 128 * 1024 * 1024
MANIFEST_MODULE = Path(__file__).resolve().parents[1] / "shared" / "manifest.mjs"
VALIDATE_SCRIPT = """
import {readFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
try {
  const {manifestCanonicalJson} = await import(pathToFileURL(process.argv[1]).href);
  process.stdout.write(manifestCanonicalJson(JSON.parse(readFileSync(0, 'utf8'))));
} catch { process.exitCode = 1; }
"""


class PublishError(Exception):
    pass


def open_regular(path):
    # O_NONBLOCK prevents an accidental FIFO input from hanging before fstat.
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise PublishError("input_not_regular_file")
        return os.fdopen(descriptor, "rb")
    except BaseException:
        os.close(descriptor)
        raise


def manifest_bytes(path, process_runner):
    with open_regular(path) as source:
        body = source.read(MAX_MANIFEST_BYTES + 1)
    if len(body) > MAX_MANIFEST_BYTES:
        raise PublishError("manifest_too_large")
    try:
        result = process_runner(
            ["node", "--input-type=module", "--eval", VALIDATE_SCRIPT, str(MANIFEST_MODULE)],
            input=body, capture_output=True, check=False, timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        raise PublishError("manifest_validator_unavailable") from None
    if result.returncode != 0 or not body or result.stdout != body:
        raise PublishError("manifest_invalid_or_not_canonical")
    return body, json.loads(body)


def snapshot_environment(source_path, destination):
    digest, total = hashlib.sha256(), 0
    with open_regular(source_path) as source, destination.open("xb") as snapshot:
        while True:
            chunk = source.read(min(1024 * 1024, MAX_ENVIRONMENT_BYTES + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_ENVIRONMENT_BYTES:
                raise PublishError("environment_too_large")
            digest.update(chunk)
            snapshot.write(chunk)
    if total == 0:
        raise PublishError("environment_empty")
    return digest.hexdigest(), total


def upload(args, key, path, digest, content_type, process_runner):
    command = [
        "aws", "--region", args.region, "--no-cli-pager", "s3api", "put-object",
        "--bucket", args.bucket, "--expected-bucket-owner", args.owner,
        "--key", key, "--body", str(path), "--if-none-match", "*",
        "--server-side-encryption", "AES256", "--content-type", content_type,
        "--checksum-sha256", base64.b64encode(bytes.fromhex(digest)).decode("ascii"),
    ]
    try:
        result = process_runner(command, capture_output=True, check=False, timeout=60,
                                env={**os.environ, "AWS_MAX_ATTEMPTS": "1"})
    except (OSError, subprocess.SubprocessError):
        raise PublishError("aws_upload_failed") from None
    if result.returncode != 0:
        # SDK/CLI error bodies may include request or credential details.
        # A pre-existing object also fails closed; no overwrite or blind success.
        raise PublishError("aws_upload_failed")


def publish(args, process_runner=subprocess.run):
    if (not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", args.bucket)
            or not re.fullmatch(r"[0-9]{12}", args.owner)
            or not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-[0-9]+", args.region)):
        raise PublishError("invalid_storage_configuration")
    body, manifest = manifest_bytes(args.manifest, process_runner)
    manifest_hash = hashlib.sha256(body).hexdigest()
    with tempfile.TemporaryDirectory(prefix="scb-publish-") as directory:
        root = Path(directory)
        environment_path = root / "environment.tar.gz"
        environment_hash, environment_size = snapshot_environment(args.environment, environment_path)
        if environment_hash != manifest["image_tarball"]["sha256"]:
            raise PublishError("environment_hash_mismatch")
        manifest_path = root / "manifest.json"
        manifest_path.write_bytes(body)
        environment_key = f"scb/envs/{environment_hash}.tar.gz"
        manifest_key = f"scb/manifests/{manifest_hash}.json"
        if args.publish:
            upload(args, environment_key, environment_path, environment_hash, "application/gzip", process_runner)
            upload(args, manifest_key, manifest_path, manifest_hash, "application/json", process_runner)
        return {
            "mode": "published" if args.publish else "dry-run",
            "manifest_sha256": manifest_hash,
            "env_blob_sha256": environment_hash,
            "manifest_object": f"s3://{args.bucket}/{manifest_key}",
            "environment_object": f"s3://{args.bucket}/{environment_key}",
            "manifest_bytes": len(body), "environment_bytes": environment_size,
            "region": args.region,
        }


def main(argv=None, process_runner=subprocess.run):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--environment", type=Path, required=True)
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--region", default="eu-north-1")
    parser.add_argument("--publish", action="store_true", help="perform conditional S3 writes (default: validate only)")
    args = parser.parse_args(argv)
    try:
        result = publish(args, process_runner)
    except PublishError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}), file=sys.stderr)
        return 1
    except Exception:
        print(json.dumps({"ok": False, "error": "artifact_preparation_failed"}), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())

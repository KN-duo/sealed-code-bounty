"""Publisher tests use the real shared Node validator and a fake AWS CLI."""

import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("publish-challenge-artifacts.py")
SPEC = importlib.util.spec_from_file_location("publish_artifacts", SCRIPT)
publisher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publisher)


class PublisherTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="scb-publish-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.environment = self.root / "environment.tar.gz"
        self.environment.write_bytes(b"synthetic compressed target bytes")
        self.manifest = {
            "format_version": 2, "name": "synthetic-ctf",
            "image_tarball": {"url": "https://metadata.invalid/ignored", "sha256": hashlib.sha256(self.environment.read_bytes()).hexdigest()},
            "target": {"kind": "tcp_service", "host": "target", "port": 31337},
            "limits": {"timeout_seconds": 5, "memory_mb": 128, "cpus": 1},
            "determinism": {"aslr": "on", "seed": 1},
            "flag_placeholder": "{{FLAG}}", "entrypoint": ["/app/target"],
        }
        self.manifest_path = self.root / "manifest.json"
        self.write_manifest()
        self.args = argparse.Namespace(manifest=self.manifest_path, environment=self.environment,
                                       bucket="scb-test-bucket", owner="123456789012",
                                       region="eu-north-1", publish=False)
        self.calls, self.aws = [], []
        self.fail_aws_at = None

    def write_manifest(self):
        self.manifest_path.write_text(json.dumps(self.manifest, sort_keys=True, separators=(",", ":")))

    def run_process(self, command, **kwargs):
        self.calls.append(command)
        if command[0] == "node":
            return subprocess.run(command, **kwargs)
        self.assertEqual(command[0], "aws")
        self.assertEqual(kwargs["env"]["AWS_MAX_ATTEMPTS"], "1")
        body_path = Path(command[command.index("--body") + 1])
        self.aws.append((command, body_path.read_bytes(), body_path))
        return subprocess.CompletedProcess(command, int(len(self.aws) == self.fail_aws_at),
                                           stdout=b"DO_NOT_PRINT_RESPONSE", stderr=b"DO_NOT_PRINT_CREDENTIALS")

    def test_default_dry_run_validates_without_aws_and_reports_exact_hashes(self):
        result = publisher.publish(self.args, self.run_process)
        self.assertEqual(result["mode"], "dry-run")
        self.assertEqual(result["manifest_sha256"], hashlib.sha256(self.manifest_path.read_bytes()).hexdigest())
        self.assertEqual(result["env_blob_sha256"], hashlib.sha256(self.environment.read_bytes()).hexdigest())
        self.assertEqual(result["environment_object"], f's3://scb-test-bucket/scb/envs/{result["env_blob_sha256"]}.tar.gz')
        self.assertEqual(result["manifest_object"], f's3://scb-test-bucket/scb/manifests/{result["manifest_sha256"]}.json')
        self.assertEqual(self.aws, [])
        self.assertEqual(len(self.calls), 1)

    def test_publish_orders_environment_before_manifest_with_immutable_parameters(self):
        self.args.publish = True
        result = publisher.publish(self.args, self.run_process)
        self.assertEqual(result["mode"], "published")
        self.assertEqual(len(self.aws), 2)
        for index, (command, body, body_path) in enumerate(self.aws):
            self.assertEqual(command[:6], ["aws", "--region", "eu-north-1", "--no-cli-pager", "s3api", "put-object"])
            self.assertEqual(command[command.index("--bucket") + 1], "scb-test-bucket")
            self.assertEqual(command[command.index("--expected-bucket-owner") + 1], "123456789012")
            self.assertEqual(command[command.index("--if-none-match") + 1], "*")
            self.assertEqual(command[command.index("--server-side-encryption") + 1], "AES256")
            expected_body = self.environment.read_bytes() if index == 0 else self.manifest_path.read_bytes()
            self.assertEqual(body, expected_body)
            self.assertFalse(body_path.exists(), "staged files must be removed after upload")
            key = command[command.index("--key") + 1]
            expected_prefix = "scb/envs/" if index == 0 else "scb/manifests/"
            self.assertTrue(key.startswith(expected_prefix))

    def test_environment_mismatch_does_not_call_aws(self):
        self.args.publish = True
        self.environment.write_bytes(b"substitution")
        with self.assertRaisesRegex(publisher.PublishError, "environment_hash_mismatch"):
            publisher.publish(self.args, self.run_process)
        self.assertEqual(self.aws, [])

    def test_noncanonical_duplicate_and_invalid_manifests_are_rejected(self):
        canonical = self.manifest_path.read_bytes()
        invalid = [canonical + b"\n", json.dumps(self.manifest, indent=2).encode(), b"{",
                   b'{"format_version":2,' + canonical[1:], b"\xff"]
        self.manifest["entrypoint"] = "/app/target"
        invalid.append(json.dumps(self.manifest, sort_keys=True, separators=(",", ":")).encode())
        self.manifest["entrypoint"] = ["/app/target"]
        self.manifest["unknown"] = True
        invalid.append(json.dumps(self.manifest, sort_keys=True, separators=(",", ":")).encode())
        for data in invalid:
            with self.subTest(data=data[:20]):
                self.manifest_path.write_bytes(data)
                with self.assertRaisesRegex(publisher.PublishError, "manifest_invalid_or_not_canonical"):
                    publisher.publish(self.args, self.run_process)
        self.assertEqual(self.aws, [])

    def test_manifest_cap_is_checked_before_node(self):
        self.manifest_path.write_bytes(b" " * (publisher.MAX_MANIFEST_BYTES + 1))
        with self.assertRaisesRegex(publisher.PublishError, "manifest_too_large"):
            publisher.publish(self.args, self.run_process)
        self.assertEqual(self.calls, [])

    def test_environment_empty_and_oversized_rejected_before_aws(self):
        with patch.object(publisher, "MAX_ENVIRONMENT_BYTES", 4):
            for body, error in [(b"", "environment_empty"), (b"12345", "environment_too_large")]:
                self.environment.write_bytes(body)
                with self.assertRaisesRegex(publisher.PublishError, error):
                    publisher.publish(self.args, self.run_process)
        self.assertEqual(self.aws, [])

    def test_environment_exact_cap_is_accepted(self):
        with patch.object(publisher, "MAX_ENVIRONMENT_BYTES", len(self.environment.read_bytes())):
            self.assertEqual(publisher.publish(self.args, self.run_process)["mode"], "dry-run")

    def test_upload_failure_stops_without_retry_or_manifest_publish(self):
        self.args.publish = True
        self.fail_aws_at = 1
        with self.assertRaisesRegex(publisher.PublishError, "aws_upload_failed"):
            publisher.publish(self.args, self.run_process)
        self.assertEqual(len(self.aws), 1)
        self.assertFalse(self.aws[0][2].exists())

    def test_manifest_upload_failure_does_not_report_published(self):
        self.args.publish = True
        self.fail_aws_at = 2
        with self.assertRaisesRegex(publisher.PublishError, "aws_upload_failed"):
            publisher.publish(self.args, self.run_process)
        self.assertEqual(len(self.aws), 2)
        self.assertTrue(all(not path.exists() for _, _, path in self.aws))

    def test_snapshots_prevent_source_mutation_during_upload(self):
        self.args.publish = True
        original_manifest = self.manifest_path.read_bytes()
        original_environment = self.environment.read_bytes()
        def mutate(command, **kwargs):
            if command[0] == "aws":
                self.environment.write_bytes(b"changed")
                self.manifest_path.write_bytes(b"changed")
            return self.run_process(command, **kwargs)
        publisher.publish(self.args, mutate)
        self.assertEqual(self.aws[0][1], original_environment)
        self.assertEqual(self.aws[1][1], original_manifest)

    def test_bad_storage_configuration_fails_before_subprocess(self):
        for field, value in [("bucket", "../bucket"), ("owner", "123"), ("region", "--endpoint-url")]:
            args = argparse.Namespace(**vars(self.args))
            setattr(args, field, value)
            with self.assertRaisesRegex(publisher.PublishError, "invalid_storage_configuration"):
                publisher.publish(args, self.run_process)
        self.assertEqual(self.calls, [])

    def test_fifo_input_is_rejected_without_hanging(self):
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        self.args.environment = fifo
        with self.assertRaisesRegex(publisher.PublishError, "input_not_regular_file"):
            publisher.publish(self.args, self.run_process)

    def test_main_errors_never_echo_cli_bodies(self):
        self.fail_aws_at = 1
        out, err = io.StringIO(), io.StringIO()
        argv = ["--manifest", str(self.manifest_path), "--environment", str(self.environment),
                "--bucket", self.args.bucket, "--owner", self.args.owner, "--publish"]
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = publisher.main(argv, self.run_process)
        self.assertEqual(status, 1)
        self.assertEqual(out.getvalue(), "")
        self.assertEqual(json.loads(err.getvalue()), {"ok": False, "error": "aws_upload_failed"})

    def test_node_failure_is_sanitized(self):
        def fail(*_, **__):
            raise FileNotFoundError("DO_NOT_LOG")
        with self.assertRaisesRegex(publisher.PublishError, "manifest_validator_unavailable"):
            publisher.publish(self.args, fail)


if __name__ == "__main__":
    unittest.main()

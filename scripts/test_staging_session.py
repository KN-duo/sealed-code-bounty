"""Exercise staging lifecycle scripts against injected CLIs; never contact AWS."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
FAKE_CLI = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

tool = Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ["SCB_TEST_EVENTS"], "a") as events:
    events.write(json.dumps([tool, *args]) + "\n")
config = json.loads(Path(os.environ["SCB_TEST_CONFIG"]).read_text())
if tool == "terraform":
    if "output" in args:
        print(config["outputs"][args[-1]])
    elif "destroy" not in args:
        sys.exit(98)
elif tool == "aws":
    operation = " ".join(args[:3]) if args[:2] == ["ec2", "wait"] else " ".join(args[:2])
    if operation == config.get("fail"):
        sys.exit(17)
    if operation == "ec2 describe-instances":
        print(config.get("instances", ""))
    elif operation == "ec2 run-instances":
        print("i-0123456789abcdef0")
    elif operation not in ["ec2 terminate-instances", "ec2 wait instance-terminated", "s3api put-object"]:
        sys.exit(99)
'''


class SessionScriptsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="scb-session-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "scripts").mkdir()
        (self.root / "infra/aws-nitro").mkdir(parents=True)
        (self.root / "infra/aws-nitro/terraform.tfstate").write_text("{}")
        for name in ["start-staging-session.sh", "stop-staging.sh", "destroy-staging.sh"]:
            shutil.copyfile(REPO_ROOT / "scripts" / name, self.root / "scripts" / name)
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        for tool in ["terraform", "aws"]:
            executable = bin_dir / tool
            executable.write_text(FAKE_CLI)
            executable.chmod(0o700)
        self.events_path = self.root / "events.jsonl"
        self.config_path = self.root / "config.json"
        self.env = {
            **os.environ,
            "PATH": str(bin_dir) + os.pathsep + os.environ["PATH"],
            "SCB_TEST_EVENTS": str(self.events_path),
            "SCB_TEST_CONFIG": str(self.config_path),
        }
        self.config = {
            "outputs": {
                "region": "eu-north-1",
                "parent_launch_template_id": "lt-01234",
                "parent_launch_template_version": "7",
                "parent_max_runtime_hours": "2",
                "parent_instance_type": "m6i.xlarge",
                "parent_instance_name": "scb-staging-nitro-parent",
                "content_bucket": "scb-test-content",
            }
        }

    def run_script(self, script, *args):
        self.config_path.write_text(json.dumps(self.config))
        return subprocess.run(
            ["bash", str(self.root / "scripts" / script), *args],
            env=self.env,
            capture_output=True,
            text=True,
            timeout=10,
        )

    def events(self):
        if not self.events_path.exists():
            return []
        return [json.loads(line) for line in self.events_path.read_text().splitlines()]

    def aws_events(self):
        return [event for event in self.events() if event[0] == "aws"]

    def test_dry_run_uses_recorded_version_and_runtime_without_mutation(self):
        result = self.run_script("start-staging-session.sh")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("version 7", result.stdout)
        self.assertIn("2 hour(s)", result.stdout)
        self.assertEqual([event[1:3] for event in self.aws_events()], [["ec2", "describe-instances"]])

    def test_launch_reserves_month_before_pinned_version(self):
        result = self.run_script("start-staging-session.sh", "--start")
        self.assertEqual(result.returncode, 0, result.stderr)
        events = self.aws_events()
        self.assertEqual([event[1:3] for event in events], [
            ["ec2", "describe-instances"], ["s3api", "put-object"], ["ec2", "run-instances"],
        ])
        self.assertIn("LaunchTemplateId=lt-01234,Version=7", events[2])
        reservation = events[1]
        self.assertEqual(reservation[reservation.index("--if-none-match") + 1], "*")
        self.assertRegex(reservation[reservation.index("--key") + 1], r"^scb/runtime-allowance/\d{4}-\d{2}\.json$")

    def test_existing_or_terminating_parent_blocks_new_session(self):
        self.config["instances"] = "i-0123456789abcdef0"
        result = self.run_script("start-staging-session.sh", "--start")
        self.assertNotEqual(result.returncode, 0)
        events = self.aws_events()
        self.assertEqual(len(events), 1)
        self.assertTrue(any("shutting-down" in value for value in events[0]))

    def test_reservation_failure_prevents_launch(self):
        self.config["fail"] = "s3api put-object"
        result = self.run_script("start-staging-session.sh", "--start")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(event[1:3] == ["ec2", "run-instances"] for event in self.aws_events()))

    def test_instance_lookup_failure_prevents_reservation(self):
        self.config["fail"] = "ec2 describe-instances"
        result = self.run_script("start-staging-session.sh", "--start")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([event[1:3] for event in self.aws_events()], [["ec2", "describe-instances"]])

    def test_launch_failure_preserves_monthly_reservation(self):
        self.config["fail"] = "ec2 run-instances"
        result = self.run_script("start-staging-session.sh", "--start")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([event[1:3] for event in self.aws_events()], [
            ["ec2", "describe-instances"], ["s3api", "put-object"], ["ec2", "run-instances"],
        ])

    def test_invalid_template_version_or_runtime_blocks_aws(self):
        for key, value in [("parent_launch_template_version", "$Latest"), ("parent_max_runtime_hours", "24")]:
            with self.subTest(key=key):
                previous = self.config["outputs"][key]
                self.config["outputs"][key] = value
                result = self.run_script("start-staging-session.sh", "--start")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.aws_events(), [])
                self.config["outputs"][key] = previous

    def test_destroy_waits_for_every_instance_before_terraform(self):
        self.config["instances"] = "i-0123456789abcdef0\ni-abcdef01234567890"
        result = self.run_script("destroy-staging.sh", "--confirm")
        self.assertEqual(result.returncode, 0, result.stderr)
        events = self.events()
        terminate = next(event for event in events if event[1:3] == ["ec2", "terminate-instances"])
        wait = next(event for event in events if event[1:4] == ["ec2", "wait", "instance-terminated"])
        destroy = next(event for event in events if event[0] == "terraform" and "destroy" in event)
        for event in [terminate, wait]:
            self.assertIn("i-0123456789abcdef0", event)
            self.assertIn("i-abcdef01234567890", event)
        self.assertLess(events.index(terminate), events.index(wait))
        self.assertLess(events.index(wait), events.index(destroy))

    def test_destroy_aborts_when_termination_or_wait_fails(self):
        self.config["instances"] = "i-0123456789abcdef0"
        for operation in ["ec2 terminate-instances", "ec2 wait instance-terminated"]:
            with self.subTest(operation=operation):
                self.config["fail"] = operation
                result = self.run_script("destroy-staging.sh", "--confirm")
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(any(event[0] == "terraform" and "destroy" in event for event in self.events()))

    def test_destroy_with_no_parent_does_not_terminate(self):
        self.config["instances"] = "None"
        result = self.run_script("destroy-staging.sh", "--confirm")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([event[1:3] for event in self.aws_events()], [["ec2", "describe-instances"]])
        self.assertIn("destroy", self.events()[-1])

    def test_invalid_instance_output_prevents_termination_and_destroy(self):
        self.config["instances"] = "i-0123456789abcdef0\n--all"
        result = self.run_script("destroy-staging.sh", "--confirm")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([event[1:3] for event in self.aws_events()], [["ec2", "describe-instances"]])
        self.assertFalse(any(event[0] == "terraform" and "destroy" in event for event in self.events()))

    def test_missing_confirmation_or_state_blocks_all_calls(self):
        result = self.run_script("destroy-staging.sh")
        self.assertNotEqual(result.returncode, 0)
        (self.root / "infra/aws-nitro/terraform.tfstate").unlink()
        result = self.run_script("start-staging-session.sh", "--start")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.events(), [])


if __name__ == "__main__":
    unittest.main()

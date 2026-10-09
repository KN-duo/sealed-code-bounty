#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 - "$repo_root" "$@" <<'PY'
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import uuid

BUILDER = "public.ecr.aws/docker/library/rust:1.89.0-slim-bookworm@sha256:d7fc7de78bb8c1469933aeecbf801314d30d7d6e9f0578bba4cfa285bfa37fe6"
repo = Path(sys.argv[1]).resolve()
parser = argparse.ArgumentParser(description="Build the runner with pinned Rust and offline compilation.")
mode = parser.add_mutually_exclusive_group(required=True)
mode.add_argument("--dev-only", action="store_true", help="explicitly allow uncommitted source")
mode.add_argument("--release", action="store_true", help="require a clean source checkout; does not approve deployment")
parser.add_argument("--output", default=os.environ.get("SCB_RUNNER_OUTPUT", "/tmp/scb-runner-pinned-artifacts"))
args = parser.parse_args(sys.argv[2:])
output = Path(args.output).resolve()
if output == repo or repo in output.parents:
    parser.error("artifact output must be outside the source checkout")


def run(argv, **kwargs):
    return subprocess.run(argv, check=True, **kwargs)


def git(*args):
    return subprocess.check_output(["git", "-C", str(repo), *args]).decode().strip()


def dirty():
    return bool(git("status", "--porcelain", "--untracked-files=all"))


def input_paths():
    paths = [repo / "runner/Cargo.toml", repo / "runner/Cargo.lock",
             repo / "nitro/RunnerBuilder.Dockerfile", repo / "nitro/build-runner.sh"]
    # Include all source data, not just .rs files, so include_bytes!/include_str!
    # additions cannot silently escape the source manifest.
    paths += sorted((repo / "runner/src").rglob("*"))
    if (repo / "runner/build.rs").exists():
        paths.append(repo / "runner/build.rs")
    result = []
    for path in paths:
        if path.is_symlink():
            raise RuntimeError(f"symlink build input is forbidden: {path}")
        if path.is_file():
            result.append(path)
    return sorted(result)


def hash_file(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def manifest():
    return {str(path.relative_to(repo)): hash_file(path) for path in input_paths()}


def tree_hash(path):
    result = hashlib.sha256()
    count = 0
    for entry in sorted(path.rglob("*")):
        if entry.is_symlink():
            raise RuntimeError("vendored symlinks are forbidden")
        if entry.is_file():
            result.update(str(entry.relative_to(path)).encode() + b"\0")
            result.update(bytes.fromhex(hash_file(entry)))
            count += 1
    return result.hexdigest(), count


source_commit = git("rev-parse", "HEAD")
source_dirty = dirty()
if args.release and source_dirty:
    parser.error("--release requires a clean tracked and untracked worktree; use --dev-only for local development")
build_commit = source_commit + ("-dirty" if source_dirty else "")
source_date_epoch = int(git("show", "-s", "--format=%ct", "HEAD"))
inputs = manifest()
image = "scb-runner-build:" + uuid.uuid4().hex
container = None
output.parent.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(prefix="scb-runner-context-") as temporary:
    context = Path(temporary)
    try:
        for relative, expected_hash in inputs.items():
            target = context / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(repo / relative, target)
            os.chmod(target, 0o644)
            os.utime(target, (source_date_epoch, source_date_epoch))
            if hash_file(target) != expected_hash:
                raise RuntimeError(f"source changed during snapshot: {relative}")
        if manifest() != inputs or git("rev-parse", "HEAD") != source_commit:
            raise RuntimeError("runner build inputs or source commit changed during snapshot")
        if args.release and dirty():
            raise RuntimeError("release checkout became dirty during snapshot")
        # Acquisition runs in the same pinned toolchain as compilation. Cargo
        # verifies registry packages against Cargo.lock while vendoring them.
        # Only this stage may use networking; compilation below cannot.
        with (context / "cargo-config.toml").open("wb") as configuration:
            run(["docker", "run", "--rm", "--pull=never", "--platform", "linux/amd64",
                 "--user", f"{os.getuid()}:{os.getgid()}", "--env", "CARGO_HOME=/tmp/cargo",
                 "--mount", f"type=bind,source={context},target=/src",
                 "--workdir", "/src/runner", BUILDER,
                 "cargo", "vendor", "--locked", "/src/vendor"], stdout=configuration)
        if hash_file(context / "runner/Cargo.lock") != inputs["runner/Cargo.lock"]:
            raise RuntimeError("vendoring modified Cargo.lock")
        vendor_sha256, vendor_file_count = tree_hash(context / "vendor")
        vendor_config_sha256 = hash_file(context / "cargo-config.toml")
        # Normalize metadata of copied sources and vendored inputs. RUSTFLAGS
        # additionally remap compiler paths; SOURCE_DATE_EPOCH binds the epoch.
        for path in sorted(context.rglob("*"), reverse=True):
            if not path.is_symlink():
                os.utime(path, (source_date_epoch, source_date_epoch))
        run(["docker", "build", "--network=none", "--pull=false", "--platform", "linux/amd64",
             "--file", str(context / "nitro/RunnerBuilder.Dockerfile"), "--tag", image,
             "--build-arg", f"SCB_BUILD_COMMIT={build_commit}",
             "--build-arg", f"SOURCE_DATE_EPOCH={source_date_epoch}", str(context)])
        container = subprocess.check_output(["docker", "create", image, "/scb-runner"]).decode().strip()
        with tempfile.TemporaryDirectory(prefix=".scb-runner-output-", dir=output.parent) as staging:
            staging = Path(staging)
            for name in ("scb-runner", "compiler.txt", "cargo.txt"):
                run(["docker", "cp", f"{container}:/{name}", str(staging / name)])
            if manifest() != inputs or git("rev-parse", "HEAD") != source_commit:
                raise RuntimeError("runner build inputs or source commit changed while compiling")
            if args.release and dirty():
                raise RuntimeError("release checkout became dirty while compiling")
            provenance = {
                "schema": "scb-runner-build-v1",
                "artifact_sha256": {"scb-runner": hash_file(staging / "scb-runner")},
                "input_sha256": inputs,
                "source_commit": source_commit, "source_dirty": source_dirty,
                "build_commit": build_commit, "source_date_epoch": source_date_epoch,
                "builder_image": BUILDER, "platform": "linux/amd64",
                "build_network": "none", "cargo_locked": True, "cargo_offline": True,
                "cargo_default_features": False, "cargo_features": [],
                "target": "x86_64-unknown-linux-gnu", "profile": "release",
                "vendor_tree_sha256": vendor_sha256, "vendor_file_count": vendor_file_count,
                "vendor_config_sha256": vendor_config_sha256,
                "compiler": (staging / "compiler.txt").read_text().strip(),
                "cargo": (staging / "cargo.txt").read_text().strip(),
                "build_mode": "dev-only" if args.dev_only else "release-candidate",
                "release_approved": False,
            }
            (staging / "provenance.json").write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n")
            os.chmod(staging / "scb-runner", 0o555)
            for name in ("compiler.txt", "cargo.txt", "provenance.json"):
                os.chmod(staging / name, 0o444)
            output.mkdir(exist_ok=True)
            # Publish provenance last. Consumers must verify its binary hash;
            # a partially interrupted publication cannot validate as a pair.
            for name in ("scb-runner", "compiler.txt", "cargo.txt", "provenance.json"):
                os.replace(staging / name, output / name)
            print(json.dumps({"output": str(output), "build_commit": build_commit,
                              "artifact_sha256": provenance["artifact_sha256"],
                              "release_approved": False}, indent=2))
    finally:
        if container:
            subprocess.run(["docker", "rm", container], stdout=subprocess.DEVNULL, check=False)
        subprocess.run(["docker", "image", "rm", image], stdout=subprocess.DEVNULL, check=False)
PY

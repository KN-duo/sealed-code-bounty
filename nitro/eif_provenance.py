#!/usr/bin/env python3
"""Validate component inputs and record an EIF candidate's local provenance.

Metadata is evidence for operator review, not a signature or release approval.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess


def digest(path, algorithm="sha256"):
    result = hashlib.new(algorithm)
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args])


def snapshot(repo):
    paths = sorted(set(git(repo, "ls-files", "-c", "-o", "--exclude-standard", "-z").split(b"\0")) - {b""})
    source = hashlib.sha256()
    for relative in paths:
        path = repo / relative.decode("utf-8")
        if not path.exists() and not path.is_symlink():
            entry = [relative.decode("utf-8"), "deleted"]
        else:
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode):
                entry = [relative.decode("utf-8"), "symlink", str(path.readlink())]
            elif stat.S_ISREG(mode):
                entry = [relative.decode("utf-8"), stat.S_IMODE(mode), digest(path)]
            else:
                raise RuntimeError("source contains an unsupported file type")
        source.update(json.dumps(entry, ensure_ascii=True, separators=(",", ":")).encode() + b"\n")
    commit = git(repo, "rev-parse", "HEAD").decode().strip()
    dirty = bool(git(repo, "status", "--porcelain", "--untracked-files=all"))
    return {"git_commit": commit, "dirty": dirty, "source_sha256": source.hexdigest(),
            "build_commit": commit + ("-dirty" if dirty else ""), "file_count": len(paths)}


def validate_components(args):
    repo = args.repo.resolve()
    source = json.loads(args.snapshot.read_text())
    runtime = json.loads(Path(str(args.runtime) + ".provenance.json").read_text())
    kms = json.loads((args.kms / "provenance.json").read_text())
    runner = json.loads((args.runner / "provenance.json").read_text())
    expected_schemas = ((runtime, "scb-runtime-provenance-v1"),
                        (kms, "scb-kms-build-v1"), (runner, "scb-runner-build-v1"))
    for component, schema in expected_schemas:
        if component.get("schema") != schema:
            raise RuntimeError("unsupported component provenance: " + schema)
        if component.get("source_commit") != source["git_commit"]:
            raise RuntimeError("component source commit differs from EIF source")
        if args.release and component.get("source_dirty") is not False:
            raise RuntimeError("release requires clean component provenance")

    runtime_inputs = dict(runtime["inputs_sha256"])
    runtime_inputs["runner/runtime.Dockerfile"] = runtime_inputs.pop("runtime.Dockerfile")
    expected_runtime = {"runner/runtime.Dockerfile", "runner/build-runtime.sh",
                        "runner/runtime/apt.lock", "runner/runtime/requirements.lock",
                        "nitro/ubuntu-snapshot.sources", "nitro/ubuntu-snapshot-ca.pem"}
    expected_kms = {"nitro/" + name for name in (
        "KmsBuilder.Dockerfile", "ubuntu-snapshot.sources", "ubuntu-snapshot-ca.pem",
        "kms-build-apt.lock", "kms-sources.lock.json", "kms-nsm-Cargo.lock",
        "kms-compile.sh", "kms_prepare.py", "build-kms-helper.sh")}
    expected_runner = {"runner/Cargo.toml", "runner/Cargo.lock",
                       "nitro/RunnerBuilder.Dockerfile", "nitro/build-runner.sh"}
    expected_runner.update(str(path.relative_to(repo))
                           for path in (repo / "runner/src").rglob("*") if path.is_file())
    for inputs, required in ((runtime_inputs, expected_runtime),
                             (kms["input_sha256"], expected_kms),
                             (runner["input_sha256"], expected_runner)):
        if not required.issubset(inputs):
            raise RuntimeError("component provenance is missing required source inputs")
        for name, expected in inputs.items():
            relative = PurePosixPath(name)
            if relative.is_absolute() or ".." in relative.parts:
                raise RuntimeError("unsafe component source path")
            path = repo / name
            if not path.resolve().is_relative_to(repo) or digest(path) != expected:
                raise RuntimeError("component source input changed: " + name)

    for component, directory, names in ((kms, args.kms, ("kmstool_enclave_cli", "libnsm.so")),
                                         (runner, args.runner, ("scb-runner",))):
        if component.get("build_network") != "none":
            raise RuntimeError("component compilation must be offline")
        for name in names:
            if digest(directory / name) != component["artifact_sha256"][name]:
                raise RuntimeError("component binary digest differs: " + name)
    if runner.get("build_commit") != source["build_commit"]:
        raise RuntimeError("runner embedded identity differs from EIF source")
    if (runner.get("cargo_default_features") is not False
            or runner.get("cargo_features") != []
            or runner.get("cargo_locked") is not True
            or runner.get("cargo_offline") is not True
            or runner.get("target") != "x86_64-unknown-linux-gnu"):
        raise RuntimeError("runner must use the locked production feature set and target")
    if (digest(args.runtime) != runtime["archive_sha256"]
            or args.runtime.stat().st_size != runtime["archive_bytes"]
            or runtime.get("platform") != "linux/amd64"):
        raise RuntimeError("runtime archive differs from its provenance")
    print(json.dumps({"runner": runner, "kms": kms, "runtime": runtime},
                     indent=2, sort_keys=True))


def tooling(repo):
    lock = json.loads((repo / "nitro/nitro-cli-blobs.lock.json").read_text())
    blobs = Path(os.environ.get("NITRO_CLI_BLOBS", "/usr/share/nitro_enclaves/blobs"))
    hashes = {name: digest(blobs / name) for name in lock["sha256"]}
    if hashes != lock["sha256"]:
        raise RuntimeError("Nitro CLI kernel/bootstrap blobs differ from the reviewed source lock")
    version = subprocess.check_output(["nitro-cli", "--version"]).decode().strip()
    if version != lock["version"]:
        raise RuntimeError("Nitro CLI version differs from its source lock")
    executable = shutil.which("nitro-cli")
    if not executable:
        raise RuntimeError("Nitro CLI executable not found")
    return {"version": version, "executable_sha256": digest(executable),
            "blobs": lock, "docker_version": subprocess.check_output(
                ["docker", "version", "--format", "{{.Server.Version}}"]).decode().strip()}


def record(args):
    repo = args.repo.resolve()
    before = json.loads(args.snapshot.read_text())
    if snapshot(repo) != before:
        raise RuntimeError("source changed during EIF build; rebuild from one stable snapshot")
    description = json.loads(args.description.read_text())
    measurements = description["Measurements"]
    for name in ("PCR0", "PCR1", "PCR2"):
        value = measurements[name]
        if (not isinstance(value, str) or len(value) != 96
                or any(c not in "0123456789abcdef" for c in value)
                or value in ("0" * 96, "f" * 96)):
            raise RuntimeError("invalid EIF measurement")
    context = args.context
    inputs = {name: digest(context / name) for name in (
        "scb-runner", "kmstool_enclave_cli", "libnsm.so", "scb-exploit-runtime.tar", "Enclave.Dockerfile")}
    components = json.loads((context / "components.json").read_text())
    build_tooling = json.loads((context / "tooling.json").read_text())
    if tooling(repo) != build_tooling:
        raise RuntimeError("Nitro/Docker build tooling changed during EIF build")
    for component, names in ((components["runner"], ("scb-runner",)),
                             (components["kms"], ("kmstool_enclave_cli", "libnsm.so"))):
        for name in names:
            if inputs[name] != component["artifact_sha256"][name]:
                raise RuntimeError("copied build artifact differs from provenance: " + name)
    if inputs["scb-exploit-runtime.tar"] != components["runtime"]["archive_sha256"]:
        raise RuntimeError("copied runtime differs from provenance")
    result = {
        "schema": "scb-eif-provenance-v1", "development_only": not args.release,
        "release_approved": False,
        "source": before, "protocol": "SCB_VERDICT_V5",
        "image_id": subprocess.check_output([
            "docker", "image", "inspect", "--format", "{{.Id}}", args.image]).decode().strip(),
        "eif_sha384": digest(args.eif, "sha384"), "eif_bytes": args.eif.stat().st_size,
        "measurements": measurements, "eif_description": description,
        "input_sha256": inputs, "cargo_lock_sha256": digest(repo / "runner/Cargo.lock"),
        "components": components,
        "tooling": build_tooling,
        "os_packages": sorted(subprocess.check_output([
            "docker", "run", "--rm", "--network", "none", "--entrypoint", "dpkg-query",
            args.image, "-W", "-f=${Package}=${Version}\\n"]).decode().splitlines()),
        "limitations": ["dirty source permitted only for development",
                        "locked dependencies do not establish bit-for-bit reproducibility",
                        "local unsigned provenance requires independent release review",
                        "no Nitro execution, KMS release, or reproducibility proof implied"],
    }
    print(json.dumps(result, indent=2, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    snap = sub.add_parser("snapshot")
    snap.add_argument("repo", type=Path)
    components = sub.add_parser("validate-components")
    for name in ("repo", "snapshot", "runner", "kms", "runtime"):
        components.add_argument("--" + name, type=Path, required=True)
    components.add_argument("--release", action="store_true")
    tool = sub.add_parser("tooling")
    tool.add_argument("repo", type=Path)
    emit = sub.add_parser("record")
    for name in ("repo", "snapshot", "description", "context", "eif"):
        emit.add_argument("--" + name, type=Path, required=True)
    emit.add_argument("--image", required=True)
    emit.add_argument("--release", action="store_true")
    args = parser.parse_args()
    if args.command == "snapshot":
        print(json.dumps(snapshot(args.repo.resolve()), sort_keys=True))
    elif args.command == "validate-components":
        validate_components(args)
    elif args.command == "tooling":
        print(json.dumps(tooling(args.repo.resolve()), indent=2, sort_keys=True))
    else:
        record(args)


if __name__ == "__main__":
    main()

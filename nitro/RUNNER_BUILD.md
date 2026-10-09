# Pinned runner compilation

`build-runner.sh` builds the runner with the digest-pinned Rust 1.89.0 Debian
Bookworm image declared in `RunnerBuilder.Dockerfile`. Docker must already have
that image available; the script does not pull a different compiler implicitly.

```sh
nitro/build-runner.sh --dev-only --output /tmp/scb-runner-pinned-artifacts
# After source review and a clean checkout:
nitro/build-runner.sh --release --output /tmp/scb-runner-release-candidate
```

The script snapshots the runner manifest, lockfile, every file under
`runner/src`, optional `runner/build.rs`, and both builder files. Symlink inputs
are rejected. It records repository-relative SHA-256 hashes of the actual copied
inputs and verifies those source inputs and the Git commit remain unchanged
through compilation. A release build also requires the whole worktree to be
clean at the start and before publication. Local development explicitly permits
unrelated changes elsewhere while retaining the relevant source stability checks.

Dependency acquisition uses `cargo vendor --locked` in the pinned compiler
container. Compilation uses `docker build --network=none` and
`cargo build --offline --locked --no-default-features`, targeting
`x86_64-unknown-linux-gnu`. The runner's plaintext development-secret feature is
absent. The script normalizes source/vendor timestamps to the source commit
epoch, disables incremental compilation, uses a fixed target CPU, and remaps
source/compiler paths. Two independent clean builds still need comparison;
these controls alone do not prove reproducibility.

The output directory contains `scb-runner`, `compiler.txt`, `cargo.txt`, and
`provenance.json`. The JSON schema is `scb-runner-build-v1` and includes:

- `artifact_sha256.scb-runner` and repository-relative `input_sha256`;
- `source_commit`, `source_dirty`, compiled `build_commit`, and source epoch;
- the full pinned `builder_image`, platform, compiler, target, and Cargo options;
- the deterministic vendor-tree hash and vendor configuration hash;
- `build_network: "none"` and `release_approved: false`.

Consumers must match the binary to its recorded hash and match its recorded
source hashes to the release inputs. A successful `--release` command creates a
release candidate; it does not approve an EIF, KMS policy, or AWS deployment.

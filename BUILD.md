# BUILD — reproducible verifier build (trust-root recipe)

> **Status:** this is a trust-root contract, not a verified production release
> procedure. A dev-only application EIF was built locally from a dirty
> worktree, but its PCR is not approved and it has not run in a Nitro Enclave.
> The repository has candidate builders and unsigned provenance, not a reviewed
> signing/release pipeline. The runner's exploit runtime image is not
> automatically a valid Nitro image.
> Follow [`DEPLOYMENT-HANDOFF.md`](DEPLOYMENT-HANDOFF.md) for current gates;
> never pin a placeholder measurement as if it were a release.

Solana Config pins the verdict operator keys and upload encryption key. It does
not store or validate a Nitro PCR. Operators must independently verify fresh
AWS attestation against the reviewed PCR0/build before registering those keys.
KMS separately gates secret release on the approved PCR0. Public-source
reproducibility remains a release requirement.

## 1. Exploit runtime (a separate sandbox dependency)
```bash
runner/build-runtime.sh
```
`runner/runtime.Dockerfile` uses a digest-pinned Ubuntu base, a fixed signed
Ubuntu snapshot, a complete OS package lock and hashed Python wheel locks.
The builder writes a Docker archive and its input/image/hash provenance.
Both the 116-package runtime layer and the 143-package enclave OS layer built
successfully on 2026-10-09. These are dependency assertions during builds,
not Nitro execution proofs. See [dependency locks](nitro/DEPENDENCY_LOCKS.md).

## 2. Development Nitro Enclave EIF

The dedicated application image is `nitro/Enclave.Dockerfile`. It contains the
release Rust runner, KMS helper, proxy, Podman and an embedded runtime archive.
Build locally with Docker and Nitro CLI; an EC2 instance is not needed to build:
```bash
SCB_KMS_TOOL_DIR=/path/to/kmstool-artifacts \
SCB_RUNTIME_TAR=/path/to/scb-exploit-runtime.tar \
nitro/build-eif.sh --dev-only
```
The builder uses the pinned runner compiler and checks helper/runtime/runner
sidecars against the actual binaries and current source recipes before copying
them. It embeds `SCB_BUILD_COMMIT` and records source/input digests, image ID,
compiler metadata, OS package inventory, EIF SHA-384 and PCRs in
`OUTPUT.provenance.json`. It refuses source changes during a build. `--release`
requires clean source and clean component provenance; its output still has
`release_approved:false` and needs independent review. Do not authorize a
development PCR in KMS.

Dependency locking alone does not prove bit-for-bit reproducibility. Docker
installation timestamps and the Nitro root filesystem conversion boundary must
be understood and reviewed, and the two-build measurement gate remains open.

See [nitro/ATTESTATION.md](nitro/ATTESTATION.md) for key verification and
controlled first-boot provisioning. Actual Nitro execution and KMS approved-PCR
release/wrong-PCR/plain-parent denial remain mandatory before launch.

## 3. Key derivation contract (D14)
At enclave boot: fetch M from KMS (attestation-gated), then derive:
- verdict key = ed25519 seed `HKDF(M, info="scb-verdict-key-v1")`
- enc key     = X25519    `HKDF(M, info="scb-enc-key-v1")`
Keys are stable across redeploys; rotation = new info-string + multisig re-pin.

## 3. Blob retention (Lane B)

Bucket layout: `scb/envs/<sha256>.tar.gz` — the filename IS its SHA-256 hash.

### Lifecycle rule (R2 / S3-compatible)
Expire unregistered blobs after **30 days** from last modification:
```
Prefix: scb/envs/
Action: Delete objects after 30 days from last modification
```

Objects referenced by a live bounty are never expired because their manifest
pins them on-chain; the lifecycle rule only cleans up orphaned uploads that
were never registered (abandoned pack runs, test artifacts).

### Key derivation
The packager computes `sha256(tarball)` during streaming upload and uses it
as both the object key suffix AND the on-chain commitment. Two different
tarballs can never collide because SHA-256 collision resistance is the
security assumption of the protocol.

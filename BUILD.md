# BUILD — reproducible verifier build (trust-root recipe)

The on-chain trust story pins `(PCR0, ed25519 pubkey)`. Anyone must be able to
reproduce the enclave image from public source. This file is the contract.

## 1. Runner container (local verification + EIF source)
```bash
cd runner
docker build -f runtime.Dockerfile -t scb/runner-runtime:<git-sha> .
```
`runtime.Dockerfile` = ubuntu:24.04 base + python3 + pwntools + util-linux(setarch).
Base digest and every apt package version resolve from the pinned ubuntu:24.04 index
at build time — record `docker image inspect` output with the release tag when cutting
a release.

## 2. Nitro Enclave EIF (phase 7)
On a `.metal` AL2023 instance:
```bash
nitro-cli build-enclave --docker-uri scb/runner-runtime:<git-sha> \
  --output-file runner.eif
nitro-cli describe-eif   # record PCR0
```
Publish `<git-sha> -> PCR0` in the release notes; this pair is what gets pinned
on-chain via `set_operators` (multisig, timelock discipline per §11).

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

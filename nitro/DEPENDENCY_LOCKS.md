# Container dependency locks

Both the exploit runtime and enclave application use the digest-pinned Ubuntu
24.04 amd64 base in their Dockerfiles and the signed Ubuntu archive snapshot
`20261008T000000Z`. `ubuntu-snapshot.sources` is the only configured APT source.
`enclave-apt.lock` and `runner/runtime/apt.lock` list **every installed package**,
including inherited base packages, with exact versions. Docker builds install
that complete set and reject any difference in the final `dpkg-query` inventory.

The minimal base has no CA bundle. `ubuntu-snapshot-ca.pem` contains the public
ISRG Root X1 and X2 certificates published by Let's Encrypt. They authenticate
snapshot HTTPS during bootstrap; Ubuntu's built-in archive keyring separately
authenticates signed repository metadata and package hashes. TLS verification
and APT signature checks stay enabled. `Check-Valid-Until: no` only permits the
expected expiry of historical signed snapshot metadata.

The root certificate DER SHA256 fingerprints are:

- X1: `96bcec06264976f37460779acf28c5a7cfe8a3c0aaee11a8ffcee05c0bddf08c6`
- X2: `69729b8e15a86efc177a57afb7171dfc64add28c2fca8cf1507e34453ccb1470`

## Build the exploit runtime

From the repository root:

```bash
runner/build-runtime.sh
```

This creates `/tmp/scb-exploit-runtime-locked.tar` and a `.provenance.json`
containing the archive hash, image ID and dependency input hashes. The script
uses a minimal Docker context. Source commit/dirty metadata are informational;
the exact copied inputs are recorded, and the final EIF builder separately
enforces its source snapshot. Override `SCB_RUNTIME_OUTPUT` for another output
path. The default local image tag `scb-runtime:latest` preserves the enclave's
offline runtime reference; the recorded image ID and archive hash are the
immutable identities. Builds and releases must not substitute another archive
just because it has the same tag.

`runner/runtime/requirements.lock` pins the complete existing Python dependency
set and the exact CPython 3.12/Linux amd64 wheel hashes. pip uses isolated config,
the explicit PyPI index, `--require-hashes --no-deps --only-binary=:all:` and
`--no-compile`. There is no dependency resolution or Python source compilation
during image assembly. This restriction concerns runtime image dependencies;
the owner/hunter CTF Dockerfile and exploit workflows remain separate.

## Update locks deliberately

1. Review a new base digest and Ubuntu snapshot timestamp together. Confirm the
   snapshot contains the required Podman/netavark/legacy iptables versions.
2. In a disposable container from that digest, configure only the new signed
   snapshot, install the required root packages without recommendations, and
   record `dpkg-query -W | tr '\t' '=' | LC_ALL=C sort` as the full lock.
3. Resolve Python updates in that OS/CPython environment, download wheels only,
   record each wheel SHA256, and review the complete transitive version diff.
4. Rebuild both images and record provenance. Updating any input changes the
   enclave measurement and requires the release/attestation/KMS review again.

An unavailable snapshot or changed package/wheel must fail the build. Never
disable authentication, silently use a live archive, or loosen hashes to make
a release proceed. Ubuntu currently promises snapshot availability for at
least two years; a reviewed artifact mirror may be needed for longer retention.

These locks stabilize dependency selection. They do not prove bit-for-bit EIF
reproducibility, a reviewed clean source tree, real Nitro execution, sandbox
isolation, or KMS attestation policy behavior. Those release gates remain open.

Primary references: [Ubuntu snapshots](https://snapshot.ubuntu.com/),
[pip secure installs](https://pip.pypa.io/en/stable/topics/secure-installs/),
[Let's Encrypt roots](https://letsencrypt.org/certificates/).

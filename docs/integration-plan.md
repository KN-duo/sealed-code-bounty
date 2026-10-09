# Integration plan: upload exploit → real execution → atomic payout + delivery

> **Status note (2026-10-09):** this plan is historical and several seams below
> have since been closed locally (receipt contract, content-addressed artifacts,
> SCB_VERDICT_V5 manifest binding, bounded ZIP handling, and relayer recovery).
> They are not production proofs: current Rust Docker execution, Nitro attestation,
> KMS release, public HTTPS API, and devnet/mainnet deployments remain open.
> Use [`../DEPLOYMENT-HANDOFF.md`](../DEPLOYMENT-HANDOFF.md) and
> [`../tasks/todo.md`](../tasks/todo.md) as the current handoff.

Supersedes `real-execution-plan.md` (folds it in) and connects it to the
hunter-VM work.

## What the user wants (refined intent, 2026-08-28)

> The bounty's vulnerable programs run inside a TEE. A hunter uploads their
> exploit (a **zip**) on the site where the bounty is listed. The exploit is sent
> to the TEE, which unpacks it (to a home/work dir) and runs it. If the exploit
> leaks the flag, the chain verifies the flag was truly captured; then the
> exploit is delivered to the bounty creator AND the hunter is paid.
> **PARAMOUNT: no one can read the exploit at any point until payment happens.
> Only the TEE can see it, and only while executing.**

This is SealedCodeBounty's original design. The `hunter-vm/` POC demonstrated
a local Docker terminal; it does not prove the current Rust verifier or any TEE.

## Confidentiality is paramount; crypto protects transport, not the current operator

The intended production guarantee is that only an attested TEE can read an
exploit before a successful payout. The cryptographic client flow protects
bytes in transit and at rest, but it does not establish that guarantee today:

- The hunter seals the exploit with `crypto_box_seal` to the verifier public key
  (`Config.enclave_enc_pk`). It is ciphertext after leaving the browser, so the
  relayer, chain, and storage see only the sealed box.
- Only the holder of `enclave_enc_secret` can open it. The current development
  runner reads that key from its environment; an ordinary host operator can
  therefore access the secret/plaintext. It is not a TEE guarantee.
- The intended production bootstrap generates/derives the key inside an
  attested enclave and never releases it to the parent.
- On PASS the verifier re-seals the exploit to the BUYER's X25519 key and publishes it
  as the `Reveal` — so the buyer receives it ONLY as part of the paying
  transaction. On FAIL the intended flow reveals nothing and purges plaintext.

**Current boundary:** local client sealing and Rust tests do not prove operator
confidentiality. The production promise becomes supportable only after the
attestation/KMS denial-and-release proofs and sandbox review in
`DEPLOYMENT-HANDOFF.md` pass.

## Exploit submission format: a zip

The hunter uploads a **zip** (chosen over a bare .py so an exploit can carry
helpers and data). The Rust runner safely validates/extracts it into a private
workspace, mounts that workspace read-only for execution, and accepts a defined
Python entrypoint. These controls are implemented and tested locally; execution
has not been proven with Docker, and they are not yet inside a TEE.

## Implemented protocol components (not a deployed service)

1. **Atomic settlement logic is in the Solana program.** `resolve_with_attestation`
   (`programs/.../resolve_with_attestation.rs`), in ONE transaction on a valid
   solve: pays the hunter from escrow, publishes the exploit sealed to the
   buyer's X25519 key (the `Reveal` account), and mints the `Receipt`. On FAIL it
   refunds the bond and reveals nothing. The atomic exchange the user asked for
   is this instruction.

2. **The Rust Docker executor is implemented but not live-tested here.** Its
   Docker CLI arguments are shim-tested; this machine has no Docker daemon. The
   verify route defaults to a typed HTTP 501 stub. The separate `hunter-vm/`
   POC is not evidence for the production runner.

## The security crux — where judging runs

Production must judge exploits in a **verifier-controlled sandbox** (the runner),
not in the hunter's interactive VM. The current runner uses a typed 501 stub by
default; the Docker implementation has only shim coverage in this environment.
The hunter controls their own VM and could print a fake flag, so a real isolated
verifier is required before payouts can be trusted. So:

- **Hunter's interactive VM** (`hunter-vm/`, extended): a workspace to DEVELOP
  the exploit against a copy of the target. Optional convenience.
- **Verifier sandbox** (runner `DockerCli`): re-runs the SUBMITTED exploit,
  derives the real secret flag, checks capture, and only then signs the verdict
  that unlocks payout. This is the trust boundary.

(Production must harden the verifier sandbox inside a TEE so even the operator
cannot forge a verdict. A plain Docker host with an operator-held key is only a
local prototype and is not acceptable for real bounties.)

## The full cycle, end to end

1. **Buyer posts a bounty** — packages the vulnerable target (`scb-pack`, cli →
   Docker image + `manifest.json` + tarball), uploads the tarball (Lane B
   storage), and `create_bounty` commits the manifest hash + a flag commitment
   on-chain. *(Core forms/account code exist; browser artifact publishing and a
   configured production store remain open.)*
2. **Hunter (optionally) develops in an interactive VM** seeded with the target.
   *(hunter-vm/ POC, extended to per-bounty targets.)*
3. **Hunter submits the finished exploit** — sealed to the enclave/runner key,
   with an intent signature, via `submit_exploit` on-chain. *(Frontend submit
   console exists.)*
4. **The relayer drives the verifier** — content-addressed target/manifest
   fetch and hash checks are implemented locally; calls the runner's
   `/internal/verify`. *(AWS storage and execution remain unverified.)*
5. **The runner judges** — intended PASS iff the flag is captured. *(Docker
   executor exists in source; current default is a stub and real execution is
   unverified.)*
6. **Atomic settlement** — on PASS the runner signs the verdict; the relayer
   lands `resolve_with_attestation`: hunter paid, exploit sealed to the buyer,
   Receipt minted, all in one transaction. On FAIL, bond refunded, nothing
   revealed. *(Program exists.)*
7. **Buyer decrypts the reveal** in the UI with their restored backup key.
   *(Frontend Manage page + reveal path exist.)*

Several protocol seams are closed locally; the production trust boundary,
live execution and deployment gates remain open.

## Seams to close (the actual work)

**S1 — content-addressed target and manifest selection (implemented locally).**
`relayer/src/pipeline.ts` supplies bounty/solver/receipt/hash data and the runner
retrieves fixed-key manifest/environment objects through the narrow storage
broker. Both hashes and manifest limits are checked locally before sandbox use.
Live S3 and Nitro proofs are still missing.

**S2 — upload response shape mismatch (closed locally).** Frontend, CLI,
runner, relayer, and the dev rig now use `{receipt}` and register the canonical
`scb:submission:v1:<receipt>` reference. Tests reject malformed/legacy responses.
Production S3 durability and browser-to-real-runner integration remain open.

**S3 — flag-commitment agreement (locally implemented, integration open).**
The Rust runner derives the commitment in `seal_bounty`; the mock rig has its
own development behavior. Prove the browser obtains the commitment from the
current Rust runner and that it matches the on-chain bounty before closing this
gate. Development environment secrets are operator-readable and must never be
used for real submissions.

**S4 — run the real Rust runner instead of the mock (open).** Build a local
integration harness that uses the current Rust service, artifact/hash contract,
CLI/browser submission, and relayer. The default sandbox returns 501; a Rust
Docker-backed PASS/FAIL integration has not run. Local test secrets must be
synthetic and never reused in production. `enclave-exec/` scripts exercise a
different legacy JavaScript process and do not close this gate.

**S5 — per-bounty target in the interactive VM (optional).** Extend `hunter-vm/`
to load the bounty's tarball instead of the baked-in ret2win, so a hunter
develops against the real target. Not required for payout; it's the workspace.

**S6 — exploit as a zip (implemented locally).** The browser and CLI accept ZIP
bytes only and seal/hash those exact bytes. The runner validates and extracts
the archive under bounded size/file/path caps, rejects traversal and links,
accepts only a fixed `python3` executable with a validated script path, and
mounts the private workspace read-only for execution. Rust adversarial tests
cover malformed entrypoints, duplicate paths, expansion limits, traversal,
symlinks, and cleanup. A real Docker-backed submission run remains unverified
where Docker is unavailable.

**S7 — TEE deployment (the confidentiality guarantee).** Create a dedicated
enclave image/build path and enclave-native sandbox; the current
`runner/runtime.Dockerfile` is not a production EIF recipe. Generate the
secret/key inside the enclave through attestation-gated KMS, validate fresh
attestation, and pin approved keys through governed on-chain config. This gate
is not implemented and requires a reviewed, approved AWS deployment.

## Phases (sequenced)

- **P0 — current Rust runner judging (open).** Add/run a Rust-runner-backed
  Docker integration for the seeded target. Confirm solve → PASS and broken
  solve → FAIL. The current host has no Docker daemon.
- **P1 — upload contract (closed locally).** Frontend, CLI, mock, runner, and
  relayer share `{receipt}` and the canonical on-chain reference. Browser to
  real-runner integration remains open.
- **P2 — relayer/artifact/commitment wiring (implemented locally; execution
  proof open).** Content-addressed fetch/hash validation and V5 manifest binding
  are tested, but real storage and the Rust runner settlement path are unverified.
- **P3 — atomic settlement, end to end (open).** Gate: browser submit → current
  Rust runner judges → relayer submits → localnet PASS pays, creates Receipt,
  and buyer decrypts; prove FAIL, retry, and unlock too.
- **P4 — exploit ZIP (implemented locally).** Browser/CLI/runner validate ZIP
  contracts with adversarial tests. Gate: prove the archive executes in the
  current Rust sandbox once a Docker-capable host is available.
- **P5 — interactive VM per bounty (S5), optional.** hunter-vm serves the
  bounty's target; embed the terminal in the hunt page for exploit development.
- **P6 — TEE deployment (S7): the confidentiality guarantee.** Runner as an
  attested Nitro Enclave, key born in-enclave. This is the phase that makes the
  exploit unreadable by the operator before payout. Gated on AWS, an enclave-
  native sandbox, attestation/KMS proof, and independent review. No production
  flow is deployed before this phase passes.

## Lane / ownership
Spans `runner/`, `relayer/`, `cli/`, `frontend/`, and `hunter-vm/` — multiple
agents' lanes. The user has directed this integration. Coordinate before editing
the runner/relayer, whose author knows constraints not visible in the code. P0
only runs their code and is the safe start.

## Verification per phase
Existing gates (`cargo test`, `npm run build/lint`, `devrig/selftest.mjs`) plus,
at P0 and P3, a recorded transcript of a real Docker-judged PASS and FAIL — and
at P3, the on-chain payout + the buyer decrypting the delivered exploit.

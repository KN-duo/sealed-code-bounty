# Integration plan: upload exploit → real execution → atomic payout + delivery

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

This is SealedCodeBounty's original design. The `hunter-vm/` POC proved the
Docker execution mechanism; the verifier version of it runs inside the TEE.

## Confidentiality is the paramount requirement — and it already exists in the crypto

The exploit must be unreadable by anyone but the TEE until a successful payout.
The scheme already delivers this:

- The hunter seals the exploit with `crypto_box_seal` to the TEE's public key
  (`Config.enclave_enc_pk`). It is ciphertext from the moment it leaves the
  browser — the relayer, the chain, storage, and any observer see only the
  sealed box.
- Only the holder of `enclave_enc_secret` can open it (`runner/src/routes.rs`
  `unseal`). Inside a real TEE that key is generated in-enclave and never leaves,
  so **literally only the TEE can decrypt the exploit, and only in memory while
  running it.**
- On PASS the TEE re-seals the exploit to the BUYER's X25519 key and publishes it
  as the `Reveal` — so the buyer receives it ONLY as part of the paying
  transaction. On FAIL nothing is revealed and the plaintext is purged.

**The honest constraint this creates:** the guarantee is only real in the TEE.
Pre-TEE, `enclave_enc_secret` is an env var (`SCB_ENCLAVE_ENC_SECRET_HEX`), so the
operator holds it and could in principle read exploits. Everything can be built
and tested pre-TEE with an operator-held key; the "no one but the TEE" promise
becomes true only when deployed in an AWS Nitro Enclave (needs AWS — Lane H).
There is no pre-TEE shortcut that also keeps the confidentiality guarantee — the
TEE IS the guarantee.

## Exploit submission format: a zip

The hunter uploads a **zip** (chosen over a bare .py so an exploit can carry
helpers, data, a requirements pin). The TEE unseals it, unpacks it into the
exploit container's work dir, and runs a defined entrypoint (default
`exploit.py`; overridable via a small `scb-exploit.json` in the zip). Today the
runner handles a single plaintext `exploit.py` (`sandbox.rs` writes `exploit.py`,
runs `python3 exploit.py`) — extending this to unpack-and-run a zip is a
contained change (S6 below), with the same safe-unpack caps already used for the
target tarball (`runner/src/unpack.rs`).

## Two things that already exist — do not rebuild

1. **Atomicity is already in the Solana program.** `resolve_with_attestation`
   (`programs/.../resolve_with_attestation.rs`), in ONE transaction on a valid
   solve: pays the hunter from escrow, publishes the exploit sealed to the
   buyer's X25519 key (the `Reveal` account), and mints the `Receipt`. On FAIL it
   refunds the bond and reveals nothing. The atomic exchange the user asked for
   is this instruction.

2. **The Docker judging engine already exists.** The runner's `DockerCli` sandbox
   (`runner/src/sandbox.rs`) loads a target image, starts it on a loopback
   network, runs the exploit container, captures output; the verify route
   (`runner/src/routes.rs`) decides PASS iff the output contains the derived
   flag, then redacts and seals the reveal. The `hunter-vm/` POC proved this same
   docker-run-and-capture mechanism works end to end.

## The security crux — where judging runs

The exploit must be judged in a **verifier-controlled sandbox** (the runner), NOT
in the hunter's interactive VM. The hunter controls their own VM and could print
a fake flag; only a sandbox the hunter cannot tamper with can be trusted to
gate a payout. So:

- **Hunter's interactive VM** (`hunter-vm/`, extended): a workspace to DEVELOP
  the exploit against a copy of the target. Optional convenience.
- **Verifier sandbox** (runner `DockerCli`): re-runs the SUBMITTED exploit,
  derives the real secret flag, checks capture, and only then signs the verdict
  that unlocks payout. This is the trust boundary.

(Production hardens the verifier sandbox inside a TEE so even the operator can't
forge a verdict — `PLAN-PRE-TEE.md`. Not required to see the cycle work; a plain
Docker host with the operator key is the pre-TEE stage.)

## The full cycle, end to end

1. **Buyer posts a bounty** — packages the vulnerable target (`scb-pack`, cli →
   Docker image + `manifest.json` + tarball), uploads the tarball (Lane B
   storage), and `create_bounty` commits the manifest hash + a flag commitment
   on-chain. *(Exists; the browser board already reads these.)*
2. **Hunter (optionally) develops in an interactive VM** seeded with the target.
   *(hunter-vm/ POC, extended to per-bounty targets.)*
3. **Hunter submits the finished exploit** — sealed to the enclave/runner key,
   with an intent signature, via `submit_exploit` on-chain. *(Frontend submit
   console exists.)*
4. **The relayer drives the verifier** — fetches the target tarball + manifest,
   calls the runner's `/internal/verify` with the target so the sandbox can run
   the exploit. *(GAP — see seams.)*
5. **The runner judges** — real Docker execution, PASS iff the flag is captured.
   *(Engine exists.)*
6. **Atomic settlement** — on PASS the runner signs the verdict; the relayer
   lands `resolve_with_attestation`: hunter paid, exploit sealed to the buyer,
   Receipt minted, all in one transaction. On FAIL, bond refunded, nothing
   revealed. *(Program exists.)*
7. **Buyer decrypts the reveal** in the UI with their restored backup key.
   *(Frontend Manage page + reveal path exist.)*

Most of this is built. The work is closing the seams between components.

## Seams to close (the actual work)

**S1 — relayer never tells the runner what to execute.** `relayer/src/pipeline.ts`
builds the `/internal/verify` body without `env_blob_path`, `target_image`,
`target_entrypoint`, `target_port`, so the sandbox has no target. Fetch the
tarball to a local path (verify sha256 vs on-chain `env_blob_sha256`), fetch the
manifest (verify hash vs on-chain `manifest_sha256`, read entrypoint + port), and
pass them.

**S2 — upload response shape mismatch.** Real runner `/internal/upload` returns
`{receipt}`; the frontend and dev mock expect `{blob_url}` and the frontend
records that on-chain. Settle one canonical contract across
`frontend/src/lib/runner.ts`, `frontend/devrig/enclave.mjs`, and the runner.
(This is the `blob url: undefined` → SBF panic seen in the live run; the
defensive guard from spec-05 belongs here too.)

**S3 — flag-commitment agreement.** `devrig` seeding invents a `flag_commitment`;
the real runner derives it (`seal_bounty`, HKDF over a master secret). For a real
verdict the on-chain commitment must equal what the runner derives. Post bounties
via the real runner's `seal_bounty`, not the mock's stand-in.

**S4 — run the real runner instead of the mock.** Replace `devrig/rig.mjs serve`
(mock) with the real runner (`SCB_SANDBOX=docker`, both secrets set) plus the
relayer in the local loop. Build the runtime image once
(`runner/runtime.Dockerfile`).

**S5 — per-bounty target in the interactive VM (optional).** Extend `hunter-vm/`
to load the bounty's tarball instead of the baked-in ret2win, so a hunter
develops against the real target. Not required for payout; it's the workspace.

**S6 — exploit as a zip.** The submission is a zip, not a bare .py. The TEE
unseals it, unpacks it into the exploit container's work dir under the same safe
caps as `unpack.rs` (size/file-count/traversal/symlink rejection), and runs the
entrypoint (`exploit.py` by default, or a `scb-exploit.json`-declared command).
The sealing/unsealing is unchanged — the sealed box just wraps zip bytes instead
of python bytes.

**S7 — TEE deployment (the confidentiality guarantee).** Build the runner as a
reproducible Nitro Enclave image (`runner/runtime.Dockerfile` → EIF, per
`BUILD.md`/`PLAN-PRE-TEE.md`), generate `enclave_enc_secret` inside the enclave
so it never leaves, and attest the public key that gets pinned on-chain. This is
what makes "only the TEE can read the exploit" literally true. Needs an AWS
account with Nitro Enclaves (Lane H). Everything else is built and tested
pre-TEE; this step swaps the operator-held key for an enclave-held one.

## Phases (sequenced)

- **P0 — the judging engine, standalone.** Real runner + `SCB_SANDBOX=docker` +
  a hand-built `/internal/verify` for the seeded ret2win bounty. Confirm
  `solve.py` → real Docker PASS, `solve-broken.py` → FAIL. Closes nothing on
  chain yet; proves the engine judges. (Touches runner only — runs its existing
  code.)
- **P1 — the contract (S2).** One upload/response shape across frontend, mock,
  runner; fold in the spec-05 guard. Gate: an upload round-trips with no
  mismatch.
- **P2 — relayer drives the runner (S1 + S3).** Relayer fetches target + manifest
  and calls verify with them; bounties posted via the real `seal_bounty`. Gate: a
  real on-chain submission is judged by real execution.
- **P3 — atomic settlement, end to end (S4).** Real runner + relayer replace the
  mock in the local loop. Gate: browser submit → Docker-judged PASS →
  `resolve_with_attestation` pays the hunter, seals the exploit to the buyer, and
  the buyer decrypts it. The full cycle.
- **P4 — exploit as a zip (S6).** Submission is a zip; TEE unpacks + runs the
  entrypoint. Gate: a multi-file zip exploit judged end to end.
- **P5 — interactive VM per bounty (S5), optional.** hunter-vm serves the
  bounty's target; embed the terminal in the hunt page for exploit development.
- **P6 — TEE deployment (S7): the confidentiality guarantee.** Runner as an
  attested Nitro Enclave, key born in-enclave. This is the phase that makes the
  exploit truly unreadable by anyone but the TEE. Gated on AWS (Lane H). Until
  this ships, the flow works but the operator technically holds the key — so
  P6 is required before real bounties with real money and real secret exploits.

## Lane / ownership
Spans `runner/`, `relayer/`, `cli/`, `frontend/`, and `hunter-vm/` — multiple
agents' lanes. The user has directed this integration. Coordinate before editing
the runner/relayer, whose author knows constraints not visible in the code. P0
only runs their code and is the safe start.

## Verification per phase
Existing gates (`cargo test`, `npm run build/lint`, `devrig/selftest.mjs`) plus,
at P0 and P3, a recorded transcript of a real Docker-judged PASS and FAIL — and
at P3, the on-chain payout + the buyer decrypting the delivered exploit.

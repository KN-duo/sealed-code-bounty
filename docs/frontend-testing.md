# Testing the frontend against a local chain

The frontend degrades gracefully with every backend service off — that is by design, and
it is also why most of `frontend-report.md`'s honesty table said REASONED rather than
EXECUTED. This guide stands up enough of a backend to actually run the browser through
the full loop: **seal → sign → upload → `submit_exploit` → verdict → decrypt**.

The real enclave needs Docker and a TEE. `frontend/devrig/` replaces it with a mock that
speaks the same HTTP surface and holds the operator key, so verdicts land on-chain for
real.

> **The mock proves nothing.** It does not build the target, does not run your exploit,
> and does not capture a flag. It decides on the exploit text alone. It exists to exercise
> *the frontend's* code paths, never to validate the protocol. The Anchor suite
> (`tests/sealed-code-bounty.ts`) and the real runner do that job.

---

## Why the work is split across WSL and Windows

The Solana/Anchor toolchain only exists in the WSL checkout (`~/sealed-code-bounty`); the
frontend, Node, and your browser live on Windows. So:

| half | runs where | does what |
| --- | --- | --- |
| `devrig/localnet.sh` | **WSL** | validator, `anchor build`, `anchor deploy` |
| `devrig/rig.mjs` | **Windows** | seeding, mock enclave, verdict relayer |

Everything on the Windows side talks plain JSON-RPC to `127.0.0.1:8899`, which WSL2
forwards automatically. No path translation, and when something breaks it is obvious
which half broke.

---

## Run order

### 1. Chain half — in WSL

```bash
cd ~/sealed-code-bounty
git pull
bash frontend/devrig/localnet.sh
```

**`git pull` matters here.** A checkout behind `main` builds a v1 IDL that looks valid but
names `submit_solution` / `resolve_submission` — as of this writing the WSL checkout was in
exactly that state. The script now aborts if the freshly built IDL has no `submit_exploit`.

Leave it running; Ctrl-C stops the validator. It refuses to start if `solana`,
`solana-test-validator`, or `anchor` are missing, and it warns loudly if the deployed
program id differs from the one `src/env.ts` defaults to
(`FbqouGmrsFmoC24H3x1vX3LX9jVXhUN5zDH7RnSXba9V`), printing the `VITE_PROGRAM_ID` line to
set if so.

### 2. Seed — in Windows, from `frontend/`

You need your Phantom address first: open Phantom, switch the network to a custom RPC of
`http://127.0.0.1:8899`, and copy the account address.

```powershell
node devrig/rig.mjs seed --wallet <your-phantom-pubkey>
```

This airdrops 20 SOL to you, initializes `Config`, **registers the rig's operator key**
(required — `initialize_config` leaves `operators` empty and `resolve_with_attestation`
rejects unregistered signers), seeds two demo bounties, and writes `frontend/.env.local`.
It prints a `#/hunt/...` link per bounty. Re-running it is safe: config init is skipped if
present, and each run seeds fresh bounty ids.

### 3. Mock enclave — separate Windows terminal, from `frontend/`

```powershell
node devrig/rig.mjs serve
```

Prints its verdict rule at startup. `--always pass` / `--always fail` forces the outcome
regardless of what you submit, which is the quickest way to reach a specific screen.

### 4. Dev server

```powershell
npm run dev
```

Restart it if it was already running — step 2 wrote `.env.local`.

---

## What the verdict rule is

The mock unseals your exploit with the enclave key it owns, then:

- **FAIL** if the text matches `/broken/i`, or is under 20 bytes
- **PASS** otherwise

So `examples/ret2win/solution/solve.py` passes and `solve-broken.py` fails, without
brittle hash matching against files you may want to edit.

On PASS it seals the exploit to the bounty's on-chain `buyer_enc_pk` and writes it as the
**inline** reveal carrier (the mock does not implement the URL carrier, so exploits must
seal to under 9,700 bytes). On FAIL it sends no ciphertext and no receipt/reveal accounts,
which is what the program requires.

---

## Scenarios worth walking

**1. Read paths.** `#/` lists the seeded bounties with real decoded fields;
`#/bounty/<pda>` shows the humanized detail plus raw JSON; `#/leaderboard` is empty until
someone wins. This is the first real exercise of the decode/normalize layer and of the
account-namespace casing bridge in `lib/anchorClient.ts`.

**2. PASS.** Open a printed `#/hunt/<pda>` link, connect Phantom, drop
`examples/ret2win/solution/solve.py`, and hit *Seal, sign & submit*. Expect the activity
log to walk sha256 → sealed box → intent signature → `blob url` → `tx`, then flip to the
win screen within a few seconds. Check `#/leaderboard` for the Receipt.

**3. FAIL.** Same on the second seeded bounty with `solve-broken.py`. Expect the
did-not-pass screen, the submission slot reopened, and your bond refunded.

**4. Buyer loop.** `#/post` with Phantom: generate a key, download the backup (the wizard
gates on it), finish the manifest form. This is the first live call to
`/internal/seal_bounty`. Then hunt your own bounty to a PASS — the program imposes no
buyer≠solver rule — and go to `#/manage` → *Restore from backup* → decrypt-reveal. The
plaintext must match what you submitted. Also worth checking here: cancel on an expired
bounty and reclaim rent on a resolved one.

Reveals for the **rig-seeded** bounties are sealed to the rig's own buyer key, not yours,
so scenario 4 needs a bounty you posted yourself.

---

## Offline checks

```powershell
node devrig/selftest.mjs
```

No validator needed. Covers the `SCB_VERDICT_V4` wire length, operator signatures, both
sealed-box hops, and the mock's HTTP surface — the things that break silently if the
program's constants drift.

---

## Troubleshooting

| symptom | cause |
| --- | --- |
| "Network unavailable" (amber plug) on data screens | no validator, or the wrong `VITE_PROGRAM_ID`. Expected with everything off. |
| "Could not reach the verifier at /enclave (dev proxy → …)" | `rig.mjs serve` is not running. |
| `seed` says the program is not deployed | step 1 did not finish, or the deployed id differs — see its warning. |
| Verdict never arrives | check the `serve` terminal: it logs `verdict` and `resolved` lines, and any resolve failure. A relayer under 1 SOL is called out at startup. |
| Phantom shows no SOL | it is on the wrong network — the custom RPC must be `http://127.0.0.1:8899`. |
| `localnet.sh: bad interpreter` in WSL | CRLF line endings; `frontend/.gitattributes` pins `*.sh` to LF, so re-checkout the file. |
| `localnet.sh` aborts on a stale IDL | the WSL checkout is behind `main`; `git pull --rebase origin main` there and re-run. |
| `'solana' is not on PATH` | the installers export PATH from `.bashrc`, which non-interactive shells skip. The script adds the usual install dirs itself; if it still fails, the toolchain really is missing. |

Teardown: Ctrl-C both terminals, and `rm -rf test-ledger` in WSL. `devrig/rig.local.json`
holds dev-only keys and is gitignored — delete it to start from fresh keys, but re-run
`seed` afterwards, since the on-chain `Config` still points at the old enclave key.

---

## A real gap this surfaced

`src/lib/runner.ts` sends `content-type: application/json`, which is not a CORS-simple
request, so browsers preflight it with `OPTIONS`. `runner/src/routes.rs` mounts its four
`/internal` routes with **no CORS layer and no `OPTIONS` handler** — so a direct
browser call to `:8443` fails at the preflight against the real runner, not just the mock.

The frontend now proxies `/enclave → 127.0.0.1:8443` through the Vite dev server
(`vite.config.ts`, `src/env.ts`), which sidesteps it entirely in development. **Any
browser-facing deployment of the real runner still needs a CORS layer**, or an equivalent
same-origin reverse proxy in front of it. That is a `runner/` change and belongs to its
owner. The mock sends permissive CORS headers of its own, so it also works if you point
`VITE_ENCLAVE_URL` straight at `:8443`.

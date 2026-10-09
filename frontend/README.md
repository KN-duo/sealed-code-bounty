# SealedCodeBounty — frontend

## Deployment status (2026-10-09)

This is a local-development walkthrough, not a production deployment guide.
There is no public website, deployed program, production RPC configuration,
authenticated verifier API, or attested Nitro runner. `devrig/rig.mjs serve`
is a mock that accepts/rejects by payload length; it does **not** execute the
uploaded ZIP. Do not use it for real bounties or present a static build as a
working TEE service.

A future static-host build must explicitly set `VITE_CLUSTER`, `VITE_PROGRAM_ID`,
`VITE_RPC_URL`, and `VITE_ENCLAVE_URL`; `npm run build:deploy` now blocks
missing/localnet/loopback or malformed settings. This is only a configuration
shape check, not proof the selected chain, API, or TEE is live. The site must
also route browser-facing verifier requests through authenticated HTTPS to the
real service. The Vite dev proxy is development-only. Mainnet additionally
requires the independent review and launch gates in
[`../DEPLOYMENT-HANDOFF.md`](../DEPLOYMENT-HANDOFF.md). See
[`../docs/hosting-readiness.md`](../docs/hosting-readiness.md) for the free-static
hosting option and the $2/month constraints.

The intended flow lets companies post SOL bounties on authorized vulnerable
software and hunters seal exploits client-side (`crypto_box_seal`). A verifier
then judges PASS/FAIL; on PASS, escrow pays the winner and an on-chain Reveal
delivers the exploit encrypted to the buyer's X25519 key. The verifier is not
currently attested or deployed; see the deployment status above.

React 19 + Vite + TS + `@solana/wallet-adapter` + `@anchor-lang/core`. Architecture and
honesty table: [`../docs/frontend-report.md`](../docs/frontend-report.md). Rig internals
and the full troubleshooting table: [`../docs/frontend-testing.md`](../docs/frontend-testing.md).

This README walks one stranger through the **full buyer-decrypt loop on localnet**:
post → hunt → PASS → restore backup key → decrypt the Reveal in the UI.

---

## Prerequisites

| what | where | notes |
| --- | --- | --- |
| Node 22.18+ or Node 24 | Windows | required for the TypeScript contract checks in the rig |
| Solana + Anchor toolchain | **WSL only** | installed in the WSL checkout `~/sealed-code-bounty`; Windows never needs it |
| this repo in WSL at `~/sealed-code-bounty` | WSL | the chain half runs there |
| Phantom (browser extension) | Windows browser | will be pointed at the local validator |
| `frontend/node_modules` present | Windows | `npm install` once from `frontend/` if missing |

Two rules that prevent most confusion:

- The **chain half** (validator, build, deploy) runs **inside WSL**.
- Everything else (seeding, mock enclave, dev server, browser) runs **on Windows**,
  talking JSON-RPC to `http://127.0.0.1:8899`, which WSL2 forwards automatically.

Commands below are labelled **[WSL bash]** or **[PowerShell]**. Steps marked
**(by hand)** are clicks only you can do — no script does them for you.

---

## Walkthrough: post → hunt → PASS → decrypt

### 1. Bring up the chain half — `[WSL bash]`

```bash
cd ~/sealed-code-bounty
git pull
bash frontend/devrig/localnet.sh
```

`anchor build` takes minutes — let it finish. **Correct output ends with**
`==> chain half is up.` plus the three commands to run next, and earlier prints
`==> program id matches the frontend default`. **Leave this terminal running**;
Ctrl-C here stops the validator. If it aborts instead, follow its own printed fix
(stale checkout, missing toolchain) or see the troubleshooting table in
[`../docs/frontend-testing.md`](../docs/frontend-testing.md).

### 2. Point Phantom at the localnet — `(by hand)`

In Phantom: settings → developer settings → change network → **custom RPC** →
`http://127.0.0.1:8899`. Then click the address at the top to copy your pubkey.
If you skip this, transactions will target the wrong network and everything
looks dead.

### 3. Seed the chain — `[PowerShell]`, from `frontend/`

```powershell
node devrig/rig.mjs seed --wallet <the-pubkey-you-copied>
```

**Correct output:** `airdropped your wallet`, `config initialized`,
`operators [...] threshold 1`, two `bounty #<id> ... -> <pda>` lines, and
`env wrote ...\frontend\.env.local`.

> Read the last paragraph it prints: those demo bounties' reveals are sealed to
> the **rig's** buyer key, not yours. They are for hunting practice only — the
> decrypt exercise needs a bounty **you** post in step 5.

### 4. Start the mock enclave — `[PowerShell]`, second terminal

```powershell
node devrig/rig.mjs serve
```

**Correct output:** `mock enclave listening on http://127.0.0.1:8443` and a rule
that says it passes payloads at least 20 bytes long. The mock does not execute
exploit archives.
Leave it running — it is also the relayer that lands verdicts on-chain, and it
logs every `upload` / `verdict` / `resolved` line there.

### 5. Dev server — `[PowerShell]`, third terminal

```powershell
npm run dev
```

**Correct output:** Vite ready on `http://localhost:5173/`. Restart it if it was
already running before step 3 — seeding wrote `.env.local`.

### 6. Post a bounty (and back up the decryption key) — `(by hand)` in the browser

1. Open `http://localhost:5173/#/post`, connect Phantom, approve nothing yet.
2. Click **Generate decryption key**. A 64-char hex secret appears in red —
   this is the *only* copy of the key that will ever exist outside the backup.
3. Click **Download backup**. The browser saves
   `scb-buyer-key-XXXXXXXX.json` (check your Downloads folder — the secret stays
   on screen until you continue exactly so a failed download is recoverable).
4. **Continue** unlocks only after the download click. Manifest form — these
   exact values work on localnet:
   - Image tarball URL: `https://example.com/target.tar.gz`
   - Image tarball sha256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
   - leave every other field at its default (prize 0.5 SOL, deadline +7 days)
5. **Review → Seal & post bounty**, approve the Phantom transaction.
   **Correct output:** green *Bounty is live* screen with a `tx` badge.

The mock's `/internal/seal_bounty` answered during this step — if it had not,
you would have seen `Could not reach the verifier at /enclave …` instead.

### 7. Hunt your own bounty to PASS — `(by hand)` in the browser

The program has no buyer≠solver rule, so one wallet plays both sides.

1. Copy your bounty address (click the hash badge on the done screen), then
   visit `http://localhost:5173/#/hunt/<that-address>`.
2. Create a ZIP with a top-level `exploit.py` and drop it into the exploit box.
   From `frontend/`, this PowerShell snippet packages the example:

   ```powershell
   $pkg = Join-Path $env:TEMP ("scb-exploit-" + [guid]::NewGuid())
   New-Item -ItemType Directory -Path $pkg | Out-Null
   Copy-Item ..\examples\ret2win\solution\solve.py (Join-Path $pkg "exploit.py")
   Compress-Archive -Path (Join-Path $pkg "*") -DestinationPath .\exploit.zip -Force
   Remove-Item -LiteralPath $pkg -Recurse -Force
   ```

   The demo mock does not unpack or execute the script, so this walkthrough
   proves browser/chain wiring, not real judging.
3. Click **Seal, sign & submit**; approve **two** Phantom prompts — a message
   signature (the intent proof) and the transaction (which posts a 0.05 SOL bond).
4. **Correct output:** the activity log walks `sha256(exploit)` → `sealed box` →
   intent signature → `enclave receipt: …` → `tx: …`, then flips to
   **“Flag captured — you won!”** within a few seconds. In the `serve` terminal
   you'll see matching `verdict … PASS` and `resolved <sig>` lines.

On PASS the enclave sealed your exploit plaintext to **your** X25519 public key
(the one from step 6) and published it as the Reveal account.

### 8. Restore from the backup and decrypt — `(by hand)` in the browser

Session keys live in `sessionStorage`, which is **per tab**: closing the tab
throws them away. That is exactly the situation the restore path exists for.

1. Close the browser tab, open a fresh one, go to
   `http://localhost:5173/#/manage`, reconnect the same Phantom account.
   Your bounty is listed with status **Resolved**.
2. Click **Decrypt exploit**. The modal now says the key isn't in this session.
3. Drop the `scb-buyer-key-XXXXXXXX.json` from step 6. **Correct output:**
   `Key restored · ab12cd…` (the first chars of your key's public half).
4. Click **Decrypt now**. **Correct output:** green “Decrypted successfully.” and
   the exploit ZIP — byte-for-byte the archive you submitted. The
   **Download exploit** button saves it.

(Skip step 8's tab-close and the modal decrypts immediately — same code path,
just without the restore.)

### 9. Recognising failure instead of silence

Every failure in this loop is designed to render a specific message:

| you see | it means |
| --- | --- |
| amber “Network unavailable” plug | no validator answering `VITE_RPC_URL` |
| “Could not reach the verifier at /enclave …” | step 4's `serve` isn't running |
| “Could not reach the Solana RPC endpoint to read the Reveal account…” | validator died between PASS and decrypt |
| “Decryption failed — this reveal is sealed to a different key…” | you restored a backup from a *different* posting session |
| “Not a valid JSON backup file.” / “Backup is format version …” | wrong or foreign file dropped on the restore zone |
| stuck on “Awaiting verdict…” past ~30 s | read the `serve` terminal — it logs why a resolve failed |

Anything else is a bug worth reporting.

### 10. Teardown

Ctrl-C all three terminals. Then:

**[WSL bash]**

```bash
cd ~/sealed-code-bounty && rm -rf test-ledger
```

`frontend/devrig/rig.local.json` holds dev-only keys and is gitignored; deleting
it resets identities but requires re-running step 3, since the on-chain Config
still points at the old enclave key.

---

## Offline checks (no validator needed)

**[PowerShell]**, from `frontend/`:

```powershell
npm run build
npm run lint
node devrig/selftest.mjs
```

All three must be clean; `selftest` covers the verdict wire format and both
sealed-box hops — the things that break silently when constants drift.

With Node 22.18+ (or Node 24), run the upload-contract checks with:

```bash
node --test devrig/upload-contract.test.mjs
```

The upload API returns exactly `{ "receipt": "<64 lowercase hex>" }`.
The browser validates it before registering `scb:submission:v1:<receipt>` in
the on-chain `blob_url` field. This opaque receipt identifies the encrypted
upload record; the plaintext exploit hash remains a separate commitment. The
development rig uses a loopback-only, in-memory mock and loses uploads on
restart. It does not demonstrate durable storage, real execution, or a TEE.

## Production hosting checklist

Run `npm run test:deploy` to test the production configuration guard. Static
host builds should use `npm run build:deploy` (not bare `npm run build`); it
requires explicit `VITE_CLUSTER=devnet|mainnet`, a valid `VITE_PROGRAM_ID`, an
HTTPS public `VITE_RPC_URL`, and an explicit `VITE_ENCLAVE_URL` (same-origin
path such as `/enclave` or a public HTTPS URL). The guard validates input shape
only; it cannot confirm the cluster/program match or that either service is
reachable. Every `VITE_*` value is public browser-bundle data.

The current Vite app expects a same-origin reverse proxy at `/enclave`; merely
uploading `dist/` to a static host leaves posting and submissions unavailable.
Before hosting a usable public app, provide and verify all of the following:

- An explicit production `VITE_CLUSTER`, `VITE_PROGRAM_ID`, and HTTPS
  `VITE_RPC_URL` that point to the same already-deployed Solana cluster.
- An authenticated HTTPS API/reverse proxy for the runner, with client
  authentication, rate limiting, and proxy-aware IP limits. Do not trust raw
  forwarded-IP headers.
- A fresh, independently verified enclave attestation before the browser trusts
  verifier encryption/signing keys.
- Hosting security headers and immutable-asset/short-`index.html` cache policy.
- For mainnet: independent security review, multisig/authority checks, key
  rotation and incident procedures, and a capped canary.

Cloudflare Pages Free is the current budget-compatible static-host candidate,
not a selected or deployed provider. The frontend can be built without external
services, but publishing it now would not produce a working or safe CTF service.

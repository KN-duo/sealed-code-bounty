# SealedCodeBounty — frontend

Companies post SOL bounties on vulnerable software. Hunters submit exploits that are
sealed client-side (`crypto_box_seal`) before they ever leave the browser; an enclave
verifier decides PASS/FAIL; on PASS the winner is paid from escrow, mints an on-chain
Receipt, and the **buyer receives the exploit encrypted to their X25519 key** as an
on-chain Reveal account.

React 19 + Vite + TS + `@solana/wallet-adapter` + `@anchor-lang/core`. Architecture and
honesty table: [`../docs/frontend-report.md`](../docs/frontend-report.md). Rig internals
and the full troubleshooting table: [`../docs/frontend-testing.md`](../docs/frontend-testing.md).

This README walks one stranger through the **full buyer-decrypt loop on localnet**:
post → hunt → PASS → restore backup key → decrypt the Reveal in the UI.

---

## Prerequisites

| what | where | notes |
| --- | --- | --- |
| Node 22 | Windows | `node --version` should print v22.x |
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

**Correct output:** `mock enclave listening on http://127.0.0.1:8443` and
`verdict rule PASS unless the exploit matches /broken/i or is under 20 bytes`.
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
2. Drop `../examples/ret2win/solution/solve.py` into the exploit box (any text
   file ≥ 20 bytes that doesn't contain the word "broken" works).
3. Click **Seal, sign & submit**; approve **two** Phantom prompts — a message
   signature (the intent proof) and the transaction (which posts a 0.05 SOL bond).
4. **Correct output:** the activity log walks `sha256(exploit)` → `sealed box` →
   intent signature → `blob url: mock://…` → `tx: …`, then flips to
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
   the exploit plaintext — byte-for-byte the contents of `solve.py`. The
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

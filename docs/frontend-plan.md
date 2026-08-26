# SealedCodeBounty — Frontend Plan (v2)

> Staff-engineer plan for the human surface of SealedCodeBounty. Source of truth
> for the protocol is `programs/sealed-code-bounty/src` + `BUILD-PLAN.md §1`.
> This plan is stable; milestone status is tracked in the session task list and
> the final `docs/frontend-report.md`.

## 0. Product in one sentence

Companies post money-bounties on vulnerable targets; hunters submit exploits that
stay cryptographically sealed; an enclave verifier decides PASS/FAIL; winners are
paid from escrow and earn permanent on-chain Receipts; the buyer receives the
exploit encrypted to their key. The frontend is the only human-facing surface.

## 1. Protocol facts the UI is built against (verified from source)

Program id `FbqouGmrsFmoC24H3x1vX3LX9jVXhUN5zDH7RnSXba9V` (override `VITE_PROGRAM_ID`).
RPC `http://127.0.0.1:8899` (`VITE_RPC_URL`). Runner/enclave `http://127.0.0.1:8443`
(`VITE_ENCLAVE_URL`).

**Instructions the UI sends** (args verified from `lib.rs` + contexts):
- `create_bounty(bounty_id u64, prize_lamports u64, deadline i64, manifest_sha256 [32], env_blob_sha256 [32], flag_commitment [32], buyer_enc_pk [32])`
  — accounts: buyer(signer), config PDA, bounty PDA `["bounty", buyer, bounty_id_le]`, system_program.
- `submit_exploit(bounty_id u64, blob_url string, exploit_sha256 [32])`
  — accounts: solver(signer), config PDA, bounty PDA, system_program. Charges `Config.submission_bond_lamports`.
- `cancel_expired_bounty(bounty_id u64)` — buyer(signer), bounty PDA (close=buyer). Only when Open + no submission + expired.
- `close_resolved_bounty(bounty_id u64)` — caller(signer), bounty, buyer. Reclaims rent after Resolved.

The UI **never** calls `resolve_with_attestation`, `initialize_config`,
`set_operators`, or `force_unlock_submission` — those are relayer/enclave/admin/ops.
They exist in the IDL for completeness + decoding only.

**Accounts the UI reads** (layouts verified from `state.rs`):
- `Config` (PDA `["config"]`): platform_authority, operators[], threshold,
  `enclave_enc_pk [32]` (hunters seal to this), submission_bond_lamports,
  force_unlock_delay_s, bump.
- `Bounty` (PDA `["bounty", buyer, bounty_id_le]`): buyer, bounty_id,
  `status` {Open, AwaitingResolution, Resolved, Cancelled}, prize_lamports,
  deadline, manifest_sha256, env_blob_sha256, flag_commitment, buyer_enc_pk,
  `current_submission` Option<SubmissionRef{solver, exploit_sha256, blob_url,
  bond_lamports, submitted_at}>, winner Option<pubkey>, bump.
- `Receipt` (PDA `["receipt", bounty, winner]`): bounty, solver, exploit_sha256,
  first_blood, timestamp. **Powers the leaderboard.**
- `Reveal` (PDA `["reveal", bounty]`): ciphertext (≤9700 B inline sealed box),
  ciphertext_url, ciphertext_sha256. Exactly one carrier on PASS.

**Off-chain runner/enclave HTTP** (base `VITE_ENCLAVE_URL`):
- Buyer: `POST /internal/seal_bounty {bounty_pda}` → `{flag_commitment}`.
- Hunter: `POST /internal/upload {bounty_pda, claimed_chain_view{env_blob_sha256,
  buyer_enc_pk, exploit_sha256, flag_commitment}, solver_pubkey,
  submit_intent_sig (b64), exploit_sealed_box (b64)}` → `{blob_url}`.

**Client crypto** (libsodium-wrappers + @noble/hashes):
- Buyer keypair: X25519 `crypto_box_keypair()`. Public key → `buyer_enc_pk`.
- Hunter seal: `crypto_box_seal(exploit, Config.enclave_enc_pk)`.
- Buyer reveal decrypt: `crypto_box_seal_open(ciphertext, buyer_pk, buyer_sk)`.
- Intent signature: wallet `signMessage(b"SCB_SUBMIT_V1" || bounty_pda(32) || sha256(exploit))`.

## 2. The fresh IDL (riskiest unknown — RESOLVED)

The committed IDL was **stale v1** (`test_suite_hash`, `submit_solution`, plaintext
`solution`) and no v2 build artifact existed anywhere (WSL's was v1 too, wrong
program address). I regenerated `frontend/src/idl/sealed_code_bounty.{json,ts}`
deterministically from `state.rs`/`lib.rs`: Anchor discriminators are
`sha256("global:"+ix)[..8]` / `sha256("account:"+name)[..8]` (verified against the
known `create_bounty` discriminator), spec `0.1.0`, all 8 instructions, 4 accounts,
8 events, 23 errors, full type layouts. The generator lives in the job scratch dir;
after any future `anchor build`, replace with the real `target/idl` output.

## 3. Second risk: browser Buffer/global

`@solana/web3.js` + `@anchor-lang/core` use Node `Buffer`/`global`. Vite does not
polyfill these. Fix in M1: `vite.config.ts` `define: { global: 'globalThis' }` +
`src/polyfills.ts` (`import { Buffer } from 'buffer'; globalThis.Buffer ??= Buffer`)
imported first in `main.tsx`. `buffer` is a transitive dep of web3.js; if it fails
to resolve as a bare import, add it as an explicit dep (justified in report).

## 4. Routing (no react-router — not in allowed deps)

Tiny hash router (`src/router/`), ~40 lines: `useHashRoute()` parses
`window.location.hash`, `<Link>` sets it, `<Route>`/`<Router>` match patterns with
`:params`. Routes:

| hash | page | flow |
|------|------|------|
| `#/` | Board | browse open/historical bounties |
| `#/bounty/:pda` | BountyDetail | humanized public fields, timeline |
| `#/leaderboard` | Leaderboard | winner ranking from Receipts |
| `#/post` | PostBounty | buyer wizard |
| `#/manage` | Manage | buyer's bounties + decrypt reveal |
| `#/hunt/:pda` | SubmitConsole | hunter submit flow |
| `*` | NotFound | friendly fallback |

## 5. Data layer / module map

```
src/
  polyfills.ts            Buffer/global shim (imported first)
  main.tsx, App.tsx       root + router mount
  env.ts                  VITE_* config, cluster label+color
  router/                 useHashRoute, Link, Router, Route
  theme.css               design tokens (dark mission-control)
  lib/
    pda.ts                PROGRAM_ID + configPda/bountyPda/receiptPda/revealPda
    format.ts             lamports<->SOL, truncateHash, countdown, statusMeta, copy
    async.ts              AsyncState<T> discriminated union + helpers
    crypto.ts             libsodium: keygen/seal/unseal, noble sha256, intent msg
    backup.ts             buyer-key backup file (create/parse/download) + session store
    runner.ts             enclave HTTP client (sealBounty, upload) + typed errors
    anchorClient.ts       Program builder + typed fetchers/decoders
  hooks/
    useProgram.ts         Program from wallet (reused, env-corrected)
    useConfig.ts          Config account (bond, enclave_enc_pk)
    useBounties.ts        all Bounty accounts -> AsyncState
    useBounty.ts          one Bounty by pda -> AsyncState
    useReceipts.ts        all Receipt accounts -> AsyncState
    useCountdown.ts       live countdown ticker
    useBuyerKey.ts        session buyer-key + restore
  components/
    ui/                   Button, Card, Pill, Mono, HashBadge, SolAmount, Countdown,
                          Field, Input, Textarea, FileDrop, Modal, Toast, Tabs,
                          Skeleton, EmptyState, ErrorState, AsyncView, StatBadge
    layout/               AppShell, NavBar, ClusterBadge, WalletButton, Footer
    bounty/               BountyCard, StatusPill, SubmissionTimeline, ManifestView
  pages/                  Board, BountyDetail, Leaderboard, PostBounty, Manage,
                          SubmitConsole, NotFound
  idl/                    sealed_code_bounty.{json,ts}  (v2, regenerated)
```

**Async convention:** every data view uses `AsyncState<T> = {kind:'loading'} |
{kind:'empty'} | {kind:'error', message, retry} | {kind:'success', data}` rendered
through `<AsyncView>` with skeleton / friendly empty / specific-error-and-retry /
success. Services being down is a first-class state, never a spinner-forever.

## 6. Milestones (each independently demoable)

- **M1 — Foundation & shell.** env, polyfills, hash router, wallet provider
  (localnet default), AppShell + nav + cluster badge + wallet button, theme tokens,
  UI primitives, AsyncState + AsyncView, pda/format/async/anchorClient read layer,
  delete stale v1 forms. *Accept:* `npm run dev` boots; nav renders; wallet connects;
  cluster badge green=localnet; a data route shows graceful error+retry with RPC off.
- **M2 — Board + BountyDetail.** useBounties/useBounty, BountyCard, filters, detail
  page (humanized fields, timeline, raw JSON toggle, hunter CTA). *Accept:* RPC off →
  error+retry; zero bounties → empty; decoded cards render with countdown + status pill.
- **M3 — Leaderboard.** useReceipts, aggregate+rank by solver, first-blood badges.
  *Accept:* 4 states; ranking correct from decoded Receipts.
- **M4 — Buyer flows.** PostBounty wizard (keygen → mandatory backup gate →
  manifest v2 → seal_bounty → create_bounty tx) + Manage (own bounties, cancel
  expired, unlock countdown, Reveal fetch + client decrypt, restore-backup path,
  URL-fallback sha256 verify). *Accept:* backup gate blocks progress; seal endpoint
  down → clear error, no tx sent; decrypt works from session or restored key.
- **M5 — Hunter submit console.** drop exploit → sha256 → seal → intent sign →
  upload → submit_exploit tx → poll status → PASS/FAIL screens. *Accept:* full
  seal+sign+upload+tx path; runner down → specific error; poll degrades gracefully.
- **M6 — Integrate, harden, report.** kill-services degradation sweep,
  restore-from-backup, zero stale v1 refs, gates green, `docs/frontend-report.md`,
  final push.

## 7. Definition of done (acceptance bar)

A stranger with Phantom on localhost posts a bounty, watches it broken, decrypts the
exploit, and understands the product without asking a question; every component is
obvious, typed, replaceable; nothing spins forever, lies, or dies silently. Gates:
`npm run build` (zero TS errors), `npm run lint`, dev server HTTP 200 with all side
services OFF.

## 8. M7 — local test rig (post-mission)

The acceptance bar above describes a stranger with Phantom on localhost — but nothing in
M1–M6 made that localhost exist. `frontend/devrig/` does: a WSL script for the chain half
(validator + `anchor build` + `anchor deploy`) and a Node CLI on Windows for the rest
(seeding, a mock enclave on `:8443`, and a relayer that lands real attested verdicts).
Walkthrough and caveats: `docs/frontend-testing.md`.

Shipped alongside it, a real defect the rig exposed: enclave calls needed a Vite dev proxy,
because the runner answers no CORS preflight. See `docs/frontend-report.md` gap 6.

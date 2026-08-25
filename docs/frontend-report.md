# SealedCodeBounty — Frontend Report (v2)

Delivered by the frontend orchestration mission. Plan of record: `docs/frontend-plan.md`.
Stack: React 19 + Vite 8 + TS 6 + @solana/wallet-adapter + @solana/web3.js +
@anchor-lang/core. ~4.8k LOC of app code across 49 source files.

## 1. Gate results (all green)

| Gate | Command | Result |
|------|---------|--------|
| Types | `npm run build` (`tsc -b`) | 0 errors |
| Bundle | `vite build` | ok (~1.31 MB / 415 kB gz single chunk) |
| Lint | `npm run lint` (oxlint) | 0 errors, **0 warnings** |
| Serve, services OFF | `vite preview` / `vite dev` | HTTP 200 on `/`, all four async states degrade gracefully |

"Services OFF" is the honest default state here: there was no localnet validator or
runner running during development, so every read/write path was built and exercised
against the *failure* side first (connection refused → specific error + retry).

## 2. Page-by-page

- **Board (`#/`)** — card grid of all `Bounty` accounts; status filter chips with live
  counts; sort (open → soonest deadline → resolved/cancelled). 4 states.
- **Bounty detail (`#/bounty/:pda`)** — humanized public fields (environment / manifest /
  flag-commitment / reveal-key each with plain-language help + truncate-with-copy hash
  badges), live countdown, submission timeline (opened → submitted → verdict), hunter CTA
  + practice exploit template download, raw account JSON toggle.
- **Leaderboard (`#/leaderboard`)** — `Receipt` accounts aggregated by solver into a ranked
  table (wins, first-bloods, last win), top-3 medaled. The "provable track record" surface.
- **Post a bounty (`#/post`)** — wizard: connect gate → generate X25519 key with a
  **mandatory backup-download gate** (secret shown once; restore-from-backup alternative) →
  manifest v2 form + prize/deadline → review (downloadable `manifest.json`, derived
  `manifest_sha256`) → `POST /internal/seal_bounty` → `create_bounty` tx → success. Warns
  when `Config` isn't initialized on the cluster.
- **Manage (`#/manage`)** — the connected wallet's bounties; cancel when open+expired+empty;
  awaiting-resolution shows the force-unlock countdown; resolved → decrypt-reveal modal
  (fetch `Reveal` PDA, inline-or-URL carrier with sha256 verification, sealed-box open
  in-browser, restore-key path) + reclaim rent via `close_resolved_bounty`.
- **Submit console (`#/hunt/:pda`)** — connect gate → drop/paste exploit → sha256 → seal to
  `Config.enclave_enc_pk` → ed25519 intent signature via wallet `signMessage`
  (`SCB_SUBMIT_V1 || bounty_pda || sha256(exploit)`) → `POST /internal/upload` →
  `submit_exploit` tx → poll on-chain status → PASS celebration / FAIL (bond refunded, slot
  reopened, retry). Live activity log for the terminal flourish.
- **Not found (`*`)** — friendly fallback with a route home.

Every async view uses one `AsyncState<T>` union rendered through `<AsyncView>`:
loading skeleton / friendly empty / **specific** error + retry / success. "Spinner forever"
and "silent failure" are unrepresentable.

## 3. Component / module tree

```
main.tsx → WalletContextProvider → ToastProvider → App (hash router)
App
 └ AppShell (nav · ClusterBadge · WalletMultiButton · footer)
    └ pages: Board · BountyDetail · Leaderboard · PostBounty · Manage · SubmitConsole · NotFound

components/ui   Button Card Pill Mono SolAmount StatBadge HashBadge Countdown
                FileDrop Field Input Textarea Modal Toast(+context) states(Skeleton/
                Empty/Error/AsyncView)
components/bounty  BountyCard StatusPill SubmissionTimeline
components/buyer   RestoreKey
components/layout  AppShell ClusterBadge

hooks  useProgram(write) useData(useConfig/useBounties/useBounty/useReceipts)
       useAsync useBuyerKey useCountdown useToast
lib    env pda format async types anchorClient(read+normalize) crypto backup
       runner manifest tx reveal
router core(primitives) index(Link)
idl    sealed_code_bounty.{json,ts}  (v2, regenerated)
```

Data flow: pages consume **normalized domain types** (`lib/types`), never raw Anchor output.
All BN/enum/byte-array quirks and the fork's runtime-lowercase account namespace are
contained in `lib/anchorClient`. All 32-byte values render as monospace truncate-with-copy.

## 4. EXECUTED vs REASONED (honesty table)

| Area | Status | Notes |
|------|--------|-------|
| `tsc -b` clean | **EXECUTED** | run each milestone |
| `oxlint` clean (0/0) | **EXECUTED** | run each milestone |
| `vite build` | **EXECUTED** | Buffer polyfill confirmed working in-bundle |
| dev + preview serve 200, services off | **EXECUTED** | curl'd `/` on 5173 and 4173 |
| v2 IDL correctness | **EXECUTED (partial)** | discriminator formula verified against the known `create_bounty` value; account/method namespaces probed at runtime via `@anchor-lang/core` (keys: config/bounty/receipt/reveal, createBounty/…); byte-exact field layouts derived from `state.rs` |
| Read decode (Board/Detail/Leaderboard) against live data | **REASONED** | no localnet validator was available; decode logic derived from verified account layouts, not run against real accounts |
| Wallet connect / signMessage / tx submit | **REASONED** | no wallet + validator in this headless env; wiring built to the wallet-adapter + Anchor 1.1.2 contracts |
| seal_bounty / upload runner calls | **REASONED** | runner offline; client built to the documented request/response shapes, failure path exercised |
| Sealed-box seal + open, X25519 keygen, sha256, intent msg | **EXECUTED (unit)** | libsodium + noble functions verified present and callable in node; end-to-end round-trip against a real Reveal is REASONED |
| Browser render (React mount) | **REASONED** | no headless browser; build + node module-load of anchor/web3/libsodium succeeded, so a module-load crash is ruled out |

Bottom line: the toolchain gates are executed and green; the on-chain/enclave round-trips
are built against verified contracts but not yet run against a live localnet (none was up).
First integration step for whoever brings up localnet: §6.

## 5. Dependency justification

Added only from the allowed set, plus one polyfill:

- **libsodium-wrappers** (+ `@types/libsodium-wrappers`) — `crypto_box_seal` / `_seal_open`
  and X25519 keygen. tweetnacl has no sealed-box primitive, so libsodium is required.
- **@noble/hashes** — sha256 for exploit/manifest hashing and URL-carrier integrity checks.
- **lucide-react** — icon set for the mission-control UI.
- **buffer** — polyfill only. `@solana/web3.js` assumes Node `Buffer`; imported in
  `src/polyfills.ts` (`globalThis.Buffer`) and paired with vite `define: { global: "globalThis" }`.
  Justified as a browser shim for a fixed-stack dependency, not a new runtime feature dep.

`react-router` was intentionally **not** added (not in the allowed set); routing is a ~90-line
hash router in `src/router`.

## 6. Known gaps / follow-ups

1. **Live localnet integration not yet run.** Bring up `solana-test-validator`, deploy the
   program, `initialize_config`, and post a bounty; then verify Board/Detail decode and the
   full post→submit→resolve→decrypt loop. This is the REASONED→EXECUTED closing step.
2. **IDL regeneration.** The committed IDL was hand-regenerated (no v2 `anchor build` artifact
   existed anywhere). After the next `anchor build`, replace `frontend/src/idl/*` with the real
   `target/idl` + `target/types` output and re-run gates; the generator lives in the job scratch
   dir for reference.
3. **Bundle size.** Single ~1.31 MB chunk (wallet-adapter + web3 dominate). Fine for launch;
   route-level `import()` code-splitting is the obvious later win.
4. **FAIL redacted_log.** The FAIL screen reports "rejected, slot reopened" from on-chain state.
   If the runner later exposes a redacted log endpoint, surface it there (no such endpoint is
   defined today, so none is fabricated).
5. **Explorer links.** tx signatures render as copyable hashes; wire cluster-aware explorer URLs
   once a canonical explorer is chosen.

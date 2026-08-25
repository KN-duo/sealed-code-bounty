# PRE-TEE PLAN — what must be done before wrapping the pipeline in an enclave

> Owner split: **LEFT CHAT = writes code** · **RIGHT CHAT (Ox Alpha) = reviews, runs gates, owns this plan**
> Rule: nothing enters the TEE until every step here passes on a plain laptop/CI.
> Status markers: `[ ]` todo · `[~]` in progress · `[x]` done

## Step 1 — Real sandbox execution (no mocks)
- [~] TASK 9 (left, in flight): DockerCli executor — target container on loopback-only net, exploit container joined, setarch ASLR parity, hard timeouts, zero leaks. References: kernelctf/server.py, kctf nsjail patterns.
- [ ] Real-Docker proof run. No docker on dev host ⇒ **GitHub Actions workflow** (ubuntu-latest has Docker): build runner, pack `examples/echo-service`, drive verify pipeline against a real solved+unsolved exploit pair. Gate: PASS for real exploit, FAIL for wrong one.
- [ ] Same proof run for each new challenge below.

## Step 2 — Challenge corpus (proves the pipeline generalizes)
- [x] `examples/echo-service` — trivial TCP flag-echo (packager smoke).
- [ ] `examples/ret2win` — classic stack-overflow → win fn (static, no PIE, no canary). Exploit: offset + address. Tests binary-kind target path.
- [ ] `examples/auth-check` — password comparison against /flag-derived value. Tests conditional logic inside target.
- [ ] Each challenge ships with `solve.py` (pwntools) = ground truth for PASS, plus `solve-broken.py` for FAIL-path demos.

## Step 3 — Blob storage for real
- [ ] Konstantine: create R2 bucket + API token (human, 10 min).
- [ ] Left: implement `uploadTarball()` (presigned PUT), runner https fetch + sha check (replace typed-unsupported).
- [ ] Round-trip test: pack → upload → verify pulls from bucket.

## Step 4 — Client submission tooling
- [ ] `scb-submit` command (cli/ or new bin): full hunter handshake — read Config (enclave pk), seal exploit, sign intent, POST /internal/upload, submit_exploit tx, poll verdict.
- [ ] Used by all E2E tests so tests exercise the real client path, not internal shortcuts.

## Step 5 — Localnet dress rehearsal (the gate to TEE)
- [ ] One script `e2e/localnet.sh`: start validator → init config w/ test operator keys → pack ret2win → upload → submit (scb-submit) → relayer verifies via DockerCli (in CI) → escrow pays → Receipt+Reveal exist → buyer decrypts reveal and it matches solve.py output.
- [ ] Negative rehearsal: broken exploit FAILs, log redacted, bond refunded, resubmit works.
- [ ] Force-unlock rehearsed: kill relayer mid-flight, sweeper unlocks, bond returns.
- GATE: only after this script is green twice in a row do we touch nitro-cli.

## Step 6 — AWS groundwork (parallel, human + left)
- [ ] Konstantine: AWS account, budget alarm ($20), S3/R2 parity decision.
- [ ] Left: `runner/runtime.Dockerfile` + EIF build recipe + `BUILD.md` reproducibility doc; KMS key + attestation-policy Terraform/console steps written down (execution needs Konstantine's console).

## Standing rules
- Every task: left codes → right re-runs ALL gates independently (anchor/clippy/cargo/npm + cross-lang fixture) → merge → push.
- Code style bar: pure-fn splits, named constants, no magic numbers, honest REAL-vs-REASONED notes, tests runnable solo (`ts-mocha -g`) and in bulk.

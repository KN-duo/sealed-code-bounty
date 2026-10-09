# scb-relayer

Pre-production status (2026-10-09): local tests pass (12), including verdict
wire verification and retry/recovery paths, but no hosted relayer or devnet/
mainnet deployment exists. The service requires a private fee-payer key and a
real verifier endpoint; do not expose it with the sample local settings below.
Current deployment gates are in [`../DEPLOYMENT-HANDOFF.md`](../DEPLOYMENT-HANDOFF.md).

Permissionless relayer (`docs/BUILD_PLAN_v2.md` §4.6): watches
`ExploitSubmitted` events, drives the verifier enclave's `/internal/verify`,
and lands the atomic `[Ed25519SigVerify, resolve_with_attestation]`
transaction. Only enclave-signed verdicts are ever submitted — the relayer
cannot fabricate outcomes.

## Run

```bash
npm install && npm run build

PROGRAM_ID=FbqouGmrsFmoC24H3x1vX3LX9jVXhUN5zDH7RnSXba9V \
FEE_PAYER_KEYPAIR_PATH=./keypair.json \
OPERATOR_PUBKEY=<pinned-enclave-ed25519-key> \
[RPC_URL=http://127.0.0.1:8899] [ENCLAVE_URL=http://127.0.0.1:8443] \
[POLL_INTERVAL_MS=10000] [IDL_PATH=target/idl/sealed_code_bounty.json] \
npm start
```

`OPERATOR_PUBKEY` is the enclave signing key pinned in `Config.operators`;
every verdict is re-verified locally against it before fees are spent.

## Behavior notes

- Jobs dedupe by Bounty PDA; one submission slot = one job.
- Pending jobs are reconstructed from on-chain state at startup and periodic
  scans; retry/backoff bookkeeping is in memory and resets when the process
  restarts.
- Enclave transport retries 5x with exponential backoff; on exhaustion the
  job is left for `force_unlock_submission`. A local FAIL is never invented.
- Verdict bytes are reconstructed from CHAIN state and the signature checked
  with tweetnacl before send (defense in depth on top of on-chain checks).
- `test/mock-enclave.cjs` signs canned verdicts for offline testing:
  `PORT=8443 node test/mock-enclave.cjs`
- Tests (verdict wire, sig helper, tx composition, mock smoke, tamper
  rejection): `npm test`

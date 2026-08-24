# scb-relayer

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
- Enclave transport retries 5x with exponential backoff; on exhaustion the
  job is left for `force_unlock_submission`. A local FAIL is never invented.
- Verdict bytes are reconstructed from CHAIN state and the signature checked
  with tweetnacl before send (defense in depth on top of on-chain checks).
- `test/mock-enclave.cjs` signs canned verdicts for offline testing:
  `PORT=8443 node test/mock-enclave.cjs`
- Tests (verdict wire, sig helper, tx composition, mock smoke, tamper
  rejection): `npm test`

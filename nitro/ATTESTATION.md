# Independent Nitro attestation verification

The runner exposes `POST /internal/attestation`. This endpoint requests a real
document from the Nitro Security Module; running a Docker image or building an
EIF does not provide such a document. The verifier here is an operator tool.
Browser integration, live Nitro execution, KMS policy denial checks, and the
controlled on-chain key registration procedure still require separate evidence.

## Version 1 application binding

Request JSON, with an independently generated cryptographically random nonce:

```json
{"nonce_b64":"<canonical standard base64 of 16..64 bytes>"}
```

Successful response JSON has exactly these fields:

```json
{
  "document_b64": "<raw AWS COSE_Sign1 document in canonical standard base64>",
  "nonce_b64": "<request nonce>",
  "enclave_enc_pubkey_hex": "<32 bytes as 64 lowercase hex characters>",
  "verdict_pubkey_hex": "<32 bytes as 64 lowercase hex characters>",
  "build_commit": "<40 lowercase Git commit hex characters>",
  "protocol": "SCB_VERDICT_V5",
  "attestation_version": 1
}
```

The NSM `public_key` field contains the **raw 32-byte encryption key**. It is
opaque application data in this protocol, rather than an X.509 public-key
encoding. The NSM `nonce` field contains the decoded request nonce. The NSM
`user_data` field is the exact concatenation below, without lengths, JSON,
base64, a trailing newline, or an extra terminator:

```text
ASCII("SCB_ATTESTATION_V1") || 0x00 || verdict_pubkey_raw_32 ||
ASCII(build_commit) || 0x00 || ASCII("SCB_VERDICT_V5")
```

The fixed 32-byte verdict key and two NUL delimiters make this binding
unambiguous. Release builds bind a clean Git commit. Development builds may bind
`development` or `<40 lowercase hex>-dirty`; they require the verifier's
explicit development option and do not authorize a production deployment.
The build commit is compiled into the runner. Unsigned response fields must
agree with the signed data and the operator's expected values.

## Run the independent client

Use Python 3.10 or newer and system OpenSSL 3 at `/usr/bin/openssl`:

```sh
python3 -m venv /tmp/scb-attestation-venv
/tmp/scb-attestation-venv/bin/pip install -r nitro/attestation-requirements.txt
/tmp/scb-attestation-venv/bin/python nitro/verify_attestation.py \
  --url https://api.example.com/internal/attestation \
  --pcr0 '<reviewed-release-PCR0-96-hex>' \
  --encryption-key '<controlled-Config-encryption-key-64-hex>' \
  --verdict-key '<controlled-Config-verdict-key-64-hex>' \
  --build-commit '<reviewed-clean-Git-commit-40-hex>'
```

The PCR0 and commit must come from the reviewed release. For an already
registered enclave, expected application keys must come from the controlled
Solana Config records. Replacing those expected keys with remote response values
would defeat detection of a change to the registered keys.

On the first boot, before Config contains those keys, the operator may read
**candidate** encryption and verdict public keys from the raw endpoint response
and supply them explicitly to the verifier. Those candidates remain untrusted
until a new challenge passes the fixed AWS root, certificate path, signature,
nonce, freshness, independently reviewed PCR0/commit, and signed key-binding
checks. The operator then records and pins exactly those verified keys in Config
through the controlled authority procedure, before funding bounties. Subsequent
checks use Config's pinned keys. This tool does not automatically register keys
or discover an acceptable PCR or source commit from the remote server.

For a private staging instance reached through an SSH tunnel, use an explicit
literal loopback URL, such as
`--url http://127.0.0.1:8443/internal/attestation --allow-loopback-http`.
This transport exception preserves all attestation checks. HTTP to other hosts,
redirects, endpoint credentials, URL query strings, and URL fragments are rejected.
The tool generates a new 32-byte nonce for each invocation; there is no reusable
nonce flag or offline success mode.

An exit code of zero and a JSON report with `verified: true` mean the returned
document passed the checks described below. This report is evidence of that
challenge response, rather than evidence that KMS denial checks, exploit
isolation, settlement, or an entire release have passed. A report from a
development build additionally has `development_build: true`.

## Trust anchor and validation

The official [AWS attestation specification](https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md)
links the [AWS Nitro Enclaves root archive](https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip).
The archive was retrieved from that URL and its SHA-256 matched the value
published in the specification:

```text
archive SHA256: 8cf60e2b2efca96c6a9e71e851d00c1b6991cc09eadbe64a6a1d1b1eb9faff7c
root DER SHA256: 641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b
```

These are different hashes: the published `8cf60...` value hashes the ZIP,
not the DER certificate. The archive's `root.pem` is preserved in
`aws_nitro_root_g1.pem`; the verifier checks its DER fingerprint against the
fixed `641a...` value before use. There is no caller-supplied trust-root option.
Certificates supplied inside an attestation document are untrusted chain
material. OpenSSL default CA files, paths, and stores are disabled.

The verifier checks:

- bounded HTTP and document sizes; duplicate-free JSON and CBOR; bounded CBOR
  depth; no indefinite-length containers or trailing encoded objects;
- COSE_Sign1 with optional tag 18, an exclusively protected ES384 algorithm,
  empty unprotected headers, and a 96-byte raw ECDSA signature;
- exact required document fields, SHA384 PCR lengths/indexes, and a reviewed
  nonzero PCR0; zero and all-`ff` placeholder PCR0 inputs are rejected;
- the fixed AWS root, certificate validity periods, CA/signing key usage,
  P-384 leaf key, strict OpenSSL RFC 5280 path and critical-extension checks,
  root self signature, and ES384 signature over the original payload bytes;
- a document age no greater than five minutes, future clock skew no greater
  than thirty seconds, and the freshly generated nonce;
- the operator's expected encryption key, verdict key, source commit, and
  `SCB_VERDICT_V5` protocol in the signed binding.

Certificate revocation checks are not enabled, following the AWS attestation
specification. Certificate and document validity depend on a trustworthy local
clock. Dependencies are pinned in `attestation-requirements.txt`; the strict
CBOR options require the declared cbor2 version. Primary dependency behavior
is documented in the [cbor2 API](https://cbor2.readthedocs.io/en/stable/api.html)
and [cryptography documentation](https://cryptography.io/en/latest/).

This implementation has received static inspection and Python compilation.
It has not yet verified a real AWS document or undergone adversarial fixture
tests or independent security review. Those checks remain release gates.

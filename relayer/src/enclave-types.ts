/**
 * Wire types for the verifier enclave's /internal/verify endpoint
 * (docs/BUILD_PLAN_v2.md §4.3). The relayer's view is a CLAIM of chain state:
 * the enclave cross-checks it against its own fetched values and aborts on
 * divergence rather than guessing which side is right.
 */

export interface ChainView {
  /** hex-encoded 32-byte SHA-256 of the environment tarball. */
  env_blob_sha256: string;
  /** hex-encoded buyer X25519 public key registered at create_bounty. */
  buyer_enc_pk: string;
  /** hex-encoded sha256(flag) commitment pinned at create_bounty. */
  flag_commitment: string;
  /** hex-encoded SHA-256 of the pending submission's sealed exploit. */
  exploit_sha256: string;
}

export interface VerifyRequest {
  /** base58 Bounty PDA the verdict must bind. */
  bounty_pda: string;
  claimed_chain_view: ChainView;
  /** base58 solver pubkey claimed for this submission. */
  solver_pubkey: string;
}

export interface VerifyResponse {
  outcome: boolean;
  /** base64 ed25519 signature over the canonical verdict wire (see test-vectors/verdict_v4.json). */
  sig: string;
  /** base64 sealed-box ciphertext (PASS only; empty/absent on FAIL). */
  reveal_ciphertext?: string;
  /** fallback transport for payloads too big to inline (PASS only). */
  reveal_ciphertext_url?: string;
  /** hex sha256 matching reveal payload when transported by URL (PASS only). */
  reveal_ciphertext_sha256?: string;
  /** hunter-facing failure log with flag material redacted. */
  redacted_log: string;
}

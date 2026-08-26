import { ENCLAVE_DISPLAY_URL, ENCLAVE_URL } from "../env";

// Typed client for the runner / enclave HTTP surface. Every call fails LOUDLY
// with a specific message so the UI can render a real error state, never a
// silent no-op or an endless spinner.

export class RunnerError extends Error {
  readonly status?: number;
  constructor(message: string, status?: number) {
    super(message);
    this.name = "RunnerError";
    this.status = status;
  }
}

async function post<T>(path: string, body: unknown): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${ENCLAVE_URL}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
  } catch {
    throw new RunnerError(
      `Could not reach the verifier at ${ENCLAVE_DISPLAY_URL}. Is the runner service running?`,
    );
  }
  if (!res.ok) {
    let detail = "";
    try {
      detail = await res.text();
    } catch {
      /* body not readable */
    }
    throw new RunnerError(
      `Verifier returned ${res.status}${detail ? `: ${detail.slice(0, 300)}` : ""}.`,
      res.status,
    );
  }
  try {
    return (await res.json()) as T;
  } catch {
    throw new RunnerError("Verifier returned a malformed response.");
  }
}

// Buyer step: enclave seals the bounty environment and returns the flag commitment
// that must be pinned on-chain at create_bounty time.
export interface SealBountyResponse {
  flag_commitment: string; // hex
}
export function sealBounty(bountyPda: string): Promise<SealBountyResponse> {
  return post<SealBountyResponse>("/internal/seal_bounty", { bounty_pda: bountyPda });
}

// Hunter step: upload the sealed exploit + intent proof; enclave returns the
// blob url the submit_exploit transaction records on-chain.
export interface ClaimedChainView {
  env_blob_sha256: string;
  buyer_enc_pk: string;
  exploit_sha256: string;
  flag_commitment: string;
}
export interface UploadRequest {
  bounty_pda: string;
  claimed_chain_view: ClaimedChainView;
  solver_pubkey: string;
  submit_intent_sig: string; // base64
  exploit_sealed_box: string; // base64
}
export interface UploadResponse {
  blob_url: string;
}
export function uploadExploit(req: UploadRequest): Promise<UploadResponse> {
  return post<UploadResponse>("/internal/upload", req);
}

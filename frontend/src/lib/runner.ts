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
// The company's target + hunter-facing challenge details, all optional. When a
// target source is supplied the enclave builds it and judges against it; when a
// title/description is supplied hunters see it on the bounty page.
export interface BountyTarget {
  source_zip_b64?: string; // zip of Dockerfile + files
  source_git?: string; // OR a public GitHub repo: owner/name[#subdir]
  port?: number; // the vulnerable service's TCP port
  title?: string;
  description?: string;
}
export function sealBounty(bountyPda: string, target?: BountyTarget): Promise<SealBountyResponse> {
  const body: { bounty_pda: string; target?: BountyTarget } = { bounty_pda: bountyPda };
  if (target && Object.keys(target).length > 0) body.target = target;
  return post<SealBountyResponse>("/internal/seal_bounty", body);
}

// Hunter-facing challenge details (what to hack, how to connect).
export interface Challenge {
  title: string;
  description: string;
  port: number;
}
// Per-bounty practice environment: ask the workspace service to spin up the
// bounty's target next to a browser terminal, and return the terminal URL.
export interface Workspace {
  id: string;
  url: string;
  expiresInS: number;
  targetImage?: string;
}
export async function startWorkspace(bountyPda: string): Promise<Workspace> {
  let res: Response;
  try {
    res = await fetch("/workspace-api/workspace", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ bounty_pda: bountyPda }),
    });
  } catch {
    throw new RunnerError("Could not reach the workspace service. Is it running (serve-local.sh)?");
  }
  if (!res.ok) {
    let detail = "";
    try {
      detail = (await res.json()).error ?? "";
    } catch {
      /* ignore */
    }
    throw new RunnerError(`Workspace service returned ${res.status}${detail ? `: ${detail}` : ""}.`);
  }
  return (await res.json()) as Workspace;
}

export async function getChallenge(bountyPda: string): Promise<Challenge | null> {
  try {
    const res = await fetch(`${ENCLAVE_URL}/internal/challenge/${encodeURIComponent(bountyPda)}`);
    if (res.status === 404) return null;
    if (!res.ok) return null;
    return (await res.json()) as Challenge;
  } catch {
    return null;
  }
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
// The enclave stores the sealed exploit and returns a receipt. The on-chain
// blob_url is a separate synthetic reference the caller builds (the enclave
// locates the upload by bounty + exploit hash, not by this url).
export interface UploadResponse {
  receipt: string;
}
export async function uploadExploit(req: UploadRequest): Promise<UploadResponse> {
  const res = await post<{ receipt?: string; blob_url?: string }>("/internal/upload", req);
  const receipt = res.receipt ?? res.blob_url;
  if (typeof receipt !== "string" || receipt.length === 0) {
    throw new RunnerError(
      `The verifier accepted the upload but returned no receipt (got ${JSON.stringify(res).slice(0, 200)}).`,
    );
  }
  return { receipt };
}

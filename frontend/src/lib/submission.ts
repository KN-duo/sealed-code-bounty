// The receipt identifies the stored encrypted upload record. It is opaque to
// clients and is independent of the plaintext exploit hash signed by the wallet.
export interface UploadResponse {
  receipt: string;
}

export function submissionReference(receipt: string): string {
  if (typeof receipt !== "string" || receipt.length !== 64 || !/^[0-9a-f]{64}$/.test(receipt)) {
    throw new Error("Verifier returned an invalid upload receipt.");
  }
  return `scb:submission:v1:${receipt}`;
}

export function parseUploadResponse(value: unknown): UploadResponse {
  if (
    typeof value !== "object" || value === null || Array.isArray(value) ||
    Object.keys(value).length !== 1 || !("receipt" in value) ||
    typeof value.receipt !== "string"
  ) {
    throw new Error("Verifier returned an invalid upload receipt.");
  }
  submissionReference(value.receipt);
  return { receipt: value.receipt };
}

/**
 * S3-compatible (R2) blob upload via aws4fetch SigV4.
 *
 * Reads SCB_R2_* env vars. When any of the four required vars are missing,
 * callers fall back to local-path mode (manifest references ./tarball).
 */

import { AwsClient } from "aws4fetch";
import { createHash } from "crypto";
import { readFile } from "fs/promises";
import { PackError } from "./errors";

export interface R2Credentials {
  endpoint: string;
  bucket: string;
  accessKeyId: string;
  secretAccessKey: string;
  region?: string;
}

/** Returns credentials when all four required SCB_R2_* vars are set. */
export function loadR2Credentials(): R2Credentials | null {
  const endpoint = process.env.SCB_R2_ENDPOINT;
  const bucket = process.env.SCB_R2_BUCKET;
  const accessKeyId = process.env.SCB_R2_ACCESS_KEY_ID;
  const secretAccessKey = process.env.SCB_R2_SECRET_KEY;

  if (!endpoint || !bucket || !accessKeyId || !secretAccessKey) return null;

  return {
    endpoint: endpoint.replace(/\/+$/, ""),
    bucket,
    accessKeyId,
    secretAccessKey,
    region: process.env.SCB_R2_REGION ?? "auto",
  };
}

export interface UploadResult {
  /** Remote URL of the uploaded object (or null in local-fallback mode). */
  remoteUrl: string;
  sha256Hex: string;
}

/**
 * Streams a tarball to S3-compatible storage via aws4fetch.
 * Computes sha256 during read for both the object key and manifest pinning.
 *
 * EXECUTED: signing + HTTP PUT round-trip tested against a local S3-lookalike
 * server (upload.test.ts). Live R2 round-trip is REASONED (needs credentials).
 */
export async function s3PutFile(
  creds: R2Credentials,
  key: string,
  filePath: string
): Promise<UploadResult> {
  const body = await readFile(filePath);
  const sha256Hex = createHash("sha256").update(body).digest("hex");

  const client = new AwsClient({
    accessKeyId: creds.accessKeyId,
    secretAccessKey: creds.secretAccessKey,
    service: "s3",
    region: creds.region ?? "auto",
  });

  const url = `${creds.endpoint}/${creds.bucket}/${key}`;
  const req = new Request(url, {
    method: "PUT",
    body: new Uint8Array(body),
    headers: { "content-type": "application/gzip" },
  });
  const signed = await client.sign(req); // SigV4; adds Authorization + x-amz-*

  const res = await fetch(signed);
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new PackError(
      5,
      `upload failed HTTP ${res.status}: ${text.slice(0, 300)}`
    );
  }

  return { remoteUrl: url, sha256Hex };
}

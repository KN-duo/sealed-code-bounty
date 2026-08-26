export const FLAG_PLACEHOLDER = "{{FLAG}}";
export const MANIFEST_FORMAT_VERSION = 2;

export interface ImageTarballRef {
  /** Remote URL after upload, or local "<sha256>.tar.gz" relative path pre-upload. */
  url: string;
  sha256: string;
}

export type TargetSpec =
  | { kind: "tcp_service"; host: string; port: number }
  | { kind: "binary"; exec: string; io: "stdio"; argv: string[] };

export interface Manifest {
  format_version: 2;
  name: string;
  image_tarball: ImageTarballRef;
  target: TargetSpec;
  limits: { timeout_seconds: number; memory_mb: number; cpus: number };
  determinism: { aslr: "off" | "on"; seed: number };
  flag_placeholder: string;
  entrypoint: string;
}

/**
 * Uploads a tarball to S3-compatible (R2) storage when credentials are
 * available, otherwise returns a local relative path.
 */
export async function uploadTarball(
  uploadUrl: string,
  tarballPath: string,
  sha256: string
): Promise<string> {
  const { loadR2Credentials, s3PutFile } = await import("./upload");
  const creds = loadR2Credentials();
  if (!creds) return `./${tarballPath.split("/").pop()}`;

  const key = `scb/envs/${sha256}.tar.gz`;
  const { remoteUrl } = await s3PutFile(creds, key, tarballPath);
  console.error(`[upload] ${tarballPath} -> ${remoteUrl}`);
  void uploadUrl;
  return remoteUrl;
}

import { PackError } from "./errors";
import { writeFile } from "fs/promises";

export async function emitManifest(outPath: string, m: Manifest): Promise<void> {
  await writeFile(outPath, JSON.stringify(m, null, 2) + "\n");
}

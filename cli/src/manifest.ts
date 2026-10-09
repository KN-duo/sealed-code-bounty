export { FLAG_PLACEHOLDER, MANIFEST_FORMAT_VERSION, manifestCanonicalJson, validateManifest } from "../../shared/manifest.mjs";
export type { Manifest, ImageTarballRef, TargetSpec } from "../../shared/manifest.mjs";
import { manifestCanonicalJson } from "../../shared/manifest.mjs";
import type { Manifest } from "../../shared/manifest.mjs";

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

import { writeFile } from "fs/promises";

export async function emitManifest(outPath: string, m: Manifest): Promise<void> {
  await writeFile(outPath, manifestCanonicalJson(m));
}

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
 * Upload hook reserved for phase-2 storage integration (R2 presigned PUT /
 * Arweave). Deliberately a stub: BUILD_PLAN_v2.md §4.2 keeps upload OUT of the
 * packager until credentials handling is designed.
 */
export async function uploadTarball(
  _uploadUrl: string,
  _tarballPath: string,
  _sha256: string
): Promise<string> {
  throw new PackError(
    5,
    "uploadTarball() is not implemented yet (phase-2 storage integration). " +
      "Re-run without --upload-url; the manifest will reference the tarball by its local relative path."
  );
}

import { PackError } from "./errors";
import { writeFile } from "fs/promises";

export async function emitManifest(outPath: string, m: Manifest): Promise<void> {
  await writeFile(outPath, JSON.stringify(m, null, 2) + "\n");
}

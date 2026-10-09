import { sha256 } from "@noble/hashes/sha2.js";
import { manifestCanonicalJson, validateManifest } from "../../../shared/manifest.mjs";
import type { Manifest } from "../../../shared/manifest.mjs";

export { manifestCanonicalJson } from "../../../shared/manifest.mjs";
export type { Manifest } from "../../../shared/manifest.mjs";
export type TargetKind = "tcp_service" | "binary";

export interface ManifestForm {
  name: string;
  imageUrl: string;
  imageSha256: string;
  kind: TargetKind;
  // JSON array: tokens keep their boundaries; no shell string splitting.
  entrypoint: string;
  port: number;
  memoryMb: number;
  timeoutS: number;
  deterministic: boolean;
  seed: number;
  flagPlaceholder: string;
}

export function buildManifest(form: ManifestForm): Manifest {
  let entrypoint: unknown;
  try {
    entrypoint = JSON.parse(form.entrypoint);
  } catch {
    throw new Error('Entrypoint must be a JSON argument array, for example ["./run.sh"].');
  }
  return validateManifest({
    format_version: 2,
    name: form.name.trim(),
    image_tarball: { url: form.imageUrl.trim(), sha256: form.imageSha256.trim() },
    target: form.kind === "tcp_service"
      ? { kind: "tcp_service", host: "target", port: form.port }
      : { kind: "binary", exec: Array.isArray(entrypoint) ? entrypoint[0] : undefined, io: "stdio", argv: Array.isArray(entrypoint) ? entrypoint.slice(1) : [] },
    limits: { timeout_seconds: form.timeoutS, memory_mb: form.memoryMb, cpus: 1 },
    determinism: { aslr: form.deterministic ? "off" : "on", seed: form.seed },
    flag_placeholder: form.flagPlaceholder,
    entrypoint,
  });
}

export function manifestSha256Hex(m: Manifest): string {
  const bytes = sha256(new TextEncoder().encode(manifestCanonicalJson(m)));
  return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
}

export function validateForm(form: ManifestForm): string[] {
  const errors: string[] = [];
  if (!/^https:\/\/.+/.test(form.imageUrl.trim())) errors.push("Image tarball URL must be an https:// link.");
  try {
    buildManifest(form);
  } catch (error) {
    errors.push(error instanceof Error ? error.message : "Invalid manifest.");
  }
  return errors;
}

export function downloadManifest(m: Manifest): void {
  const blob = new Blob([manifestCanonicalJson(m)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "manifest.json";
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

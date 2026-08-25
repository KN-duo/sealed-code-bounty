import { sha256Bytes } from "./crypto";
import { bytesToHex } from "./format";

// Manifest schema v2 — the spec the enclave uses to build and run the target.
// The env blob (image tarball) is content-addressed by its own sha256; the whole
// manifest is committed on-chain by its sha256.
export type TargetKind = "tcp_service" | "binary";

export interface Manifest {
  schema: "v2";
  image_tarball: { url: string; sha256: string };
  target: { kind: TargetKind; entrypoint: string };
  limits: { memory_mb: number; timeout_s: number };
  determinism: { deterministic: boolean; seed: number };
  flag_placeholder: string;
}

export interface ManifestForm {
  imageUrl: string;
  imageSha256: string;
  kind: TargetKind;
  entrypoint: string;
  memoryMb: number;
  timeoutS: number;
  deterministic: boolean;
  seed: number;
  flagPlaceholder: string;
}

export function buildManifest(form: ManifestForm): Manifest {
  return {
    schema: "v2",
    image_tarball: { url: form.imageUrl.trim(), sha256: form.imageSha256.trim().toLowerCase() },
    target: { kind: form.kind, entrypoint: form.entrypoint.trim() },
    limits: { memory_mb: form.memoryMb, timeout_s: form.timeoutS },
    determinism: { deterministic: form.deterministic, seed: form.seed },
    flag_placeholder: form.flagPlaceholder.trim(),
  };
}

// Deterministic serialization (recursively sorted keys) so the committed
// manifest_sha256 is reproducible regardless of property insertion order.
function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`).join(",")}}`;
}

export function manifestCanonicalJson(m: Manifest): string {
  return stableStringify(m);
}

export function manifestSha256Hex(m: Manifest): string {
  const bytes = new TextEncoder().encode(manifestCanonicalJson(m));
  return bytesToHex(sha256Bytes(bytes));
}

// Basic client-side validation; returns a list of human-readable problems.
export function validateForm(form: ManifestForm): string[] {
  const errs: string[] = [];
  if (!/^https:\/\/.+/.test(form.imageUrl.trim()))
    errs.push("Image tarball URL must be an https:// link.");
  if (!/^[0-9a-fA-F]{64}$/.test(form.imageSha256.trim()))
    errs.push("Image tarball sha256 must be 64 hex characters.");
  if (form.entrypoint.trim().length === 0) errs.push("Entrypoint is required.");
  if (form.flagPlaceholder.trim().length === 0) errs.push("Flag placeholder is required.");
  if (form.memoryMb <= 0) errs.push("Memory limit must be positive.");
  if (form.timeoutS <= 0) errs.push("Timeout must be positive.");
  return errs;
}

export function downloadManifest(m: Manifest): void {
  const blob = new Blob([JSON.stringify(m, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "manifest.json";
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

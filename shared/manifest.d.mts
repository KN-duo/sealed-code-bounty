export const FLAG_PLACEHOLDER: "{{FLAG}}";
export const MANIFEST_FORMAT_VERSION: 2;
export interface ImageTarballRef { url: string; sha256: string }
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
  entrypoint: string[];
}
export function validateManifest(value: unknown): Manifest;
export function manifestCanonicalJson(value: Manifest): string;

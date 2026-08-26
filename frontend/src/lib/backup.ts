import { toBase64, fromBase64, publicKeyFromSecret } from "./crypto";
import { bytesToHex } from "./format";
import type { X25519Keypair } from "./crypto";

// The buyer's X25519 secret key is the ONLY way to decrypt a winning exploit.
// It is never sent anywhere: shown once, backed up to a file by the user, and
// held in sessionStorage (cleared when the tab closes) for the active session.

const SESSION_KEY = "scb.buyerKey.v1";
export const BACKUP_SCHEME = "SCB-BUYER-KEY";
export const BACKUP_VERSION = 1;

export interface BackupFile {
  scheme: string;
  version: number;
  algo: "X25519";
  publicKey: string; // hex
  secretKeyB64: string;
  createdAt: string; // ISO
}

export function buildBackup(kp: X25519Keypair): BackupFile {
  return {
    scheme: BACKUP_SCHEME,
    version: BACKUP_VERSION,
    algo: "X25519",
    publicKey: bytesToHex(kp.publicKey),
    secretKeyB64: toBase64(kp.secretKey),
    createdAt: new Date().toISOString(),
  };
}

export function backupFilename(kp: X25519Keypair): string {
  return `scb-buyer-key-${bytesToHex(kp.publicKey).slice(0, 8)}.json`;
}

// Trigger a browser download of the backup JSON. Returns the filename used.
export function downloadBackup(kp: X25519Keypair): string {
  const file = buildBackup(kp);
  const blob = new Blob([JSON.stringify(file, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const name = backupFilename(kp);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  return name;
}

// Parse + verify a restored backup: the secret key must actually derive the
// stored public key, or we reject it (guards against a truncated/edited file).
export async function parseBackup(json: string): Promise<X25519Keypair> {
  let parsed: Partial<BackupFile>;
  try {
    parsed = JSON.parse(json) as Partial<BackupFile>;
  } catch {
    throw new Error("Not a valid JSON backup file.");
  }
  if (parsed.scheme !== BACKUP_SCHEME) {
    throw new Error("This file is not a SealedCodeBounty buyer-key backup.");
  }
  if (parsed.version !== BACKUP_VERSION) {
    throw new Error(
      `Backup is format version ${parsed.version ?? "unknown"} — this app reads version ${BACKUP_VERSION}. Re-export the key from the browser session that created it.`,
    );
  }
  if (!parsed.secretKeyB64) throw new Error("Backup is missing its secret key.");

  const secretKey = fromBase64(parsed.secretKeyB64);
  if (secretKey.length !== 32) throw new Error("Secret key has the wrong length.");
  const publicKey = await publicKeyFromSecret(secretKey);

  if (parsed.publicKey && bytesToHex(publicKey) !== parsed.publicKey.toLowerCase()) {
    throw new Error("Backup is corrupt: secret key does not match its public key.");
  }
  return { publicKey, secretKey };
}

// --- session persistence --------------------------------------------------

export function saveKeyToSession(kp: X25519Keypair): void {
  try {
    sessionStorage.setItem(
      SESSION_KEY,
      JSON.stringify({ pk: toBase64(kp.publicKey), sk: toBase64(kp.secretKey) }),
    );
  } catch {
    // sessionStorage may be unavailable (private mode); the in-memory key still works.
  }
}

export function loadKeyFromSession(): X25519Keypair | null {
  try {
    const raw = sessionStorage.getItem(SESSION_KEY);
    if (!raw) return null;
    const { pk, sk } = JSON.parse(raw) as { pk: string; sk: string };
    return { publicKey: fromBase64(pk), secretKey: fromBase64(sk) };
  } catch {
    return null;
  }
}

export function clearKeySession(): void {
  try {
    sessionStorage.removeItem(SESSION_KEY);
  } catch {
    // ignore
  }
}

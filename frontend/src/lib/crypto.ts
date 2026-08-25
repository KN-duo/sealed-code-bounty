import _sodium from "libsodium-wrappers";
import { sha256 } from "@noble/hashes/sha2.js";
import { PublicKey } from "@solana/web3.js";

// libsodium loads its wasm asynchronously; every entry point awaits this first.
let ready: Promise<typeof _sodium> | null = null;
export async function sodiumReady(): Promise<typeof _sodium> {
  if (!ready) {
    ready = _sodium.ready.then(() => _sodium);
  }
  return ready;
}

export interface X25519Keypair {
  publicKey: Uint8Array; // 32 bytes
  secretKey: Uint8Array; // 32 bytes
}

// Buyer's decryption keypair (reveals are sealed boxes to publicKey).
export async function generateBuyerKeypair(): Promise<X25519Keypair> {
  const sodium = await sodiumReady();
  const kp = sodium.crypto_box_keypair();
  return { publicKey: kp.publicKey, secretKey: kp.privateKey };
}

// Recover the X25519 public key from a stored secret key (backup restore).
export async function publicKeyFromSecret(secretKey: Uint8Array): Promise<Uint8Array> {
  const sodium = await sodiumReady();
  return sodium.crypto_scalarmult_base(secretKey);
}

// Anonymous sealed box to a recipient X25519 public key (crypto_box_seal).
// Used by hunters to seal exploits to Config.enclave_enc_pk.
export async function sealTo(message: Uint8Array, recipientPk: Uint8Array): Promise<Uint8Array> {
  const sodium = await sodiumReady();
  return sodium.crypto_box_seal(message, recipientPk);
}

// Open a sealed box with the recipient keypair (buyer decrypting a Reveal).
// Returns null on any failure (wrong key, corrupt ciphertext) — never throws.
export async function openSealed(
  ciphertext: Uint8Array,
  kp: X25519Keypair,
): Promise<Uint8Array | null> {
  const sodium = await sodiumReady();
  try {
    return sodium.crypto_box_seal_open(ciphertext, kp.publicKey, kp.secretKey);
  } catch {
    return null;
  }
}

// --- hashing --------------------------------------------------------------

export function sha256Bytes(data: Uint8Array): Uint8Array {
  return sha256(data);
}

// --- intent signature message --------------------------------------------

const SUBMIT_DOMAIN = new TextEncoder().encode("SCB_SUBMIT_V1");

// The message a hunter's wallet signs to prove intent to submit:
//   b"SCB_SUBMIT_V1" || bounty_pda(32) || sha256(exploit_plaintext)
export function buildSubmitIntentMessage(bountyPda: PublicKey, exploit: Uint8Array): Uint8Array {
  const digest = sha256Bytes(exploit);
  const pk = bountyPda.toBytes();
  const out = new Uint8Array(SUBMIT_DOMAIN.length + pk.length + digest.length);
  out.set(SUBMIT_DOMAIN, 0);
  out.set(pk, SUBMIT_DOMAIN.length);
  out.set(digest, SUBMIT_DOMAIN.length + pk.length);
  return out;
}

// --- base64 helpers (payloads to the runner) ------------------------------

export function toBase64(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

export function fromBase64(b64: string): Uint8Array {
  const bin = atob(b64.trim());
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

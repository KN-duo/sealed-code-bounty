import { PublicKey } from "@solana/web3.js";
import { fetchReveal } from "./anchorClient";
import { revealPda } from "./pda";
import { openSealed, sha256Bytes } from "./crypto";
import { bytesToHex } from "./format";
import type { X25519Keypair } from "./crypto";

export interface RevealResult {
  plaintext: Uint8Array;
  carrier: "inline" | "url";
  sourceUrl?: string;
}

// Fetch a Resolved bounty's Reveal, resolve its carrier (inline ciphertext XOR
// https URL, verifying the URL blob's sha256), and open the sealed box with the
// buyer keypair. Throws a specific message at every failure point.
export async function loadReveal(
  bountyPda: string,
  kp: X25519Keypair,
): Promise<RevealResult> {
  let reveal: Awaited<ReturnType<typeof fetchReveal>>;
  try {
    reveal = await fetchReveal(revealPda(new PublicKey(bountyPda)));
  } catch {
    // A dead RPC surfaces here as a raw TypeError otherwise — name the actual cause.
    throw new Error(
      "Could not reach the Solana RPC endpoint to read the Reveal account. Is the validator running, and is VITE_RPC_URL pointing at it?",
    );
  }
  if (!reveal) throw new Error("No reveal has been published for this bounty yet.");

  let ciphertext: Uint8Array;
  let carrier: "inline" | "url";
  let sourceUrl: string | undefined;

  if (reveal.ciphertext.length > 0) {
    ciphertext = reveal.ciphertext;
    carrier = "inline";
  } else if (reveal.ciphertextUrl) {
    carrier = "url";
    sourceUrl = reveal.ciphertextUrl;
    let buf: ArrayBuffer;
    try {
      const res = await fetch(reveal.ciphertextUrl);
      if (!res.ok) throw new Error(`fetch ${res.status}`);
      buf = await res.arrayBuffer();
    } catch {
      throw new Error(`Could not download the ciphertext from ${reveal.ciphertextUrl}.`);
    }
    ciphertext = new Uint8Array(buf);
    if (bytesToHex(sha256Bytes(ciphertext)) !== reveal.ciphertextSha256) {
      throw new Error("Downloaded ciphertext failed its sha256 integrity check.");
    }
  } else {
    throw new Error("Reveal account has no ciphertext carrier.");
  }

  const plaintext = await openSealed(ciphertext, kp);
  if (!plaintext) {
    throw new Error(
      "Decryption failed — this reveal is sealed to a different key than the one loaded here (or the ciphertext is corrupt). Restore the backup that was downloaded when this bounty was posted.",
    );
  }
  return { plaintext, carrier, sourceUrl };
}

// Key material for the rig, persisted so `seed` and `serve` always agree.
//
// libsodium covers both halves of what the rig needs: ed25519 (Solana keypairs and
// the operator's verdict signature) and X25519 (crypto_box_seal). A Solana secret key
// is byte-identical to libsodium's 64-byte ed25519 secret key, so Keypair.fromSecretKey
// consumes what crypto_sign_keypair produces without conversion.

import fs from "node:fs";
import _sodium from "libsodium-wrappers";
import { Keypair } from "@solana/web3.js";
import { KEYS_PATH } from "./config.mjs";

let ready = null;
export async function sodium() {
  if (!ready) ready = _sodium.ready.then(() => _sodium);
  return ready;
}

const b64 = (u8) => Buffer.from(u8).toString("base64");
const un64 = (s) => new Uint8Array(Buffer.from(s, "base64"));

async function generate() {
  const s = await sodium();
  const signer = () => b64(s.crypto_sign_keypair().privateKey);
  const box = () => {
    const kp = s.crypto_box_keypair();
    return { publicKey: b64(kp.publicKey), secretKey: b64(kp.privateKey) };
  };
  return {
    _comment: "DEV-ONLY rig keys. Never reuse on devnet or mainnet. Gitignored.",
    operator: signer(), // signs SCB_VERDICT_V4 attestations
    relayer: signer(), // lands resolve_with_attestation, pays reveal/receipt rent
    buyer: signer(), // posts the pre-seeded demo bounties
    enclaveEnc: box(), // hunters seal exploits to this pk (Config.enclave_enc_pk)
    buyerEnc: box(), // reveals for rig-seeded bounties are sealed to this pk
  };
}

/** Idempotent: reads rig.local.json if it exists, otherwise creates it. */
export async function loadOrCreateKeys() {
  await sodium();
  if (!fs.existsSync(KEYS_PATH)) {
    fs.writeFileSync(KEYS_PATH, JSON.stringify(await generate(), null, 2) + "\n");
  }
  return hydrate(JSON.parse(fs.readFileSync(KEYS_PATH, "utf8")));
}

export function keysExist() {
  return fs.existsSync(KEYS_PATH);
}

function hydrate(raw) {
  return {
    operator: Keypair.fromSecretKey(un64(raw.operator)),
    relayer: Keypair.fromSecretKey(un64(raw.relayer)),
    buyer: Keypair.fromSecretKey(un64(raw.buyer)),
    enclaveEnc: {
      publicKey: un64(raw.enclaveEnc.publicKey),
      secretKey: un64(raw.enclaveEnc.secretKey),
    },
    buyerEnc: {
      publicKey: un64(raw.buyerEnc.publicKey),
      secretKey: un64(raw.buyerEnc.secretKey),
    },
  };
}

// --- sodium-backed primitives the rig shares with the app -------------------

export async function sealTo(message, recipientPk) {
  return (await sodium()).crypto_box_seal(message, recipientPk);
}

export async function openSealed(ciphertext, kp) {
  const s = await sodium();
  try {
    return s.crypto_box_seal_open(ciphertext, kp.publicKey, kp.secretKey);
  } catch {
    return null;
  }
}

/** Detached ed25519 signature; `kp` is a web3.js Keypair. */
export async function signDetached(message, kp) {
  return (await sodium()).crypto_sign_detached(message, kp.secretKey);
}

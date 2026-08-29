// Upload a sealed reveal blob to Arweave via Turbo, permanently, and return an
// https gateway URL + its sha256. Used by the enclave so the exploit delivered
// to the buyer lives off-chain (public, but encrypted to the buyer) while only a
// tiny URL + hash go on-chain — no transaction-size limit, no key on-chain.
//
// Turbo uploads under 100 KiB are free (Arweave storage is permanent). A sealed
// exploit is normally a few KB, so this is free in practice.
//
// Confidentiality is unaffected: the blob is a crypto_box_seal to the buyer's
// key, so a public Arweave URL is fine — only the buyer can decrypt it. Integrity
// is the on-chain sha256, which the frontend re-checks after download.

import { createHash } from "node:crypto";
import { Readable } from "node:stream";
import { TurboFactory } from "@ardrive/turbo-sdk";
import bs58 from "bs58";

const GATEWAY = process.env.SCB_ARWEAVE_GATEWAY ?? "https://arweave.net";
const FREE_LIMIT = 100 * 1024;

/**
 * @param {Uint8Array|Buffer} bytes  the sealed reveal blob
 * @param {Uint8Array|string} signer a Solana secret key: 64-byte array or base58
 * @returns {Promise<{url:string, sha256:string, id:string}>}
 */
export async function uploadToArweave(bytes, signer) {
  const buf = Buffer.from(bytes);
  if (buf.length > FREE_LIMIT) {
    // Over the free tier — Turbo would require a funded wallet. Surface it
    // clearly rather than failing deep in the SDK.
    throw new Error(
      `reveal blob is ${buf.length} bytes, over Turbo's ${FREE_LIMIT}-byte free limit; ` +
        "fund the Arweave signer wallet or split the payload",
    );
  }

  const privateKey = typeof signer === "string" ? signer : bs58.encode(Buffer.from(signer));
  const turbo = await TurboFactory.authenticated({ privateKey, token: "solana" });

  const res = await turbo.uploadFile({
    // Fresh stream per call — the SDK may read it more than once.
    fileStreamFactory: () => Readable.from(Buffer.from(buf)),
    fileSizeFactory: () => buf.length,
    dataItemOpts: {
      tags: [
        { name: "Content-Type", value: "application/octet-stream" },
        { name: "App-Name", value: "SealedCodeBounty" },
      ],
    },
  });

  const id = res.id;
  if (!id) throw new Error("Turbo upload returned no data-item id");
  return {
    id,
    url: `${GATEWAY}/${id}`,
    sha256: createHash("sha256").update(buf).digest("hex"),
  };
}

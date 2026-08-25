#!/usr/bin/env node
/**
 * scb-submit — CLI wrapper over submit-lib.ts (see header there for flow).
 * Lib functions are exported from submit-lib.ts; tests target that module.
 */
import { Command } from "commander";
import {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
} from "@solana/web3.js";
import nacl from "tweetnacl";
import sodium from "libsodium-wrappers";
import * as fs from "fs";
import { createHash } from "crypto";

import {
  buildSealedPayload,
  encodeSubmitExploitData,
  parseBountyFields,
  parseEnclavePkFromConfig,
  DEFAULT_PROGRAM_ID,
} from "./submit-lib";

function createSha256Hex(data: Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}
function createSha256Buf(data: Uint8Array): Buffer {
  return createHash("sha256").update(data).digest();
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

interface Opts {
  rpcUrl: string;
  keypair: string;
  bounty: string;
  file: string;
  enclaveUrl: string;
  blobUrl?: string;
  programId: string;
  wait?: boolean;
  dryRun?: boolean;
}

async function run(o: Opts): Promise<void> {
  const [buyerStr, idStr] = o.bounty.split(":");
  if (!buyerStr || !idStr || !/^\d+$/.test(idStr)) {
    throw new Error('--bounty must be "<buyer_pubkey>:<numeric_id>"');
  }
  const buyerPk = new PublicKey(buyerStr);
  const bountyId = BigInt(idStr);
  const exploitBytes = fs.readFileSync(o.file);
  const hunter = Keypair.fromSecretKey(
    Uint8Array.from(JSON.parse(fs.readFileSync(o.keypair, "utf8")))
  );
  const programId = new PublicKey(o.programId);

  const bountyIdBuf = Buffer.alloc(8);
  bountyIdBuf.writeBigUInt64LE(bountyId);
  const bountyPda = PublicKey.findProgramAddressSync(
    [Buffer.from("bounty"), buyerPk.toBuffer(), bountyIdBuf],
    programId
  )[0];
  const configPda = PublicKey.findProgramAddressSync(
    [Buffer.from("config")],
    programId
  )[0];

  if (o.dryRun) {
    // No network: print shapes with placeholder chain values.
    // No network AND no real key material in dry-run: derive only sizes.
    const sealedLen = exploitBytes.length + 48; // libsodium sealed box = epk(32)+tag(16)+msg
    const shaBuf = createSha256Buf(exploitBytes);
    const shaHex = shaBuf.toString("hex");
    console.log("[dry-run] /internal/upload body shape:");
    console.log(
      JSON.stringify(
        {
          bounty_pda: bountyPda.toBase58(),
          claimed_chain_view: {
            env_blob_sha256: "<32B hex from Bounty>",
            buyer_enc_pk: "<32B hex from Bounty>",
            flag_commitment: "<32B hex from Bounty>",
            exploit_sha256: shaHex,
          },
          solver_pubkey: hunter.publicKey.toBase58(),
          submit_intent_sig_b64_len: Buffer.from(
            nacl.sign.detached(
              Buffer.concat([Buffer.from("SCB_SUBMIT_V1"), bountyPda.toBytes(), Buffer.from(shaHex, "hex")]),
              hunter.secretKey
            )
          ).toString("base64").length,
          exploit_sealed_box_b64_len: Buffer.from(
            Buffer.alloc(Math.ceil(sealedLen / 3) * 4)
          ).toString("base64").length,
        },
        null,
        2
      )
    );
    console.log(
      "[dry-run] submit_exploit data length:",
      encodeSubmitExploitData(bountyId, blobUrlPlaceholder(), shaBuf).length
    );
    return;
  }

  const connection = new Connection(o.rpcUrl, "confirmed");

  // ---- a. fetch Bounty ----------------------------------------------------
  const bountyAcct = await connection.getAccountInfo(bountyPda);
  if (!bountyAcct) throw new Error(`Bounty account ${bountyPda.toBase58()} not found`);
  const bounty = parseBountyFields(bountyAcct.data);
  if (Math.floor(Date.now() / 1000) >= bounty.deadlineSecs) {
    throw new Error(
      `deadline passed client-side (${new Date(bounty.deadlineSecs * 1000).toISOString()})`
    );
  }
  if (bounty.statusByte !== 0 && bounty.statusByte !== 1) {
    throw new Error(`bounty not submittable (status byte ${bounty.statusByte})`);
  }

  // ---- b. fetch Config ----------------------------------------------------
  const cfgAcct = await connection.getAccountInfo(configPda);
  if (!cfgAcct) throw new Error(`Config account ${configPda.toBase58()} not found`);
  const enclaveEncPk = parseEnclavePkFromConfig(cfgAcct.data);

  // ---- c+d. seal + intent -------------------------------------------------
  const built = await buildSealedPayload(
    exploitBytes,
    hunter,
    bountyPda,
    enclaveEncPk,
    {
      envBlobSha256: bounty.envBlobSha256,
      buyerEncPk: bounty.buyerEncPk,
      flagCommitment: bounty.flagCommitment,
    }
  );

  const blobUrl =
    o.blobUrl ?? `https://blob.local/${built.plaintextShaHex}`;

  // ---- e. enclave upload --------------------------------------------------
  const uploadRes = await fetch(`${o.enclaveUrl}/internal/upload`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      bounty_pda: bountyPda.toBase58(),
      claimed_chain_view: built.claimedChainView,
      solver_pubkey: built.solverPubkeyB58,
      submit_intent_sig: built.intentSigB64,
      exploit_sealed_box: built.sealedBoxB64,
    }),
  });
  if (!uploadRes.ok) {
    throw new Error(
      `upload failed HTTP ${uploadRes.status}: ${await uploadRes.text()}`
    );
  }
  const receipt = ((await uploadRes.json()) as { receipt: string }).receipt;

  // ---- f. on-chain registration -------------------------------------------
  const data = encodeSubmitExploitData(
    bountyId,
    blobUrl,
    Buffer.from(built.plaintextShaHex, "hex")
  );
  const ix = new TransactionInstruction({
    programId,
    keys: [
      { pubkey: hunter.publicKey, isSigner: true, isWritable: true }, // solver
      { pubkey: configPda, isSigner: false, isWritable: false }, // config
      { pubkey: bountyPda, isSigner: false, isWritable: true }, // bounty
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  });
  const tx = new Transaction().add(ix);
  const signature = await connection.sendTransaction(tx, [hunter]);

  // ---- g. optional verdict polling ----------------------------------------
  if (!o.wait) {
    console.log(JSON.stringify({ status: "submitted", receipt, signature }));
    return;
  }
  for (;;) {
    const acct = await connection.getAccountInfo(bountyPda);
    if (!acct) throw new Error("bounty closed while waiting");
    const st = parseBountyFields(acct.data).statusByte;
    if (st === 2) {
      console.log(JSON.stringify({ status: "PASS", receipt, signature }));
      return;
    }
    if (st === 0) {
      console.log(
        JSON.stringify({
          status: "FAIL",
          note:
            "bond refunded, slot open for resubmit. redacted_log retrieval TODO (no public log endpoint yet).",
          receipt,
        })
      );
      return;
    }
    await sleep(1500);
  }
}

function createSha256(data: Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}
function blobUrlPlaceholder(): string {
  return "https://blob.local/x";
}

const program = new Command();
program
  .name("scb-submit")
  .description("Submit a sealed exploit to a SealedCodeBounty bounty.")
  .requiredOption("--rpc-url <url>", "Solana RPC endpoint")
  .requiredOption("--keypair <path>", "hunter wallet keypair JSON (solana-keygen format)")
  .requiredOption("--bounty <buyer:bounty_id>", "bounty identity as buyer_pubkey:numeric_id")
  .requiredOption("--file <path>", "exploit script (python3 + pwntools)")
  .option("--enclave-url <url>", "verifier enclave base URL (required unless --dry-run)")
  .option("--blob-url <url>", "blob_url recorded on-chain (default https://blob.local/<sha>)")
  .option("--program-id <pubkey>", "program id", DEFAULT_PROGRAM_ID)
  .option("--wait", "poll until the bounty leaves AwaitingResolution")
  .option("--dry-run", "print payload shapes without any network")
  .showHelpAfterError("(run with --help)");

async function cliMain() {
  program.parse(process.argv);
  const o = program.opts<Opts>();
  const [dir] = program.args ?? [];
  void dir;
  await run(o);
}

if (require.main === module) {
  cliMain()
    .then(() => process.exit(0))
    .catch((e) => {
      console.error(`scb-submit: ${e?.message ?? e}`);
      process.exit(1);
    });
}

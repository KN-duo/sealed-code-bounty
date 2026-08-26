// e2e/chain.mjs — chain helpers + CLI entry for the localnet dress rehearsal.
//
// Usage: node e2e/chain.mjs <cmd> [args...]   (prints JSON on stdout)
// Env:   RPC_URL, PROGRAM_ID

import { createRequire } from "node:module";
import * as path from "node:path";
import * as fs from "node:fs";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, "..");
const require = createRequire(import.meta.url);

const anchor = require(path.join(REPO_ROOT, "node_modules/@anchor-lang/core"));
const web3 = require(path.join(REPO_ROOT, "node_modules/@solana/web3.js"));
const SODIUM_PATH = path.join(
  REPO_ROOT,
  "cli/node_modules/libsodium-wrappers/dist/modules/libsodium-wrappers.js"
);
async function getSodium() {
  return import(pathToFileURL(SODIUM_PATH));
}

function pathToFileURL(p) {
  return "file://" + (process.platform === "win32" ? "/" : "") + p.replace(/\\/g, "/");
}

const RPC_URL = process.env.RPC_URL ?? "http://127.0.0.1:8899";
const PROGRAM_ID_STR =
  process.env.PROGRAM_ID ?? "FbqouGmrsFmoC24H3x1vX3LX9jVXhUN5zDH7RnSXba9V";
const PROGRAM_ID = new web3.PublicKey(PROGRAM_ID_STR);
const PROCESS_ENV_PROGRAM_ID = PROGRAM_ID_STR;

const connection = new web3.Connection(RPC_URL, "confirmed");
const IDL = JSON.parse(
  fs.readFileSync(path.join(REPO_ROOT, "target/idl/sealed_code_bounty.json"), "utf8")
);
// anchor 1.x derives the program id from idl.metadata.address.
IDL.metadata.address = PROCESS_ENV_PROGRAM_ID;

function kpFromFile(p) {
  return web3.Keypair.fromSecretKey(Uint8Array.from(JSON.parse(fs.readFileSync(p, "utf8"))));
}
function programWithWallet(walletKp) {
  const provider = new anchor.AnchorProvider(connection, new anchor.Wallet(walletKp), {
    commitment: "confirmed",
  });
  return new anchor.Program(IDL, provider);
}

const configPdaPubkey = () =>
  web3.PublicKey.findProgramAddressSync([Buffer.from("config")], PROGRAM_ID)[0];
const bountyPdaPubkey = (buyer, id) => {
  const buyerKey = buyer instanceof web3.PublicKey ? buyer : new web3.PublicKey(buyer);
  const idBuf = Buffer.alloc(8);
  idBuf.writeBigUInt64LE(BigInt(id));
  return web3.PublicKey.findProgramAddressSync(
    [Buffer.from("bounty"), buyerKey.toBuffer(), idBuf],
    PROGRAM_ID
  )[0];
};
const receiptPdaPubkey = (bountyKey, solver) =>
  web3.PublicKey.findProgramAddressSync(
    [Buffer.from("receipt"), bountyKey.toBuffer(), solver.toBuffer()],
    PROGRAM_ID
  )[0];
const revealPdaPubkey = (bountyKey) =>
  web3.PublicKey.findProgramAddressSync([Buffer.from("reveal"), bountyKey.toBuffer()], PROGRAM_ID)[0];

async function confirm(sig) {
  const latest = await connection.getLatestBlockhash("confirmed");
  const r = await connection.confirmTransaction({ signature: sig, ...latest }, "confirmed");
  if (r.value.err) {
    let logs = "";
    try {
      const tx = await connection.getTransaction(sig, { maxSupportedTransactionVersion: 0 });
      logs = (tx?.meta?.logMessages ?? []).join("\n");
    } catch {}
    throw new Error(`tx ${sig} failed on-chain:\n${logs}`);
  }
}

/** Fetch + decode the Bounty fields the e2e cares about. null if closed. */
async function fetchBounty(buyerPk, id) {
  const key = bountyPdaPubkey(buyerPk, id);
  const info = await connection.getAccountInfo(key);
  if (!info) return { exists: false };
  const d = info.data;
  const hasSubmission = d[193] === 1;
  let solverB58 = null;
  let exploitSha256Hex = null;
  let bondLamports = null;
  let submittedAtSecs = null;
  if (hasSubmission) {
    solverB58 = new web3.PublicKey(d.subarray(194, 226)).toBase58();
    exploitSha256Hex = Buffer.from(d.subarray(226, 258)).toString("hex");
    const urlLen = d.readUInt32LE(258);
    // url bytes then bond u64 then submittedAt i64
    bondLamports = Number(d.readBigInt64LE(262 + urlLen));
    submittedAtSecs = Number(d.readBigInt64LE(262 + urlLen + 8));
  }
  return {
    exists: true,
    pda: key.toBase58(),
    statusByte: d[48],
    prizeLamports: Number(d.readBigInt64LE(49)),
    deadlineSecs: Number(d.readBigInt64LE(57)),
    envBlobSha256Hex: Buffer.from(d.subarray(97, 129)).toString("hex"),
    flagCommitmentHex: Buffer.from(d.subarray(129, 161)).toString("hex"),
    buyerEncPkHex: Buffer.from(d.subarray(161, 193)).toString("hex"),
    submissionFlag: d[193],
    solverB58,
    exploitSha256Hex,
    bondLamports,
    submittedAtSecs,
    winnerByte: (() => {
      if (!hasSubmission) return null;
      const urlLen = d.readUInt32LE(258);
      const afterUrl = 262 + urlLen + 16; // bond + submittedAt
      return d[afterUrl] === 1 ? new web3.PublicKey(d.subarray(afterUrl + 1, afterUrl + 33)).toBase58() : null;
    })(),
  };
}

async function balance(pkStr) {
  return connection.getBalance(new web3.PublicKey(pkStr));
}
async function accountExists(pk) {
  return (await connection.getAccountInfo(new web3.PublicKey(pk))) !== null;
}
async function receiptExists(buyerPk, id, solverPkStr) {
  const key = receiptPdaPubkey(bountyPdaPubkey(buyerPk, id), new web3.PublicKey(solverPkStr));
  return (await connection.getAccountInfo(key)) !== null;
}
async function revealCtB64(buyerPk, id) {
  const key = revealPdaPubkey(bountyPdaPubkey(buyerPk, id));
  const acc = await connection.getAccountInfo(key);
  if (!acc) return null;
  const ctLen = acc.data.readUInt32LE(8);
  return Buffer.from(acc.data.subarray(12, 12 + ctLen)).toString("base64");
}

// ---------------------------------------------------------------------------
// CLI dispatch
// ---------------------------------------------------------------------------

const [, , cmd, ...args] = process.argv;

switch (cmd) {
  case "init-config": {
    const [authKpPath, operatorPubB58, encPkHex, bond] = args;
    const payer = kpFromFile(authKpPath);
    const prog = programWithWallet(payer);
    const sig = await prog.methods
      .initializeConfig(payer.publicKey, [...Buffer.from(encPkHex, "hex")], new anchor.BN(Number(bond)))
      .accountsStrict({ payer: payer.publicKey, config: configPdaPubkey(), systemProgram: web3.SystemProgram.programId })
      .rpc();
    await confirm(sig);
    console.log(JSON.stringify({ ok: true, signature: sig }));
    break;
  }
  case "arm-operators": {
    // initializeConfig leaves operators empty by design; arming happens here via
    // the authority-gated set_operators. Args: authKpPath opPubB58 encPkHex threshold delaySecs
    const [authKpPath, operatorPubB58, encPkHex, threshold, delay] = args;
    const payer = kpFromFile(authKpPath);
    const prog = programWithWallet(payer);
    const sig = await prog.methods
      .setOperators([new web3.PublicKey(operatorPubB58)], Number(threshold), [...Buffer.from(encPkHex, "hex")], new anchor.BN(Number(delay)))
      .accountsStrict({ authority: payer.publicKey, config: configPdaPubkey() })
      .rpc();
    await confirm(sig);
    console.log(JSON.stringify({ ok: true, signature: sig }));
    break;
  }
  case "set-operators": {
    // args: <authorityKp> <opsJsonArray> <threshold> <encPkHex> <delaySecs>
    const [authKpPath, opsJson, threshold, encPkHex, delay] = args;
    const auth = kpFromFile(authKpPath);
    const prog = programWithWallet(auth);
    const ops = JSON.parse(opsJson).map(s => new web3.PublicKey(s));
    const sig = await prog.methods
      .setOperators(ops, Number(threshold), [...Buffer.from(encPkHex, "hex")], new anchor.BN(Number(delay)))
      .accountsStrict({ authority: auth.publicKey, config: configPdaPubkey() })
      .rpc();
    await confirm(sig);
    console.log(JSON.stringify({ ok: true }));
    break;
  }

  case "create-bounty": {
    const [buyerKpPath, id, prize, deadlineInSecs, manifestHex, envHex, flagCHex, buyerEncPkHex] = args;
    const buyer = kpFromFile(buyerKpPath);
    const prog = programWithWallet(buyer);
    const deadline = Math.floor(Date.now() / 1000) + Number(deadlineInSecs);
    const sig = await prog.methods
      .createBounty(
        new anchor.BN(id),
        new anchor.BN(prize),
        new anchor.BN(deadline),
        [...Buffer.from(manifestHex, "hex")],
        [...Buffer.from(envHex, "hex")],
        [...Buffer.from(flagCHex, "hex")],
        [...Buffer.from(buyerEncPkHex, "hex")]
      )
      .accountsStrict({
        buyer: buyer.publicKey,
        config: configPdaPubkey(),
        bounty: bountyPdaPubkey(buyer.publicKey, id),
        systemProgram: web3.SystemProgram.programId,
      })
      .rpc();
    await confirm(sig);
    console.log(JSON.stringify({ ok: true, signature: sig, deadline }));
    break;
  }
  case "submit-exploit": {
    const [solverKpPath, buyerB58, id, url, shaHex] = args;
    const solver = kpFromFile(solverKpPath);
    const buyer = new web3.PublicKey(buyerB58);
    const prog = programWithWallet(solver);
    const sig = await prog.methods
      .submitExploit(new anchor.BN(id), url, [...Buffer.from(shaHex, "hex")])
      .accountsStrict({
        solver: solver.publicKey,
        config: configPdaPubkey(),
        bounty: bountyPdaPubkey(buyer, id),
        systemProgram: web3.SystemProgram.programId,
      })
      .rpc();
    await confirm(sig);
    console.log(JSON.stringify({ ok: true, signature: sig }));
    break;
  }
  case "force-unlock": {
    const [callerKpPath, buyerB58, solverB58, id] = args;
    const caller = kpFromFile(callerKpPath);
    const buyer = new web3.PublicKey(buyerB58);
    const solver = new web3.PublicKey(solverB58);
    const prog = programWithWallet(caller);
    const sig = await prog.methods
      .forceUnlockSubmission(new anchor.BN(id))
      .accountsStrict({
        caller: caller.publicKey,
        bounty: bountyPdaPubkey(buyer, id),
        config: configPdaPubkey(),
        solver,
      })
      .rpc();
    await confirm(sig);
    console.log(JSON.stringify({ ok: true, signature: sig }));
    break;
  }
  case "set-delay": {
    // Rewrites Config.force_unlock_delay_s by replaying the CURRENT operator
    // set through set_operators with a new delay (authority-gated).
    const [authKpPath, delay] = args;
    const auth = kpFromFile(authKpPath);
    const prog = programWithWallet(auth);
    const cfgInfo = await connection.getAccountInfo(configPdaPubkey());
    if (!cfgInfo) throw new Error("config not initialized");
    const d = cfgInfo.data;
    const opsLen = d.readUInt32LE(40);
    const ops = [];
    for (let i = 0; i < opsLen; i++) {
      ops.push(new web3.PublicKey(d.subarray(44 + i * 32, 76 + i * 32)));
    }
    const threshold = d[76 + opsLen * 32];
    const encPk = Buffer.from(d.subarray(77 + opsLen * 32, 109 + opsLen * 32));
    const sig = await prog.methods
      .setOperators(ops, threshold, [...encPk], new anchor.BN(Number(delay)))
      .accountsStrict({ authority: auth.publicKey, config: configPdaPubkey() })
      .rpc();
    await confirm(sig);
    console.log(JSON.stringify({ ok: true, signature: sig }));
    break;
  }
  case "fetch-config": {
    const key = configPdaPubkey();
    const info = await connection.getAccountInfo(key);
    if (!info) { console.log(JSON.stringify(null)); break; }
    const d = info.data;
    // Anchor vec layout: u32 len then items. ops_len sits at 8+32=40.
    const opsLen = d.readUInt32LE(8 + 32);
    const ops = [];
    for (let i = 0; i < opsLen; i++)
      ops.push(new web3.PublicKey(d.subarray(44 + i * 32, 76 + i * 32)).toBase58());
    const afterOps = 44 + opsLen * 32;
    console.log(JSON.stringify({
      authority: new web3.PublicKey(d.subarray(8, 40)).toBase58(),
      operators: ops,
      threshold: d[afterOps],
      encPkHex: Buffer.from(d.subarray(afterOps + 1, afterOps + 33)).toString("hex"),
    }));
    break;
  }



  case "fetch-bounty": {
    const [buyerB58, id] = args;
    console.log(JSON.stringify(await fetchBounty(new web3.PublicKey(buyerB58), id)));
    break;
  }
  case "balance": {
    console.log(JSON.stringify({ lamports: await balance(args[0]) }));
    break;
  }
  case "dump-config": {
    const info = await connection.getAccountInfo(configPdaPubkey());
    if (!info) { console.log(JSON.stringify({hex:null})); break; }
    console.log(JSON.stringify({ hex: Buffer.from(info.data.subarray(0,120)).toString("hex"), len: info.data.length }));
    break;
  }


  case "receipt-exists": {
    const [buyerB58, id, solverB58] = args;
    console.log(JSON.stringify({ exists: await receiptExists(buyerB58, id, solverB58) }));
    break;
  }
  case "reveal-ct": {
    const [buyerB58, id] = args;
    console.log(JSON.stringify({ ciphertextB64: await revealCtB64(buyerB58, id) }));
    break;
  }
  default:
    console.error(`unknown cmd: ${cmd}`);
    process.exit(2);
}


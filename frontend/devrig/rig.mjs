#!/usr/bin/env node
// Local test rig for the SealedCodeBounty frontend.
//
//   node devrig/rig.mjs keys                          generate/print the dev keypairs
//   node devrig/rig.mjs seed --wallet <pubkey>        init config + operators + demo bounties
//   node devrig/rig.mjs serve [--always pass|fail]    mock enclave on :8443
//
// Run the chain half first (devrig/localnet.sh, in WSL). See docs/frontend-testing.md.

import fs from "node:fs";
import { createHash } from "node:crypto";
import {
  BOND_LAMPORTS,
  DEFAULT_PRIZE_LAMPORTS,
  ENV_LOCAL_PATH,
  FORCE_UNLOCK_DELAY_S,
  KEYS_PATH,
  LAMPORTS_PER_SOL,
  PROGRAM_ID,
  RPC_URL,
} from "./config.mjs";
import { loadOrCreateKeys } from "./keys.mjs";
import {
  BN,
  PublicKey,
  SystemProgram,
  accounts,
  bountyPda,
  chainNow,
  configPda,
  connect,
  fundTo,
  hex,
  makeProgram,
} from "./chain.mjs";
import { VERDICT_RULE, mockFlagCommitment, serve } from "./enclave.mjs";

const sha256 = (data) => new Uint8Array(createHash("sha256").update(data).digest());

function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) out[a.slice(2)] = argv[i + 1]?.startsWith("--") ? true : argv[++i];
    else out._.push(a);
  }
  return out;
}

function die(msg) {
  console.error(`\n  error: ${msg}\n`);
  process.exit(1);
}

async function requireValidator(connection) {
  try {
    await connection.getVersion();
  } catch {
    die(
      `no validator answering at ${RPC_URL}.\n` +
        "  Start the chain half first: run devrig/localnet.sh inside WSL.",
    );
  }
  const info = await connection.getAccountInfo(new PublicKey(PROGRAM_ID));
  if (!info) {
    die(
      `program ${PROGRAM_ID} is not deployed on ${RPC_URL}.\n` +
        "  Run anchor deploy (devrig/localnet.sh does this), or set VITE_PROGRAM_ID.",
    );
  }
}

// --- commands --------------------------------------------------------------

async function cmdKeys() {
  const keys = await loadOrCreateKeys();
  console.log(`\n  keys        ${KEYS_PATH}`);
  console.log(`  operator    ${keys.operator.publicKey.toBase58()}`);
  console.log(`  relayer     ${keys.relayer.publicKey.toBase58()}`);
  console.log(`  rig buyer   ${keys.buyer.publicKey.toBase58()}`);
  console.log(`  enclave pk  ${hex(keys.enclaveEnc.publicKey)}`);
  console.log(`  buyer pk    ${hex(keys.buyerEnc.publicKey)}\n`);
}

async function cmdSeed(args) {
  const wallet = args.wallet;
  if (!wallet || wallet === true) {
    die("--wallet <your-phantom-pubkey> is required so the rig can airdrop to you.");
  }
  let walletPk;
  try {
    walletPk = new PublicKey(wallet);
  } catch {
    die(`"${wallet}" is not a valid base58 public key.`);
  }

  const connection = connect();
  await requireValidator(connection);
  const keys = await loadOrCreateKeys();
  const program = makeProgram(connection, keys.buyer);

  console.log("\n  funding accounts...");
  for (const [name, pk] of [
    ["rig buyer", keys.buyer.publicKey],
    ["relayer", keys.relayer.publicKey],
    ["your wallet", walletPk],
  ]) {
    const did = await fundTo(connection, pk, 20);
    console.log(`    ${did ? "airdropped" : "already funded"}  ${name}  ${pk.toBase58()}`);
  }

  // 1. config -------------------------------------------------------------
  const cfg = configPda();
  const existing = await accounts(program).config.fetchNullable(cfg);
  if (existing) {
    console.log(`  config      already initialized at ${cfg.toBase58()}`);
  } else {
    await program.methods
      .initializeConfig(
        keys.buyer.publicKey,
        Array.from(keys.enclaveEnc.publicKey),
        new BN(BOND_LAMPORTS),
      )
      .accountsStrict({
        payer: keys.buyer.publicKey,
        config: cfg,
        systemProgram: SystemProgram.programId,
      })
      .rpc();
    console.log(`  config      initialized at ${cfg.toBase58()}`);
  }

  // 2. operators ----------------------------------------------------------
  // initialize_config leaves `operators` empty; resolve_with_attestation rejects
  // signatures from unregistered keys, so the operator MUST be added here.
  await program.methods
    .setOperators(
      [keys.operator.publicKey],
      1,
      Array.from(keys.enclaveEnc.publicKey),
      new BN(FORCE_UNLOCK_DELAY_S),
    )
    .accountsStrict({ authority: keys.buyer.publicKey, config: cfg })
    .rpc();
  console.log(`  operators   [${keys.operator.publicKey.toBase58()}] threshold 1`);

  // 3. demo bounties ------------------------------------------------------
  const now = await chainNow(connection);
  const base = Date.now() % 1_000_000;
  const demos = [
    { id: base, label: "ret2win", deadline: now + 7 * 24 * 3600 },
    { id: base + 1, label: "echo-service", deadline: now + 7 * 24 * 3600 },
  ];

  const seeded = [];
  for (const demo of demos) {
    const bountyId = new BN(demo.id);
    const pda = bountyPda(keys.buyer.publicKey, bountyId);
    const manifest = sha256(Buffer.from(`scb-mock-manifest:${demo.label}`));
    const envBlob = sha256(Buffer.from(`scb-mock-env:${demo.label}`));
    const flag = Buffer.from(mockFlagCommitment(pda.toBase58()), "hex");

    await program.methods
      .createBounty(
        bountyId,
        new BN(DEFAULT_PRIZE_LAMPORTS),
        new BN(demo.deadline),
        Array.from(manifest),
        Array.from(envBlob),
        Array.from(flag),
        Array.from(keys.buyerEnc.publicKey),
      )
      .accountsStrict({
        buyer: keys.buyer.publicKey,
        config: cfg,
        bounty: pda,
        systemProgram: SystemProgram.programId,
      })
      .rpc();
    seeded.push({ ...demo, pda: pda.toBase58() });
    console.log(`  bounty      #${demo.id} ${demo.label} -> ${pda.toBase58()}`);
  }

  // 4. .env.local ---------------------------------------------------------
  const envBody =
    "# Written by devrig/rig.mjs seed. Safe to delete.\n" +
    `VITE_RPC_URL=${RPC_URL}\n` +
    `VITE_PROGRAM_ID=${PROGRAM_ID}\n`;
  fs.writeFileSync(ENV_LOCAL_PATH, envBody);
  console.log(`  env         wrote ${ENV_LOCAL_PATH}`);

  console.log("\n  next:");
  console.log("    node devrig/rig.mjs serve     (mock enclave, separate terminal)");
  console.log("    npm run dev                   (restart it - .env.local changed)\n");
  for (const s of seeded) {
    console.log(`    ${s.label.padEnd(13)} http://localhost:5173/#/hunt/${s.pda}`);
  }
  console.log(
    "\n  Reveals for these bounties are sealed to the rig's buyer key, not yours -\n" +
      "  post your own bounty at #/post to exercise the decrypt flow in #/manage.\n",
  );
}

async function cmdServe(args) {
  const force = args.always === "pass" || args.always === "fail" ? args.always : null;
  if (args.always && !force) die(`--always takes "pass" or "fail", got "${args.always}".`);

  const connection = connect();
  await requireValidator(connection);
  const keys = await loadOrCreateKeys();

  const { port } = await serve({ keys, force });
  console.log(`\n  mock enclave listening on http://127.0.0.1:${port}`);
  console.log(`  rpc          ${RPC_URL}`);
  console.log(`  enclave pk   ${hex(keys.enclaveEnc.publicKey)}`);
  console.log(`  operator     ${keys.operator.publicKey.toBase58()}`);
  console.log(`  verdict rule ${force ? `forced ${force.toUpperCase()}` : VERDICT_RULE}`);
  console.log("\n  This mock does NOT run your exploit. It decides on the plaintext alone.\n");

  const relayerSol = (await connection.getBalance(keys.relayer.publicKey)) / LAMPORTS_PER_SOL;
  if (relayerSol < 1) {
    console.log(`  ! relayer has ${relayerSol} SOL - run seed first or resolves will fail.\n`);
  }
}

// --- dispatch --------------------------------------------------------------

const args = parseArgs(process.argv.slice(2));
const cmd = args._[0];

const commands = { keys: cmdKeys, seed: cmdSeed, serve: cmdServe };
if (!commands[cmd]) {
  console.log(`
  usage: node devrig/rig.mjs <command>

    keys                          generate or print the dev keypairs
    seed --wallet <pubkey>        init config, register the operator, seed demo bounties
    serve [--always pass|fail]    run the mock enclave + verdict relayer on :8443

  Start the chain half first: devrig/localnet.sh (inside WSL).
`);
  process.exit(cmd ? 1 : 0);
}

commands[cmd](args).catch((e) => {
  console.error(`\n  failed: ${e?.message ?? e}`);
  if (process.env.SCB_DEBUG) console.error(e);
  process.exit(1);
});

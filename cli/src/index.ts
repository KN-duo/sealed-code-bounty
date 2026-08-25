#!/usr/bin/env node
import { Command } from "commander";
import { existsSync } from "fs";
import { mkdir, writeFile, rm } from "fs/promises";
import * as path from "path";

import { PackError, EXIT_FLAG_INVALID, EXIT_USAGE } from "./errors";
import {
  assertDocker,
  build,
  inspectImage,
  readFlagFile,
  saveGzipped,
} from "./docker";
import { emitManifest, uploadTarball, FLAG_PLACEHOLDER, Manifest } from "./manifest";
import { renderCompose } from "./compose";
import { sanitizeName, shortHash } from "./util";

const program = new Command();

program
  .name("scb-pack")
  .description(
    "Package a SealedCodeBounty vulnerable environment: docker build -> /flag placeholder check -> docker save|gzip (sha256-pinned) -> manifest.json + dev-plane docker-compose.yml."
  )
  .version("0.1.0")
  .argument("<challenge-dir>", "directory containing a Dockerfile (build context)")
  .requiredOption("--out <outdir>", "output directory for manifest.json, compose file and tarball")
  .option("--name <name>", "challenge name (default: slug of challenge-dir basename)")
  .option("--kind <kind>", "target kind: tcp_service | binary", "tcp_service")
  .option("--port <n>", "tcp_service: port the service listens on", "1337")
  .option("--exec <path>", "binary: executable path inside the image")
  .option("--arg <tok>", "binary: extra argv token (repeatable)", (v: string, prev: string[]) => [...prev, v], [])
  .option("--timeout-secs <n>", "verification wall-clock limit", "60")
  .option("--memory-mb <n>", "verification memory cap", "512")
  .option("--cpus <n>", "verification cpu cap", "1")
  .option("--aslr <mode>", "determinism: off | on", "off")
  .option("--seed <n>", "determinism RNG seed exported as SEED to the target", "0")
  .option("--upload-url <url>", "storage endpoint to push the tarball to (phase-2; stub)")
  .showHelpAfterError("(run with --help for usage)");

interface Opts {
  out: string;
  name?: string;
  kind: string;
  port: string;
  exec?: string;
  arg: string[];
  timeoutSecs: string;
  memoryMb: string;
  cpus: string;
  aslr: string;
  seed: string;
  uploadUrl?: string;
}

async function main(): Promise<void> {
  program.parse(process.argv);
  const [challengeDirRaw] = program.args;
  if (!challengeDirRaw) throw new PackError(EXIT_USAGE, "<challenge-dir> is required");
  const o = program.opts<Opts>();

  // ---- validate inputs --------------------------------------------------
  const challengeDir = path.resolve(challengeDirRaw);
  if (!existsSync(path.join(challengeDir, "Dockerfile"))) {
    throw new PackError(EXIT_USAGE, `no Dockerfile in ${challengeDir}`);
  }
  if (!["tcp_service", "binary"].includes(o.kind)) {
    throw new PackError(EXIT_USAGE, `--kind must be tcp_service or binary (got "${o.kind}")`);
  }
  if (o.kind === "binary" && !o.exec) {
    throw new PackError(EXIT_USAGE, "--kind binary requires --exec <path-inside-image>");
  }
  const port = Number(o.port);
  if (o.kind === "tcp_service" && !(Number.isInteger(port) && port > 0 && port < 65536)) {
    throw new PackError(EXIT_USAGE, `--port "${o.port}" is not a valid TCP port`);
  }
  if (!["off", "on"].includes(o.aslr)) {
    throw new PackError(EXIT_USAGE, `--aslr must be off|on (got "${o.aslr}")`);
  }
  const timeoutSeconds = Number(o.timeoutSecs);
  const memoryMb = Number(o.memoryMb);
  const cpus = Number(o.cpus);
  const seed = Number(o.seed);
  if (![timeoutSeconds, memoryMb, cpus, seed].every((n) => Number.isFinite(n) && n >= 0)) {
    throw new PackError(EXIT_USAGE, "--timeout-secs/--memory-mb/--cpus/--seed must be non-negative numbers");
  }

  const name = sanitizeName(o.name ?? path.basename(challengeDir));
  const outDir = path.resolve(o.out);
  await mkdir(outDir, { recursive: true });

  await assertDocker();

  // ---- build (idempotent tag from Dockerfile contents) -------------------
  const dockerfile = await import("fs/promises").then((m) => m.readFile(path.join(challengeDir, "Dockerfile"), "utf8"));
  const tag = `scb/${name}:${shortHash(dockerfile)}`;
  console.error(`[1/5] docker build -t ${tag}`);
  await build(tag, challengeDir);

  // ---- static flag verification (image never executes) -------------------
  console.error("[2/5] verifying /flag contains the literal {{FLAG}}");
  const tmpFlag = path.join(outDir, `.flag-check-${Date.now()}`);
  let flagContent: Buffer;
  try {
    flagContent = await readFlagFile(tag, tmpFlag);
  } finally {
    await rm(tmpFlag, { force: true });
  }
  if (!flagContent.includes(FLAG_PLACEHOLDER)) {
    throw new PackError(
      EXIT_FLAG_INVALID,
      `/flag exists but does NOT contain the literal "{{FLAG}}" placeholder. ` +
        `The verification enclave injects the real secret at that marker; without it the environment would leak the flag to hunters.`
    );
  }

  // ---- save | gzip | hash -------------------------------------------------
  console.error(`[3/5] docker save | gzip -> ${outDir}/<sha256>.tar.gz`);
  const tmpTar = path.join(outDir, `${name}.tmp.tar.gz`);
  const sha256 = await saveGzipped(tag, tmpTar);
  const tarballName = `${sha256}.tar.gz`;
  const tarballPath = path.join(outDir, tarballName);
  await rm(tarballPath, { force: true });
  await import("fs/promises").then((m) => m.rename(tmpTar, tarballPath));

  // ---- manifest + dev plane ----------------------------------------------
  console.error("[4/5] emitting manifest.json + docker-compose.yml");
  const img = await inspectImage(tag);

  let url = tarballName; // relative until phase-2 storage lands
  if (o.uploadUrl) {
    url = await uploadTarball(o.uploadUrl, tarballPath, sha256); // throws NotImplemented(5)
  } else {
    console.error(
      "[!] no --upload-url given: manifest references the tarball by its LOCAL relative path " +
        `"${tarballName}". Upload before committing the manifest hash on-chain.`
    );
  }

  const entrypointString = [...img.entrypoint, ...img.cmd].join(" ");
  const manifest: Manifest = {
    format_version: 2,
    name,
    image_tarball: { url, sha256 },
    target:
      o.kind === "tcp_service"
        ? { kind: "tcp_service", host: "127.0.0.1", port }
        : { kind: "binary", exec: o.exec!, io: "stdio", argv: o.arg },
    limits: { timeout_seconds: timeoutSeconds, memory_mb: memoryMb, cpus },
    determinism: { aslr: o.aslr as "off" | "on", seed },
    flag_placeholder: FLAG_PLACEHOLDER,
    entrypoint: entrypointString,
  };
  await emitManifest(path.join(outDir, "manifest.json"), manifest);

  const composeText = renderCompose(manifest, tag, img.architecture, img.entrypoint, img.cmd);
  await writeFile(path.join(outDir, "docker-compose.yml"), composeText);

  console.error("[5/5] done:");
  console.error(`      ${tarballPath}   (sha256 ${sha256})`);
  console.error(`      ${path.join(outDir, "manifest.json")}`);
  console.error(`      ${path.join(outDir, "docker-compose.yml")}`);
}

main()
  .then(() => process.exit(0))
  .catch((e) => {
    if (e instanceof PackError) {
      console.error(`scb-pack: ${e.message}`);
      process.exit(e.exitCode);
    }
    console.error(`scb-pack: unexpected failure\n${e?.stack ?? e}`);
    process.exit(1);
  });


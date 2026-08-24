import { spawn } from "child_process";
import { createHash } from "crypto";
import { createWriteStream } from "fs";
import { PackError, EXIT_BUILD_FAILED, EXIT_SAVE_FAILED } from "./errors";
import { run } from "./util";

const DOCKER = "docker";

export async function dockerAvailable(): Promise<boolean> {
  try {
    await run(DOCKER, ["--version"], { quiet: true });
    return true;
  } catch {
    return false;
  }
}

export async function assertDocker(): Promise<void> {
  if (!(await dockerAvailable())) {
    throw new PackError(
      3,
      "`docker` CLI not found on PATH. The packager builds and saves images via docker; install Docker Desktop / engine and retry."
    );
  }
}

/** `docker build -t tag contextDir` (args array only — no shell interpolation). */
export async function build(tag: string, contextDir: string): Promise<void> {
  // --pull omitted deliberately: offline-friendly, reproducible against the
  // locally cached base. Callers wanting fresh bases can `docker pull` first.
  try {
    await run(DOCKER, ["build", "-t", tag, contextDir]);
  } catch (e) {
    throw new PackError(EXIT_BUILD_FAILED, String(e));
  }
}

export interface ImageConfig {
  entrypoint: string[];
  cmd: string[];
  architecture: string;
}

/** `docker inspect <tag>` → the fields the runner contract needs. */
export async function inspectImage(tag: string): Promise<ImageConfig> {
  const { stdout } = await run(DOCKER, ["inspect", "--format", "{{json .}}", tag]);
  const raw = JSON.parse(stdout);
  const cfg = raw.Config ?? {};
  const arch = String(raw.Architecture ?? "amd64");
  // Go template emits null for absent fields.
  const norm = (a: unknown): string[] => (Array.isArray(a) ? a.map(String) : []);
  return {
    entrypoint: norm(cfg.Entrypoint),
    cmd: norm(cfg.Cmd),
    architecture: arch === "arm64" ? "arm64" : arch, // keep as reported
  };
}

/**
 * Reads `/flag` out of the image WITHOUT running it:
 *   docker create <tag>            (container in Created state)
 *   docker cp <cid>:/flag <tmp>    (works on created containers)
 *   docker rm -f <cid>
 * Never executes image code — verification stays static (D3 adjacency).
 */
export async function readFlagFile(tag: string, tmpPath: string): Promise<Buffer> {
  const cid = `scb-pack-tmp-${Math.random().toString(36).slice(2, 10)}`;
  try {
    await run(DOCKER, ["create", "--name", cid, tag]);
  } catch (e) {
    throw new PackError(4, `docker create failed for ${tag}: ${String(e)}`);
  }
  try {
    await run(DOCKER, ["cp", `${cid}:/flag`, tmpPath]);
  } catch {
    throw new PackError(
      4,
      `/flag is MISSING from image ${tag}. Every SealedCodeBounty environment must ship /flag containing the literal {{FLAG}} placeholder.`
    );
  } finally {
    await run(DOCKER, ["rm", "-f", cid]).catch(() => {});
  }
  const { readFile } = await import("fs/promises");
  return readFile(tmpPath);
}

/**
 * `docker save <tag>` piped through gzip into <out>, hashing while streaming
 * so multi-hundred-MB images never sit fully in memory.
 */
export function saveGzipped(tag: string, outPath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = createHash("sha256");
    const out = createWriteStream(outPath);
    const saveProc = spawn(DOCKER, ["save", tag], { stdio: ["ignore", "pipe", "pipe"] });
    const gzipProc = spawn("gzip", ["-c"], { stdio: ["pipe", "pipe", "pipe"] });
    let saveErr = "";
    let gzipErr = "";
    let saveDone = false;
    let gzipDone = false;
    let failed = false;

    saveProc.stderr.on("data", (c: Buffer) => (saveErr += c));
    gzipProc.stderr.on("data", (c: Buffer) => (gzipErr += c));
    saveProc.stdout.pipe(gzipProc.stdin);
    gzipProc.stdout.on("data", (c: Buffer) => {
      hash.update(c);
      if (!out.write(c)) saveProc.stdout.pause(), gzipProc.stdout.pause();
    });
    out.on("drain", () => {
      saveProc.stdout.resume();
      gzipProc.stdout.resume();
    });

    const fail = (code: number, what: string): PackError =>
      new PackError(code, `${what}: ${(saveErr + " " + gzipErr).trim() || "unknown error"}`);

    const settle = () => {
      if (failed || !saveDone || !gzipDone) return;
      if (saveProc.exitCode !== 0)
        return reject(fail(EXIT_SAVE_FAILED, `docker save exited ${saveProc.exitCode}`));
      if (gzipProc.exitCode !== 0)
        return reject(fail(EXIT_SAVE_FAILED, `gzip exited ${gzipProc.exitCode}`));
      out.end(() => resolve(hash.digest("hex")));
    };

    saveProc.on("close", (code) => {
      saveDone = true;
      if (code !== 0) {
        failed = true;
        gzipProc.kill();
        out.destroy();
        return reject(fail(EXIT_SAVE_FAILED, `docker save exited ${code}`));
      }
      gzipProc.stdin.end();
      settle();
    });
    gzipProc.on("close", (code) => {
      gzipDone = true;
      if (code !== 0 && !failed) {
        failed = true;
        saveProc.kill();
        out.destroy();
        return reject(fail(EXIT_SAVE_FAILED, `gzip exited ${code}`));
      }
      settle();
    });
    out.on("close", () => {
      if (!saveDone || !gzipDone) {
        // out destroyed mid-stream by a failure path; nothing to do.
      }
    });
    [saveProc, gzipProc].forEach((p) => p.on("error", (e) => reject(e)));
  });
}

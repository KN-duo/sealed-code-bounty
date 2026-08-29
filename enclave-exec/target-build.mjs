// Build a company's vulnerable target from an uploaded SOURCE bundle (a zip of a
// Dockerfile + files) into a per-bounty Docker image. Storing source (KB) rather
// than a built image tarball (100s of MB) is what keeps target upload cheap/free.
//
// The bundle MUST contain a Dockerfile whose image:
//   - serves the vulnerable service on a TCP port (default 1337);
//   - reads /flag at exploit time (the enclave injects the real secret there),
//     so /flag must be root-owned and NOT world-readable — the exploit is the
//     only intended way to leak it.
//
// SECURITY (pre-TEE): `docker build` runs arbitrary instructions from untrusted
// input. On a local dev host that is acceptable; a hosted/production build must
// run inside the TEE (or a throwaway sandbox) with no secrets and no network to
// anything sensitive. Flagged here so it is a decision, not an accident.

import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";

const pexec = promisify(execFile);
const DOCKER = process.env.SCB_DOCKER ?? "docker";
const BUILD_TIMEOUT_MS = Number(process.env.SCB_BUILD_TIMEOUT_MS ?? 600000);
const MAX_UNZIP_BYTES = Number(process.env.SCB_TARGET_MAX_BYTES ?? 50 * 1024 * 1024);

async function docker(args, opts = {}) {
  try {
    const { stdout, stderr } = await pexec(DOCKER, args, {
      timeout: opts.timeoutMs,
      maxBuffer: 16 * 1024 * 1024,
      cwd: opts.cwd,
    });
    return { code: 0, stdout, stderr };
  } catch (e) {
    return { code: e.code ?? 1, stdout: e.stdout ?? "", stderr: e.stderr ?? String(e.message ?? e) };
  }
}

/**
 * Build a target image from a source-bundle zip.
 * @param {Uint8Array|Buffer} zipBytes  a zip containing a Dockerfile + files
 * @param {string} tag                  the image tag to build (e.g. scb-bounty-<pda8>)
 * @returns {Promise<{tag:string}>}
 */
export async function buildTargetImage(zipBytes, tag) {
  const buf = Buffer.from(zipBytes);
  if (buf.length > MAX_UNZIP_BYTES) {
    throw new Error(`target source is ${buf.length} bytes, over the ${MAX_UNZIP_BYTES} limit`);
  }
  const dir = await mkdtemp(path.join(tmpdir(), "scb-target-src-"));
  try {
    const zipPath = path.join(dir, "src.zip");
    await writeFile(zipPath, buf);

    // Unzip safely: reject absolute paths / traversal via unzip's own -d jail and
    // -qq; -o overwrite. (unzip refuses ../ escapes by default.)
    const src = path.join(dir, "src");
    const unz = await docker0("unzip", ["-o", "-qq", zipPath, "-d", src]);
    if (unz.code !== 0) throw new Error(`could not unzip target source: ${unz.stderr.trim()}`);

    const build = await docker(["build", "-t", tag, "."], { cwd: src, timeoutMs: BUILD_TIMEOUT_MS });
    if (build.code !== 0) {
      throw new Error(`docker build failed: ${(build.stderr || build.stdout).trim().slice(-1500)}`);
    }
    return { tag };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

// small helper to run a non-docker binary (unzip) with the same shape
async function docker0(bin, args) {
  try {
    const { stdout, stderr } = await pexec(bin, args, { maxBuffer: 16 * 1024 * 1024 });
    return { code: 0, stdout, stderr };
  } catch (e) {
    return { code: e.code ?? 1, stdout: e.stdout ?? "", stderr: e.stderr ?? String(e.message ?? e) };
  }
}

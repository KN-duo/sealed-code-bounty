import { createHash } from "crypto";
import { createReadStream } from "fs";
import { execFile } from "child_process";

/** Promisified execFile that never touches a shell (no injection surface). */
export function run(
  cmd: string,
  args: string[],
  opts: { quiet?: boolean } = {}
): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { maxBuffer: 64 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) {
        const tail = String(stderr).trim().split("\n").slice(-4).join("\n");
        reject(new Error(`${cmd} ${args.join(" ")} failed: ${err.message}\n${tail}`));
        return;
      }
      resolve({ stdout: String(stdout), stderr: String(stderr) });
    });
  });
}

export function sha256Hex(data: Buffer | string): string {
  return createHash("sha256").update(data).digest("hex");
}

/** Incremental sha256 of a file — used for tarballs too big for memory. */
export function sha256File(path: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const h = createHash("sha256");
    const s = createReadStream(path);
    s.on("data", (c) => h.update(c));
    s.on("end", () => resolve(h.digest("hex")));
    s.on("error", reject);
  });
}

/** Short deterministic build tag suffix from the Dockerfile contents. */
export function shortHash(data: string): string {
  return sha256Hex(data).slice(0, 12);
}

/** Only lowercase alphanumerics, dashes — safe for docker tags & filenames. */
export function sanitizeName(raw: string): string {
  const name = raw.toLowerCase().replace(/[^a-z0-9-]+/g, "-").replace(/^-+|-+$/g, "");
  if (!name) throw new Error(`--name "${raw}" reduces to an empty slug`);
  return name;
}

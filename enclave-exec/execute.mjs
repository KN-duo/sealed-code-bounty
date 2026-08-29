// The judging core: run a hunter's exploit against a live target in Docker, with
// a secret flag injected into the target at run time, and decide PASS/FAIL by
// whether the exploit's output captured that flag.
//
// This is the pre-TEE stand-in for what will run INSIDE the TEE. It is the one
// genuinely new capability behind the whole workflow; everything else (chain
// escrow, verdict signing, reveal) already exists. Same Docker mechanism the
// hunter-vm POC proved, hardened into a judge: the flag is generated here, the
// exploit runs isolated on a loopback-only network, and only its stdout is
// inspected for the flag.
//
// Usage (standalone, for testing on a Docker host):
//   node execute.mjs <exploit-file>
//   node execute.mjs ../examples/ret2win/solution/solve.py        -> PASS
//   node execute.mjs ../examples/ret2win/solution/solve-broken.py -> FAIL
//
// Exit code: 0 on PASS, 3 on FAIL, 1 on an execution error (couldn't judge).

import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";

const TARGET_IMAGE = process.env.SCB_TARGET_IMAGE ?? "scb-target";
const RUNTIME_IMAGE = process.env.SCB_RUNTIME_IMAGE ?? "scb-runtime";
const TARGET_PORT = Number(process.env.SCB_TARGET_PORT ?? 1337);
const EXPLOIT_TIMEOUT_S = Number(process.env.SCB_EXPLOIT_TIMEOUT_S ?? 60);
const DOCKER = process.env.SCB_DOCKER ?? "docker";

const pexec = promisify(execFile);

// Run docker, capturing output; never let a nonzero exit throw silently.
async function docker(args, { timeoutMs } = {}) {
  try {
    const { stdout, stderr } = await pexec(DOCKER, args, {
      timeout: timeoutMs,
      maxBuffer: 16 * 1024 * 1024,
    });
    return { code: 0, stdout, stderr };
  } catch (e) {
    return {
      code: typeof e.code === "number" ? e.code : 1,
      stdout: e.stdout ?? "",
      stderr: e.stderr ?? String(e.message ?? e),
      killed: Boolean(e.killed),
    };
  }
}

/**
 * Judge one exploit against the target.
 * @param {Uint8Array|Buffer} exploitBytes  the exploit file contents
 * @param {object} [opts]
 * @param {string} [opts.flag]  the secret flag to inject (default: random)
 * @returns {Promise<{pass:boolean, flag:string, output:string, reason:string}>}
 */
export async function judge(exploitBytes, opts = {}) {
  const flag = opts.flag ?? `flag{${randomBytes(16).toString("hex")}}`;
  const targetImage = opts.targetImage ?? TARGET_IMAGE; // per-bounty image, or the baked default
  const targetPort = opts.targetPort ?? TARGET_PORT;
  const copyBinary = opts.copyBinary ?? "/app/ret2win"; // convenience: give the exploit the target binary (null to skip)
  const uniq = randomBytes(8).toString("hex");
  const net = `scb-net-${uniq}`;
  const targetName = `scb-target-${uniq}`;
  const exploitName = `scb-exploit-${uniq}`;
  const work = await mkdtemp(path.join(tmpdir(), "scb-exec-"));

  const cleanup = async () => {
    await docker(["rm", "-f", exploitName]);
    await docker(["rm", "-f", targetName]);
    await docker(["network", "rm", net]);
    await rm(work, { recursive: true, force: true });
  };

  try {
    // 1. Loopback-only network: containers reach each other, nothing reaches out.
    const netRes = await docker(["network", "create", "--internal", net]);
    if (netRes.code !== 0) {
      return fail(flag, "", `could not create docker network: ${netRes.stderr.trim()}`);
    }

    // 2. Start the target, reachable as host "target" on the network.
    const tRes = await docker([
      "run", "-d", "--name", targetName,
      "--network", net, "--network-alias", "target",
      "--memory", "256m", "--cpus", "1",
      targetImage,
    ]);
    if (tRes.code !== 0) {
      return fail(flag, "", `could not start target (is ${targetImage} built?): ${tRes.stderr.trim()}`);
    }

    // 3. Inject the fresh secret flag into the running target.
    const injRes = await docker([
      "exec", targetName, "sh", "-c",
      `printf '%s\\n' '${flag}' > /flag && chmod 0644 /flag`,
    ]);
    if (injRes.code !== 0) {
      return fail(flag, "", `could not inject flag into target: ${injRes.stderr.trim()}`);
    }

    // 4. Give the target's socat listener a moment to bind. `docker run -d`
    //    returns when the container starts, not when the port is up, so a short
    //    fixed wait avoids a connect race (socat binds within milliseconds).
    await new Promise((res) => setTimeout(res, Number(process.env.SCB_TARGET_WARMUP_MS ?? 2000)));

    // 5. Provide the target binary to the exploit workdir (many exploits read
    //    symbols from it), and stage the submission. A submission is either a
    //    single python file or a ZIP (the product's format — an exploit can carry
    //    helpers/data). We detect the zip magic and, inside the sandbox, unpack
    //    it and run its entrypoint. entrypoint = `exploit.py` by default, or the
    //    "entrypoint" field of a top-level scb-exploit.json in the zip.
    if (copyBinary) {
      await docker(["cp", `${targetName}:${copyBinary}`, path.join(work, "ret2win")]).catch(() => {});
    }
    const bytes = Buffer.from(exploitBytes);
    const isZip = bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b &&
      (bytes[2] === 0x03 || bytes[2] === 0x05 || bytes[2] === 0x07);

    let runCmd;
    if (isZip) {
      await writeFile(path.join(work, "submission.zip"), bytes);
      // Unpack, read an optional entrypoint from scb-exploit.json, run it.
      const script =
        'set -e; ' +
        'mkdir -p /work/x && cd /work/x && unzip -o -qq /work/submission.zip; ' +
        'EP=exploit.py; ' +
        'if [ -f scb-exploit.json ]; then ' +
        '  EP=$(python3 -c "import json,sys; print(json.load(open(\\"scb-exploit.json\\")).get(\\"entrypoint\\",\\"exploit.py\\"))"); ' +
        'fi; ' +
        'cp -n /work/ret2win ./ret2win 2>/dev/null || true; ' +
        'exec timeout ' + EXPLOIT_TIMEOUT_S + ' python3 "$EP" target ' + targetPort;
      runCmd = ["sh", "-c", script];
    } else {
      await writeFile(path.join(work, "exploit.py"), bytes);
      runCmd = ["timeout", String(EXPLOIT_TIMEOUT_S), "python3", "exploit.py", "target", String(targetPort)];
    }

    // 6. Run the exploit, isolated, with a hard wall-clock timeout. It reaches
    //    the target as "target:1337".
    const run = await docker(
      [
        "run", "--rm", "--name", exploitName,
        "--network", net,
        "--memory", "512m", "--cpus", "1", "--pids-limit", "256",
        "-v", `${work}:/work`, "-w", "/work",
        RUNTIME_IMAGE,
        ...runCmd,
      ],
      { timeoutMs: (EXPLOIT_TIMEOUT_S + 15) * 1000 },
    );

    const output = `${run.stdout}${run.stderr}`;
    const pass = output.includes(flag);
    return {
      pass,
      flag,
      output,
      reason: pass
        ? "exploit output contained the injected flag"
        : run.killed
          ? "exploit timed out"
          : "exploit output did not contain the flag",
    };
  } finally {
    await cleanup();
  }
}

function fail(flag, output, reason) {
  return { pass: false, flag, output, reason };
}

// --- CLI -------------------------------------------------------------------

async function main() {
  const file = process.argv[2];
  if (!file) {
    console.error("usage: node execute.mjs <exploit-file>");
    process.exit(1);
  }
  const { readFile } = await import("node:fs/promises");
  const bytes = await readFile(file);
  process.stderr.write(`judging ${file} against ${TARGET_IMAGE} ...\n`);
  const res = await judge(bytes);
  process.stderr.write(`\n--- exploit output ---\n${res.output}\n----------------------\n`);
  if (res.pass) {
    console.log(`PASS — ${res.reason}`);
    process.exit(0);
  }
  console.log(`FAIL — ${res.reason}`);
  process.exit(3);
}

// Run as CLI only when invoked directly.
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => {
    console.error(`execution error: ${e?.message ?? e}`);
    process.exit(1);
  });
}

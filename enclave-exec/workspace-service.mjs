// Per-bounty practice environment: on request, spin up a hunter workspace — the
// bounty's target running next to a browser terminal (ttyd) with pwntools — so a
// hunter can develop their exploit live, then submit the finished one for judging.
//
// This is a DEV sandbox, separate from the enclave/judge: it injects a throwaway
// PRACTICE flag (never the real bounty flag), and the shell is unprivileged so a
// hunter must actually exploit the target to read it — same as the real thing.
//
//   node enclave-exec/workspace-service.mjs        # listens on :8080
//
// Endpoints (JSON):
//   POST /workspace        { bounty_pda } -> { id, url, expiresInS }
//   DELETE /workspace/:id  -> { ok }
//   GET  /healthz          -> { ok }
//
// The target image is scb-bounty-<pda12> when the enclave built one for the
// bounty, else the demo scb-target. Requires the scb-workspace image
// (enclave-exec/build.sh).

import http from "node:http";
import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { promisify } from "node:util";

const pexec = promisify(execFile);
const DOCKER = process.env.SCB_DOCKER ?? "docker";
const PORT = Number(process.env.SCB_WORKSPACE_PORT ?? 8080);
const WORKSPACE_IMAGE = process.env.SCB_WORKSPACE_IMAGE ?? "scb-workspace";
const DEFAULT_TARGET = process.env.SCB_TARGET_IMAGE ?? "scb-target";
const TTL_MS = Number(process.env.SCB_WORKSPACE_TTL_MS ?? 30 * 60 * 1000); // 30 min
const HOST = process.env.SCB_WORKSPACE_HOST ?? "http://localhost";

const sessions = new Map(); // id -> { net, target, shell, port, createdAt }

async function docker(args, opts = {}) {
  try {
    const { stdout, stderr } = await pexec(DOCKER, args, { timeout: opts.timeoutMs, maxBuffer: 8 * 1024 * 1024 });
    return { code: 0, stdout, stderr };
  } catch (e) {
    return { code: e.code ?? 1, stdout: e.stdout ?? "", stderr: e.stderr ?? String(e.message ?? e) };
  }
}
async function imageExists(image) {
  return (await docker(["image", "inspect", image])).code === 0;
}

async function startWorkspace(bountyPda) {
  const uniq = randomBytes(6).toString("hex");
  const net = `scb-ws-${uniq}`;
  const targetName = `scb-ws-target-${uniq}`;
  const shellName = `scb-ws-shell-${uniq}`;

  const perBounty = `scb-bounty-${String(bountyPda).slice(0, 12).toLowerCase()}`;
  const targetImage = (await imageExists(perBounty)) ? perBounty : DEFAULT_TARGET;

  const teardown = async () => {
    await docker(["rm", "-f", shellName]);
    await docker(["rm", "-f", targetName]);
    await docker(["network", "rm", net]);
  };

  try {
    let r = await docker(["network", "create", "--internal", net]);
    if (r.code !== 0) throw new Error(`network: ${r.stderr.trim()}`);

    // Target, reachable as "target".
    r = await docker([
      "run", "-d", "--name", targetName, "--network", net, "--network-alias", "target",
      "--memory", "256m", "--cpus", "1", targetImage,
    ]);
    if (r.code !== 0) throw new Error(`target (${targetImage}): ${r.stderr.trim()}`);

    // A throwaway PRACTICE flag — NOT the real bounty flag.
    const practiceFlag = `flag{practice_${randomBytes(6).toString("hex")}}`;
    await docker(["exec", targetName, "sh", "-c", `printf '%s\\n' '${practiceFlag}' > /flag && chmod 0644 /flag`]);

    // Shell with a random published host port for ttyd.
    r = await docker([
      "run", "-d", "--name", shellName, "--network", net,
      "-p", "127.0.0.1::7681", "--memory", "512m", "--cpus", "1", "--pids-limit", "256",
      WORKSPACE_IMAGE,
    ]);
    if (r.code !== 0) throw new Error(`shell (is ${WORKSPACE_IMAGE} built?): ${r.stderr.trim()}`);

    // Give the hunter the target binary to poke at, best-effort.
    await docker(["cp", `${targetName}:/app/ret2win`, "/tmp/scb-ws-bin-" + uniq]).catch(() => {});
    await docker(["cp", "/tmp/scb-ws-bin-" + uniq, `${shellName}:/root/target-binary`]).catch(() => {});

    // Let ttyd bind, then read the published host port from the container's own
    // port map (more reliable than parsing `docker port`).
    await new Promise((r) => setTimeout(r, 800));
    const insp = await docker([
      "inspect", "-f",
      '{{if .State.Running}}{{with index .NetworkSettings.Ports "7681/tcp"}}{{(index . 0).HostPort}}{{end}}{{else}}exited{{end}}',
      shellName,
    ]);
    const val = insp.stdout.trim();
    if (val === "exited" || val === "") {
      // The shell container died (or never published) — surface WHY.
      const logs = await docker(["logs", "--tail", "25", shellName]);
      const why = (logs.stdout + logs.stderr).trim().slice(-600) || val || "no output";
      throw new Error(`practice shell did not start (${WORKSPACE_IMAGE}). container log: ${why}`);
    }
    const port = Number(val);
    if (!Number.isFinite(port) || port <= 0) throw new Error(`unexpected published port: "${val}"`);

    const id = uniq;
    sessions.set(id, { net, target: targetName, shell: shellName, port, teardown, createdAt: Date.now() });
    return { id, url: `${HOST}:${port}`, expiresInS: Math.floor(TTL_MS / 1000), targetImage };
  } catch (e) {
    await teardown();
    throw e;
  }
}

// --- reaper ----------------------------------------------------------------
setInterval(async () => {
  const now = Date.now();
  for (const [id, s] of [...sessions]) {
    if (now - s.createdAt > TTL_MS) {
      await s.teardown();
      sessions.delete(id);
    }
  }
}, 60 * 1000).unref?.();

// --- http ------------------------------------------------------------------
const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET,POST,DELETE,OPTIONS",
  "access-control-allow-headers": "content-type",
};
function send(res, code, obj) {
  res.writeHead(code, { "content-type": "application/json", ...CORS });
  res.end(JSON.stringify(obj));
}

const server = http.createServer((req, res) => {
  if (req.method === "OPTIONS") { res.writeHead(204, CORS); return res.end(); }
  const url = new URL(req.url, "http://localhost");

  if (req.method === "GET" && url.pathname === "/healthz") return send(res, 200, { ok: true });

  if (req.method === "POST" && url.pathname === "/workspace") {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", async () => {
      try {
        const { bounty_pda } = JSON.parse(body || "{}");
        if (!bounty_pda) return send(res, 400, { error: "bounty_pda required" });
        const out = await startWorkspace(bounty_pda);
        send(res, 200, out);
      } catch (e) {
        send(res, 500, { error: "could not start workspace: " + String((e && e.message) || e) });
      }
    });
    return;
  }

  if (req.method === "DELETE" && url.pathname.startsWith("/workspace/")) {
    const id = url.pathname.slice("/workspace/".length);
    const s = sessions.get(id);
    if (!s) return send(res, 404, { error: "no such workspace" });
    s.teardown().finally(() => { sessions.delete(id); send(res, 200, { ok: true }); });
    return;
  }

  send(res, 404, { error: "not found" });
});

process.on("uncaughtException", (e) => console.error("workspace-service:", String(e)));
server.listen(PORT, "127.0.0.1", () => {
  console.log(`workspace-service on http://127.0.0.1:${PORT} (image ${WORKSPACE_IMAGE}, ttl ${TTL_MS / 60000}m)`);
});

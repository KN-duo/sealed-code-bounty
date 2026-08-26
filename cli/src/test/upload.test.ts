import { test } from "node:test";
import assert from "node:assert/strict";
import * as http from "http";
import type { AddressInfo } from "net";
import * as fs from "fs/promises";
import { loadR2Credentials, s3PutFile } from "../upload";

test("(B1) loadR2Credentials null when var missing", () => {
  const orig = { ...process.env };
  try {
    delete process.env.SCB_R2_ENDPOINT;
    assert.equal(loadR2Credentials(), null);
    process.env.SCB_R2_ENDPOINT = "https://x.r2.example.com";
    delete process.env.SCB_R2_BUCKET;
    assert.equal(loadR2Credentials(), null);
  } finally {
    Object.assign(process.env, orig);
  }
});

test("(B1) loadR2Credentials strips trailing slash", () => {
  const orig = { ...process.env };
  try {
    process.env.SCB_R2_ENDPOINT = "https://acct.r2.cloudflarestorage.com/";
    process.env.SCB_R2_BUCKET = "scb-envs";
    process.env.SCB_R2_ACCESS_KEY_ID = "k";
    process.env.SCB_R2_SECRET_KEY = "s";
    const c = loadR2Credentials();
    assert.ok(c);
    assert.equal(c.endpoint, "https://acct.r2.cloudflarestorage.com");
  } finally {
    Object.assign(process.env, orig);
  }
});

test("(B1) s3PutFile round-trip signed PUT to local S3-lookalike", async () => {
  const got = { auth: "", sha: "", body: Buffer.alloc(0) };
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      got.auth = String(req.headers.authorization ?? "");
      got.sha = String(req.headers["x-amz-content-sha256"] ?? "");
      got.body = Buffer.concat(chunks);
      res.writeHead(200);
      res.end();
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const addr = server.address() as AddressInfo;

  const tmp = await fs.mkdtemp("/tmp/scb-b1-");
  const tarPath = `${tmp}/env.tar.gz`;
  const payload = Buffer.from("fake-tarball-bytes-for-roundtrip-test");
  await fs.writeFile(tarPath, payload);

  const creds = {
    endpoint: `http://127.0.0.1:${addr.port}`,
    bucket: "test-bucket",
    accessKeyId: "test-key",
    secretAccessKey: "test-secret",
    region: "auto",
  };

  const result = await s3PutFile(creds, "scb/envs/abc.tar.gz", tarPath);

  assert.ok(got.auth.startsWith("AWS4-HMAC-SHA256"), got.auth);
  assert.match(got.auth, /Credential=test-key\//);
  assert.match(got.auth, /SignedHeaders=/);
  assert.match(got.auth, /Signature=[0-9a-f]{64}/);
  assert.ok(got.sha.length === 64 || got.sha === "UNSIGNED-PAYLOAD", `sha header: ${got.sha}`);
  assert.equal(result.sha256Hex.length, 64);
  assert.ok(got.body.equals(payload));
  assert.equal(
    result.remoteUrl,
    `http://127.0.0.1:${addr.port}/test-bucket/scb/envs/abc.tar.gz`
  );
  server.closeAllConnections?.();
  server.close();
});

test("(B1) non-2xx surfaces status in PackError", async () => {
  const server = http.createServer((_q, res) => {
    res.writeHead(403);
    res.end("denied");
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const addr = server.address() as AddressInfo;
  const tmp = await fs.mkdtemp("/tmp/scb-b1e-");
  const p = `${tmp}/f.bin`;
  await fs.writeFile(p, "x");

  const creds = {
    endpoint: `http://127.0.0.1:${addr.port}`,
    bucket: "b",
    accessKeyId: "k",
    secretAccessKey: "s",
    region: "auto",
  };
  await assert.rejects(
    s3PutFile(creds, "k.tar.gz", p),
    (err: unknown) =>
      err instanceof Error && err.name === "PackError" && /403/.test(err.message)
  );
  server.closeAllConnections?.();
  server.close();
});

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { buildManifest, manifestCanonicalJson, manifestSha256Hex, validateForm, downloadManifest } from "../src/lib/manifest.ts";
import { validateManifest } from "../../shared/manifest.mjs";

const fixture = JSON.parse(await readFile(new URL("../../fixtures/manifest-v2.json", import.meta.url), "utf8"));
const expected = JSON.parse(fixture.canonical);
const form = {
  name: expected.name,
  imageUrl: expected.image_tarball.url,
  imageSha256: expected.image_tarball.sha256,
  kind: "tcp_service",
  entrypoint: JSON.stringify(expected.entrypoint),
  port: 1337,
  memoryMb: 512,
  timeoutS: 60,
  deterministic: true,
  seed: 0,
  flagPlaceholder: "{{FLAG}}",
};

test("browser commits the same canonical bytes and digest as CLI and Rust", () => {
  const manifest = buildManifest(form);
  assert.deepEqual(validateForm(form), []);
  assert.equal(manifestCanonicalJson(manifest), fixture.canonical);
  assert.equal(manifestSha256Hex(manifest), fixture.sha256);
  assert.deepEqual(manifest.entrypoint, expected.entrypoint);
});

test("download contains exactly the bytes committed by the browser", async () => {
  const originalDocument = globalThis.document;
  const originalCreate = URL.createObjectURL;
  const originalRevoke = URL.revokeObjectURL;
  let downloaded;
  globalThis.document = { createElement: () => ({ click() {}, remove() {} }), body: { appendChild() {} } };
  URL.createObjectURL = (blob) => { downloaded = blob; return "blob:test"; };
  URL.revokeObjectURL = () => {};
  try {
    downloadManifest(buildManifest(form));
    assert.equal(await downloaded.text(), fixture.canonical);
  } finally {
    globalThis.document = originalDocument;
    URL.createObjectURL = originalCreate;
    URL.revokeObjectURL = originalRevoke;
  }
});

test("schema rejects unknown fields, shell strings, controls, Unicode and unbounded limits", () => {
  const invalid = [
    m => { m.extra = true; },
    m => { m.target.extra = true; },
    m => { m.entrypoint = "/bin/sh -c run"; },
    m => { m.entrypoint = []; },
    m => { m.entrypoint = ["", "run"]; },
    m => { m.entrypoint = ["run\ncommand"]; },
    m => { m.name = "challengé"; },
    m => { m.name = "x".repeat(4097); },
    m => { m.entrypoint = Array(65).fill("run"); },
    m => { m.target.host = "169.254.169.254"; },
    m => { m.target.port = 0; },
    m => { m.image_tarball.sha256 = "A".repeat(64); },
    m => { m.limits.timeout_seconds = 61; },
    m => { m.limits.memory_mb = 15; },
    m => { m.limits.cpus = 2; },
    m => { m.determinism.seed = 0.5; },
    m => { m.determinism.seed = 4294967296; },
    m => { m.flag_placeholder = "FLAG"; },
  ];
  for (const mutate of invalid) {
    const manifest = structuredClone(expected);
    mutate(manifest);
    assert.throws(() => validateManifest(manifest));
  }
  assert.ok(validateForm({ ...form, entrypoint: "./run.sh" }).length);
});

test("binary form preserves executable and arguments as separate strings", () => {
  const manifest = buildManifest({ ...form, kind: "binary", entrypoint: '["/app/bin", "one two", ""]' });
  assert.deepEqual(manifest.target, { kind: "binary", exec: "/app/bin", io: "stdio", argv: ["one two", ""] });
  manifest.entrypoint = ["/app/other"];
  assert.throws(() => validateManifest(manifest), /binary entrypoint must equal/);
});

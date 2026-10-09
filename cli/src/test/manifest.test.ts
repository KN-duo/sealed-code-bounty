import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { emitManifest, manifestCanonicalJson, validateManifest } from "../manifest";
import { renderCompose } from "../compose";

test("CLI emits the shared manifest commitment bytes, preserving argument boundaries", async () => {
  const fixture = JSON.parse(await readFile(join(__dirname, "../../../fixtures/manifest-v2.json"), "utf8"));
  const manifest = validateManifest(JSON.parse(fixture.canonical));
  assert.equal(manifestCanonicalJson(manifest), fixture.canonical);
  assert.equal(createHash("sha256").update(fixture.canonical).digest("hex"), fixture.sha256);
  const dir = await mkdtemp(join(tmpdir(), "scb-manifest-"));
  try {
    await emitManifest(join(dir, "manifest.json"), manifest);
    const bytes = await readFile(join(dir, "manifest.json"));
    assert.equal(bytes.toString(), fixture.canonical);
    assert.notEqual(bytes.at(-1), 10, "no newline is appended to committed bytes");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("compose uses the manifest argument array without a shell or image CMD suffix", async () => {
  const fixture = JSON.parse(await readFile(join(__dirname, "../../../fixtures/manifest-v2.json"), "utf8"));
  const manifest = validateManifest(JSON.parse(fixture.canonical));
  const off = renderCompose(manifest, "scb/challenge:test", "amd64");
  assert.ok(off.includes(`    entrypoint: ${JSON.stringify(["setarch", "x86_64", "-R", ...manifest.entrypoint])}\n    command: []`));
  manifest.determinism.aslr = "on";
  const on = renderCompose(manifest, "scb/challenge:test", "amd64");
  assert.ok(on.includes(`    entrypoint: ${JSON.stringify(manifest.entrypoint)}\n    command: []`));
});

import { test } from "node:test";
import assert from "node:assert/strict";
import { parseUploadResponse, submissionReference } from "../src/lib/submission.ts";

test("registers the upload receipt as the encrypted-record reference", () => {
  const receipt = "0123456789abcdef".repeat(4);
  assert.deepEqual(parseUploadResponse({ receipt }), { receipt });
  assert.equal(submissionReference(receipt), `scb:submission:v1:${receipt}`);
  assert.equal(submissionReference(receipt).length, 82);
});

test("rejects missing, legacy, malformed, and ambiguous upload responses", () => {
  const receipt = "a".repeat(64);
  for (const value of [
    null, undefined, [], "receipt", {}, { blob_url: receipt },
    { receipt, blob_url: "https://example.com/upload" },
    { receipt: 42 }, { receipt: "" }, { receipt: "a".repeat(63) },
    { receipt: "a".repeat(65) }, { receipt: "A".repeat(64) },
    { receipt: "g".repeat(64) }, { receipt: `${receipt}\n` },
    { receipt: `scb:submission:v1:${receipt}` },
    { receipt: `https://example.com/${receipt}` },
  ]) {
    assert.throws(() => parseUploadResponse(value), /invalid upload receipt/);
  }
});

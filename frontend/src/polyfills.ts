// Node globals that @solana/web3.js and @anchor-lang/core assume but the browser
// lacks. Imported first thing in main.tsx, before any Solana code runs.
import { Buffer } from "buffer";

declare global {
  // eslint-disable-next-line no-var
  var Buffer: typeof import("buffer").Buffer;
}

if (typeof globalThis.Buffer === "undefined") {
  globalThis.Buffer = Buffer;
}

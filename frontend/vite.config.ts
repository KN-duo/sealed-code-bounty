import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The runner/enclave lives on its own port. lib/runner.ts POSTs
// `content-type: application/json`, which is NOT a CORS-simple request, so a direct
// browser call to :8443 would send an OPTIONS preflight first — and the runner mounts
// no CORS layer and no OPTIONS handler (runner/src/routes.rs). Proxying through the dev
// server keeps every enclave call same-origin, so no preflight is ever emitted.
// Keep this prefix in sync with DEV_ENCLAVE_PREFIX in src/env.ts.
const ENCLAVE_PREFIX = "/enclave";
const ENCLAVE_TARGET = process.env.VITE_ENCLAVE_PROXY_TARGET ?? "http://127.0.0.1:8443";

// `global` shim: @solana/web3.js and its deps reference the Node `global`, which
// the browser lacks. Buffer itself is polyfilled in src/polyfills.ts.
export default defineConfig({
  plugins: [react()],
  define: {
    global: "globalThis",
  },
  server: {
    proxy: {
      [ENCLAVE_PREFIX]: {
        target: ENCLAVE_TARGET,
        changeOrigin: true,
        rewrite: (path) => path.replace(new RegExp(`^${ENCLAVE_PREFIX}`), ""),
      },
    },
  },
});

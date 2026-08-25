import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// `global` shim: @solana/web3.js and its deps reference the Node `global`, which
// the browser lacks. Buffer itself is polyfilled in src/polyfills.ts.
export default defineConfig({
  plugins: [react()],
  define: {
    global: "globalThis",
  },
});

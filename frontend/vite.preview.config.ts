import { fileURLToPath } from "node:url";
import path from "node:path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const here = path.dirname(fileURLToPath(import.meta.url));

// Isolate the public preview from developer .env files. Preview builds deliberately
// contain no RPC, program, enclave URL, or credentials.
export default defineConfig({
  root: path.join(here, "preview"),
  envDir: path.join(here, "preview-env"),
  plugins: [react()],
  define: {
    global: "globalThis",
  },
  build: { outDir: path.join(here, "dist"), emptyOutDir: true },
});

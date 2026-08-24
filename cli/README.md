# scb-pack

SealedCodeBounty challenge packager (`docs/BUILD_PLAN_v2.md` §4.2/§4.5).

```bash
npm install && npm run build
node dist/index.js <challenge-dir> --out out/ [options]
```

| Option | Default | Meaning |
|---|---|---|
| `--name` | dir slug | challenge name (lowercase `[a-z0-9-]`) |
| `--kind` | `tcp_service` | `tcp_service` \| `binary` |
| `--port` | 1337 | tcp_service listen port (manifest + compose expose) |
| `--exec` / `--arg` | — | binary kind: executable path / repeatable argv token |
| `--timeout-secs` / `--memory-mb` / `--cpus` | 60 / 512 / 1 | verification limits (manifest only at this stage) |
| `--aslr` | off | determinism block; `off` adds the setarch parity wrapper to the dev plane AND is what the verifier will use |
| `--seed` | 0 | exported as `SEED` to the target process |
| `--upload-url` | — | phase-2 storage hook; currently a NotImplemented stub |

Pipeline: `docker build` → static `/flag` check via `docker create`+`cp`
(the image is never executed) → `docker save | gzip` streamed to
`<sha256>.tar.gz` while hashing → `manifest.json` (schema v2) +
`docker-compose.yml` dev plane.

Exit codes: 0 ok · 2 usage · 3 docker missing · 4 flag invalid ·
5 upload not implemented · 6 build failed · 7 save failed.

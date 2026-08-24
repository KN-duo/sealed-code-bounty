# echo-service (sample challenge)

Trivially vulnerable demo target used to dogfood `scb-pack`.

**Behavior:** on each TCP connection to port 1337 the service prints `/flag`,
then echoes whatever it receives until EOF. The "vulnerability" is that the
flag is handed out — enough to exercise the full packager pipeline without
needing an actual bug.

## Pack

```bash
cli$ npm install && npm run build
cli$ node dist/index.js ../examples/echo-service --out out/
```

Outputs in `out/`:

| File | Purpose |
|---|---|
| `<sha256>.tar.gz` | `docker save`d image, gzip'd; name IS its sha256 |
| `manifest.json` | schema v2 (`docs/BUILD_PLAN_v2.md` §4.2), hash-committed on-chain |
| `docker-compose.yml` | dev plane: `target` service + pwntools workspace w/ ttyd on :7681 |

## Hunt locally

```bash
cd out && docker compose up -d
nc target 1337          # from inside the workspace container, or:
docker compose exec workspace nc target 1337
```

The dev replica carries the harmless `{{FLAG}}` placeholder; the real secret
only ever exists inside the verification enclave (two-plane rule).

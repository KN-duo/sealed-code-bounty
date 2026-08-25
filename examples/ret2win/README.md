# ret2win — minimal stack-overflow challenge (binary exploitation corpus #1)

Static (`-static`), no-PIE, no-canary `gcc -O0` build. Buffer overflow at 40 bytes
reaches `win()` which prints `/flag`. One process per connection (socat fork) so the
single verification run is deterministic.

- `flag` — contains the literal placeholder `{{FLAG}}` (packager asserts it)
- `solution/solve.py` — ground-truth exploit → must yield PASS
- `solution/solve-broken.py` — underflowing payload → must yield FAIL

Pack: `scb-pack examples/ret2win --name ret2win --port 1337 --aslr off --out out/`

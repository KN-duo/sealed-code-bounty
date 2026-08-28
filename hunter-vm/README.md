# Hunter VM (POC)

A single Docker image that gives you a **Linux terminal in the browser** where a
vulnerable target is already running — the pwn.college mechanism, self-contained.
You open a web page, get a shell, run an exploit against the target, and the flag
prints. Build and run this on a machine with Docker (your Linux box).

## Run it

```bash
# from the repo root
docker build -t scb-hunter-vm hunter-vm
docker run --rm -d -p 7681:7681 --name hunter-vm scb-hunter-vm
```

Open **http://localhost:7681** in a browser. You get a terminal, logged in as the
unprivileged `hunter` user, with `solve.py` already in the home directory.

In that browser terminal:

```bash
python3 solve.py localhost 1337
```

The exploit overflows the target, jumps to `win()`, and the flag prints:
`flag{hunter_vm_poc}`.

Prove it's real: try to read the flag directly — it fails, because only a working
exploit can leak it:

```bash
cat /flag        # Permission denied — the flag is root-only
```

## Teardown

```bash
docker rm -f hunter-vm
```

## What's inside

- **The target** (`target/ret2win.c`) — built static/no-pie, served on
  `localhost:1337` inside the container by socat, running as root so it can read
  the root-only `/flag`.
- **ttyd** — serves the browser terminal on `:7681`, running a shell as the
  unprivileged `hunter` user (so `cat /flag` is denied; the exploit is the only
  way).
- **pwntools + solve.py** — a working starting-point exploit.

## This is a POC

One image, one baked-in flag, minimal isolation, and the container is fairly
permissive. It proves the in-browser-VM mechanism. Turning it into real product —
one fresh VM per hunter per bounty, the target pulled from the bounty's manifest,
and proper sandboxing (dropped capabilities, seccomp, no external network,
memory/CPU/pid limits, per-session flags) — is planned in
[`../docs/hunter-vm-plan.md`](../docs/hunter-vm-plan.md).

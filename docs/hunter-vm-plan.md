# Plan: in-browser hunter VM (workspace)

**Goal.** When a hunter opens a bounty, they get a live Linux terminal in the
browser, with the vulnerable target running, where they write and run their
exploit and it **executes on that container's OS** — exactly like a CTF. This
is a *workspace* only; it does not decide the bounty payout (that stays a
separate decision).

**Model, borrowed from pwn.college/dojo** (`dojo_plugin/api/v1/docker.py`,
`workspace/services/terminal.nix`): a per-session Docker container runs **ttyd**
(a terminal served over WebSocket), the target is inside it, and the browser
embeds that terminal. dojo's version is a large multi-node Flask app; we need a
small fraction of it.

**Stack decision:** a new **Node/TypeScript** service (`workspace-service/`).
Matches the relayer, cli, and frontend; simplest to drive and maintain. It is a
NEW top-level component in no existing lane — coordinate before it lands, and it
must run on a host with Docker (the Linux test box, not the Windows checkout).

---

## Architecture

```
browser (React)  ──embeds──►  ttyd terminal (WebSocket)
      │                              ▲
      │ POST /session {bountyPda}    │ proxied
      ▼                              │
 workspace-service (Node) ──docker run──► session container
                                          ├─ target service running
                                          ├─ /exploit workdir (hunter's files)
                                          └─ ttyd on :7681 + a login shell
```

- The service exposes `POST /session` → starts a container from the target
  image, launches ttyd inside it, returns a URL/token the frontend embeds.
- `DELETE /session/:id` (and an idle timeout) tears the container down.
- The frontend renders the terminal in an `<iframe>` (ttyd serves its own web
  UI) — the least-effort embed; xterm.js + a WS proxy is the fancier option and
  is deferred.

---

## Smallest real milestone (build this first)

**One container running the ret2win target + a shell + ttyd, embedded in the
frontend, where you run `solve.py` and watch the flag print.** No Solana, no
enclave, no per-bounty dynamism. If this works, "one per bounty on demand" is
mechanical.

Pieces:
1. **Workspace image** — extend `runner/runtime.Dockerfile`'s idea: a Dockerfile
   with the target build + pwntools + **ttyd** + a shell, target auto-started.
   For the POC it can bake in ret2win directly.
2. **workspace-service** (Node) — `POST /session` does `docker run -d -p <hostport>:7681`
   the image, returns `{ url: "http://localhost:<hostport>" }`; `DELETE` removes
   it; an idle reaper kills stale containers. Docker via `dockerode` or by
   shelling out to `docker` (no new heavy deps — mirror how the Rust runner
   shells out).
3. **Frontend** — on the hunt page, a "Open workspace" button calls the service
   and renders the returned URL in a sandboxed `<iframe>`. Lane C.

**Done when:** on the Linux box, opening the hunt page, clicking Open workspace,
and typing `python3 solve.py` in the browser terminal runs the exploit against
the live target and prints the flag.

---

## Then (later phases)
- Per-bounty: pull the target image from the bounty's manifest tarball instead
  of baking ret2win in — reuses the same tarball the real-execution plan fetches.
- Upload the hunter's exploit file into the container (or let them paste/edit in
  the terminal).
- Auth/rate-limit sessions; one workspace per hunter; resource caps
  (`--memory`, `--cpus`, `--pids-limit`), no-network or loopback-only, non-root,
  seccomp — mirror dojo's container hardening (`docker.py` security_opt/cap set).
- Optional: replace the iframe with xterm.js + a WebSocket proxy for a native
  feel and tighter control.

## Security notes (do not skip when it goes beyond POC)
The container runs untrusted hunter code. dojo runs each challenge non-root with
a seccomp profile, dropped caps, a locked-down network, and resource rlimits.
The POC can be permissive on a local box, but any shared/hosted deployment needs
that hardening first — call it out, don't silently ship a root container with a
socket to the daemon.

## Relationship to the other plan
Independent of `real-execution-plan.md`. That one makes the *enclave* judge
exploits for payout; this one gives *hunters* a place to develop them. They share
the target-image/tarball pipeline but nothing else, and can proceed in parallel.
```

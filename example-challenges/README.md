# Example challenges — ready to post as bounties

Three original, classic-style vulnerable targets, each following the target
conventions the verifier expects:

- serve the vulnerable service on TCP **1337**;
- keep the secret at **/flag**, root-owned and not world-readable, so only a
  working exploit can leak it (the verifier injects a fresh random flag there for
  each judging run).

| dir | vuln | difficulty | intended solve |
| --- | --- | --- | --- |
| `injection/` | command injection (`os.system` with user input) | easy | send `; cat /flag` |
| `baby-auth/` | stack overflow flips an `authed` flag | easy–medium | send 40 bytes |
| `ret2win/` | buffer overflow → redirect to `win()` | medium | 40 bytes + `&win` |

Each has a `solution/solve.py` — a working exploit you (or a hunter) can drop
into the submit console or develop in the test environment.

## Post one as a bounty

These live in this GitHub repo, so you can point a bounty straight at a subdir —
no separate upload needed. In the Post-a-bounty wizard's **Target from GitHub**
field, enter (replace with your repo owner/name):

```
KN-duo/sealed-code-bounty#example-challenges/injection
KN-duo/sealed-code-bounty#example-challenges/baby-auth
KN-duo/sealed-code-bounty#example-challenges/ret2win
```

Set the service port to **1337**, write a title/description, and post. The
verifier clones the repo, builds that subdir's Dockerfile, and judges exploits
against it. A hunter can open the test environment to develop against the live
target, then submit `solution/solve.py`.

## Writing your own

Copy any of these as a template. The only hard rules are the two conventions
above (serve on a port, root-only `/flag`). Everything else — language, service,
vulnerability — is up to you.

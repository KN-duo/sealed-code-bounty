#!/bin/sh
# Hunter-VM entrypoint. Two things run in this container:
#   1. the vulnerable target, served on loopback :1337 as ROOT so it can read
#      the root-only /flag — the hunter reaches it over TCP but cannot read the
#      flag file directly;
#   2. ttyd, the browser terminal on :7681, running an UNPRIVILEGED shell as the
#      `hunter` user, so `cat /flag` fails and only a working exploit leaks it.
set -e

# 1. target service in the background (root). One fresh process per connection.
socat TCP-LISTEN:1337,reuseaddr,fork EXEC:"/app/ret2win",pty,raw,echo=0 &

# 2. browser terminal as the unprivileged hunter user.
#    ttyd flags: -p port, -i interface, -W writable (accept keyboard input).
exec setpriv --reuid=hunter --regid=hunter --init-groups \
    ttyd -p 7681 -i 0.0.0.0 -W bash --login

#!/bin/sh
# One fresh process per connection => deterministic single-run verification (D13).
exec socat TCP-LISTEN:1337,reuseaddr,fork EXEC:"/app/ret2win",pty,raw,echo=0

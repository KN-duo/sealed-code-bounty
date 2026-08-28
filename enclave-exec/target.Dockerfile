# The vulnerable TARGET image for judging. ret2win served on :1337.
# /flag holds a placeholder at build time; the executor overwrites it with a
# fresh per-run secret before the exploit connects, so the flag is never baked
# into a distributable image.
FROM ubuntu:24.04
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      gcc libc6-dev socat \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY target-ret2win.c /app/src/ret2win.c
# NOT stripped: an exploit may want the symbol table.
RUN gcc -static -no-pie -fno-stack-protector -O0 -o /app/ret2win /app/src/ret2win.c \
 && chmod 0755 /app/ret2win
RUN printf 'flag{placeholder-overwritten-at-runtime}\n' > /flag && chmod 0644 /flag
# One fresh process per connection (deterministic single-run verification).
RUN printf '#!/bin/sh\nexec socat TCP-LISTEN:1337,reuseaddr,fork EXEC:/app/ret2win,pty,raw,echo=0\n' \
      > /app/serve.sh \
 && chmod +x /app/serve.sh
EXPOSE 1337
ENTRYPOINT ["/app/serve.sh"]

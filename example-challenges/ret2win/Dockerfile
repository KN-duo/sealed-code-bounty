# Classic ret2win. Overflow a 32-byte buffer, redirect execution to win(), which
# prints /flag. Convention: serve on 1337; secret at root-only /flag. NOT stripped
# so an exploit can resolve win() by symbol.
FROM ubuntu:24.04
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends gcc libc6-dev socat \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY ret2win.c /app/src/ret2win.c
RUN gcc -static -no-pie -fno-stack-protector -O0 -o /app/ret2win /app/src/ret2win.c && chmod 0755 /app/ret2win
RUN printf 'flag{placeholder-overwritten-per-run}\n' > /flag && chown root:root /flag && chmod 0400 /flag
RUN printf '#!/bin/sh\nexec socat TCP-LISTEN:1337,reuseaddr,fork EXEC:/app/ret2win,pty,raw,echo=0\n' \
      > /app/serve.sh && chmod +x /app/serve.sh
EXPOSE 1337
ENTRYPOINT ["/app/serve.sh"]

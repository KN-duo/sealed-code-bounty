# Auth-bypass overflow. A 32-byte password buffer sits before an `authed` field;
# overflowing the buffer flips authed non-zero and unlocks /flag. Convention:
# serve on 1337; secret at root-only /flag.
FROM ubuntu:24.04
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends gcc libc6-dev socat \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY baby.c /app/src/baby.c
RUN gcc -static -no-pie -fno-stack-protector -O0 -o /app/baby /app/src/baby.c && chmod 0755 /app/baby
RUN printf 'flag{placeholder-overwritten-per-run}\n' > /flag && chown root:root /flag && chmod 0400 /flag
RUN printf '#!/bin/sh\nexec socat TCP-LISTEN:1337,reuseaddr,fork EXEC:/app/baby,pty,raw,echo=0\n' \
      > /app/serve.sh && chmod +x /app/serve.sh
EXPOSE 1337
ENTRYPOINT ["/app/serve.sh"]

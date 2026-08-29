# Command-injection challenge. A "ping service" concatenates user input straight
# into a shell command. Convention: serve on 1337; secret at root-only /flag.
FROM ubuntu:24.04
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 socat \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY serve.py /app/serve.py
RUN printf 'flag{placeholder-overwritten-per-run}\n' > /flag \
 && chown root:root /flag && chmod 0400 /flag
RUN printf '#!/bin/sh\nexec socat TCP-LISTEN:1337,reuseaddr,fork EXEC:"python3 /app/serve.py",pty,raw,echo=0\n' \
      > /app/serve.sh && chmod +x /app/serve.sh
EXPOSE 1337
ENTRYPOINT ["/app/serve.sh"]

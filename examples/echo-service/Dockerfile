# SealedCodeBounty sample challenge: TCP echo service that leaks /flag first.
# Connect on 1337 -> server prints /flag, then echoes everything you send.
FROM ubuntu:24.04

RUN apt-get update \
 && apt-get install -y --no-install-recommends socat \
 && rm -rf /var/lib/apt/lists/*

COPY flag /flag
COPY serve.sh /usr/local/bin/serve
RUN chmod 755 /usr/local/bin/serve

EXPOSE 1337
CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:/usr/local/bin/serve"]

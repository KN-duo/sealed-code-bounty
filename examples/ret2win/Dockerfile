FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends gcc socat && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY src/ /app/src/
RUN gcc -static -no-pie -fno-stack-protector -O0 -o /app/ret2win /app/src/ret2win.c && strip /app/ret2win
COPY flag /flag
COPY serve.sh /app/serve.sh
RUN chmod +x /app/serve.sh
EXPOSE 1337
ENTRYPOINT ["/app/serve.sh"]

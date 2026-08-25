# Exploit runtime image used by the DockerCli sandbox executor.
# Build ONCE per machine:
#   docker build -t scb/exploit-runtime:latest -f runner/runtime.Dockerfile runner/
FROM ubuntu:24.04

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      python3 python3-pip util-linux netcat-openbsd socat \
 && pip install --break-system-packages pwntools \
 && rm -rf /var/lib/apt/lists/*

# setarch comes from util-linux (D13 ASLR-off personality support).
WORKDIR /work
CMD ["sleep", "infinity"]

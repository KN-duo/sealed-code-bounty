# The exploit RUNTIME image: where the hunter's exploit runs, isolated from the
# target on a loopback-only network. pwntools + setarch (for ASLR-off parity).
FROM ubuntu:24.04
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      python3 python3-pip util-linux unzip ca-certificates \
 && pip install --break-system-packages pwntools \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /work
CMD ["sleep", "infinity"]

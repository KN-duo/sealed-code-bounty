# The hunter's PRACTICE shell image: a browser terminal (ttyd) with pwntools and
# editors, used to develop an exploit against a bounty's target. The target runs
# in a SEPARATE container on the same network (reachable as "target"), so /flag
# lives in the target, not here — the hunter must still exploit it over the
# network. That's why this shell can run as root without weakening anything.
FROM ubuntu:24.04
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      python3 python3-pip ttyd socat util-linux vim nano less unzip curl ca-certificates \
 && pip install --break-system-packages pwntools \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /root
EXPOSE 7681
# A writable browser terminal serving a login shell. `ttyd` is resolved via PATH.
ENTRYPOINT ["ttyd", "-p", "7681", "-i", "0.0.0.0", "-W", "bash", "-l"]

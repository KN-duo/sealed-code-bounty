# The hunter's PRACTICE shell image: a browser terminal (ttyd) with pwntools and
# editors, used to develop an exploit against a bounty's target. The target runs
# in a SEPARATE container on the same network (reachable as "target"); this image
# is just the workspace, so it works for any bounty's target.
#
# NOTE: this is a development sandbox, not the judge. Its injected flag is a
# throwaway PRACTICE flag, never the real bounty flag.
FROM ubuntu:24.04
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      python3 python3-pip ttyd socat util-linux vim nano less unzip curl ca-certificates \
 && pip install --break-system-packages pwntools \
 && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash hunter
WORKDIR /home/hunter
EXPOSE 7681
# ttyd serves a login shell as the unprivileged hunter user.
ENTRYPOINT ["/usr/bin/ttyd", "-p", "7681", "-i", "0.0.0.0", "-W", \
            "setpriv", "--reuid=hunter", "--regid=hunter", "--init-groups", \
            "env", "HOME=/home/hunter", "USER=hunter", "TERM=xterm-256color", \
            "bash", "--login"]

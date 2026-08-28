# Hunter-VM POC: one image = the ret2win target + pwntools + ttyd (browser
# terminal). Run it and open http://localhost:7681 to get a Linux shell in the
# browser where you run an exploit against the live target — the pwn.college
# mechanism, self-contained.
#
# POC ONLY: single baked-in flag, minimal isolation. Hosted/multi-user use needs
# the hardening in docs/hunter-vm-plan.md (per-session containers, dropped caps,
# seccomp, network lockdown, resource limits).
FROM ubuntu:24.04

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      gcc socat python3 python3-pip ttyd tmux less vim-tiny util-linux ca-certificates \
 && pip install --break-system-packages pwntools \
 && rm -rf /var/lib/apt/lists/*

# --- build the vulnerable target (static, no-pie: win() address is link-fixed) --
WORKDIR /app
COPY target/ret2win.c /app/src/ret2win.c
RUN gcc -static -no-pie -fno-stack-protector -O0 -o /app/ret2win /app/src/ret2win.c \
 && strip /app/ret2win \
 && chmod 0755 /app/ret2win

# --- the secret flag: readable only by root, so the hunter must exploit for it --
RUN printf 'flag{hunter_vm_poc}\n' > /flag \
 && chown root:root /flag \
 && chmod 0400 /flag

# --- unprivileged hunter user with a starting-point exploit in their home -------
RUN useradd -m -s /bin/bash hunter
COPY solve.py /home/hunter/solve.py
RUN chown -R hunter:hunter /home/hunter

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 7681
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

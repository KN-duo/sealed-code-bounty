# Exploit runtime image used by the Docker/Podman sandbox executor.
# Build from the repository root (the shared snapshot inputs are under nitro/):
#   docker build --platform linux/amd64 -t scb-runtime:locked -f runner/runtime.Dockerfile .
FROM public.ecr.aws/ubuntu/ubuntu@sha256:5ce7043d3beb84e91bfeecacb5fafc80602bf247a1dd6016bc0fe7d69d707eca

COPY nitro/ubuntu-snapshot.sources /etc/apt/scb-ubuntu.sources
COPY nitro/ubuntu-snapshot-ca.pem /usr/share/scb-build/
COPY runner/runtime/apt.lock runner/runtime/requirements.lock /usr/share/scb-build/
RUN rm -f /etc/apt/sources.list /etc/apt/sources.list.d/* \
 && mv /etc/apt/scb-ubuntu.sources /etc/apt/sources.list.d/ubuntu.sources \
 && apt-get -o Acquire::https::CaInfo=/usr/share/scb-build/ubuntu-snapshot-ca.pem \
      -o Acquire::Languages=none update --error-on=any \
 && DEBIAN_FRONTEND=noninteractive xargs -r apt-get \
      -o Acquire::https::CaInfo=/usr/share/scb-build/ubuntu-snapshot-ca.pem \
      install -y --no-install-recommends </usr/share/scb-build/apt.lock \
 && dpkg-query -W | tr '\t' '=' | LC_ALL=C sort >/tmp/installed-apt.lock \
 && cmp /usr/share/scb-build/apt.lock /tmp/installed-apt.lock \
 && rm /tmp/installed-apt.lock \
 && python3 -m pip --isolated install --index-url https://pypi.org/simple \
      --break-system-packages --ignore-installed --no-cache-dir --no-compile \
      --require-hashes --no-deps --only-binary=:all: \
      --requirement /usr/share/scb-build/requirements.lock \
 && rm -rf /var/lib/apt/lists/*

# setarch comes from util-linux (D13 ASLR-off personality support).
WORKDIR /work
CMD ["sleep", "infinity"]

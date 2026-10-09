# Application image consumed by `nitro-cli build-enclave`.
# The script that assembles this build context must provide the release runner,
# AWS kmstool_enclave_cli + libnsm.so, and the Docker-save exploit runtime.
FROM public.ecr.aws/ubuntu/ubuntu@sha256:5ce7043d3beb84e91bfeecacb5fafc80602bf247a1dd6016bc0fe7d69d707eca

COPY nitro/ubuntu-snapshot.sources /etc/apt/scb-ubuntu.sources
COPY nitro/ubuntu-snapshot-ca.pem nitro/enclave-apt.lock /usr/share/scb-build/
# The minimal base has no CA bundle. Bootstrap TLS with the checked-in public
# ISRG roots; APT independently authenticates every index/package with Ubuntu's
# archive keyring. Never fall back to live repositories or unsigned indexes.
RUN rm -f /etc/apt/sources.list /etc/apt/sources.list.d/* \
 && mv /etc/apt/scb-ubuntu.sources /etc/apt/sources.list.d/ubuntu.sources \
 && apt-get -o Acquire::https::CaInfo=/usr/share/scb-build/ubuntu-snapshot-ca.pem \
      -o Acquire::Languages=none update --error-on=any \
 && DEBIAN_FRONTEND=noninteractive xargs -r apt-get \
      -o Acquire::https::CaInfo=/usr/share/scb-build/ubuntu-snapshot-ca.pem \
      install -y --no-install-recommends </usr/share/scb-build/enclave-apt.lock \
 && dpkg-query -W | tr '\t' '=' | LC_ALL=C sort >/tmp/installed-apt.lock \
 && cmp /usr/share/scb-build/enclave-apt.lock /tmp/installed-apt.lock \
 && rm /tmp/installed-apt.lock \
 && rm -rf /var/lib/apt/lists/*

RUN printf 'root:100000:65536\n' >/etc/subuid \
 && printf 'root:100000:65536\n' >/etc/subgid \
 && install -d -m 0700 /run/user/0 \
 && install -d -m 0755 /etc/containers \
 && install -d -m 0755 /app/lib \
 && install -d -m 0700 /var/lib/scb-runner

# AWS Nitro CLI's pinned 4.14 x86_64 guest kernel has iptables support but
# CONFIG_NF_TABLES is disabled. Force netavark to use the supported backend.
RUN printf '[network]\nnetwork_backend="netavark"\nfirewall_driver="iptables"\n' \
      >/etc/containers/containers.conf \
 && printf '[engine]\ncgroup_manager="cgroupfs"\nevents_logger="none"\n' \
      >>/etc/containers/containers.conf \
 && printf '[containers]\nlog_driver="k8s-file"\nlog_size_max=65536\n' \
      >>/etc/containers/containers.conf \
 && rm -f /etc/cni/net.d/87-podman-bridge.conflist
RUN update-alternatives --set iptables /usr/sbin/iptables-legacy \
 && update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy \
 && iptables --version | grep -q legacy \
 && ip6tables --version | grep -q legacy

WORKDIR /app
COPY scb-runner /app/scb-runner
COPY kmstool_enclave_cli /app/kmstool_enclave_cli
COPY libnsm.so /app/lib/libnsm.so
COPY scb-exploit-runtime.tar /app/scb-exploit-runtime.tar
COPY nitro/protocol.py nitro/storage_protocol.py nitro/kms_bootstrap_client.py \
     nitro/storage_client.py nitro/enclave_proxy.py nitro/deny-vsock-seccomp.json /app/nitro/
COPY enclave-entrypoint.sh /app/enclave-entrypoint.sh

RUN chmod 0555 /app/scb-runner /app/kmstool_enclave_cli \
      /app/nitro/kms_bootstrap_client.py /app/nitro/storage_client.py \
      /app/enclave-entrypoint.sh \
 && chmod 0444 /app/nitro/*.py /app/nitro/deny-vsock-seccomp.json

ENV AWS_REGION=eu-north-1 \
    PORT=8443 \
    SCB_SANDBOX=podman \
    SCB_PODMAN_CLI=/usr/bin/podman \
    SCB_PODMAN_SUBUID_START=100000 \
    SCB_SECCOMP_PROFILE=/app/nitro/deny-vsock-seccomp.json \
    SCB_RUNTIME_IMAGE=scb-runtime:latest \
    SCB_SUBMISSION_STORE=vsock \
    SCB_STORAGE_HELPER=/app/nitro/storage_client.py \
    SCB_STORAGE_VSOCK_PORT=5001 \
    SCB_WORK_DIR=/var/lib/scb-runner \
    LD_LIBRARY_PATH=/app/lib

ENTRYPOINT ["/app/enclave-entrypoint.sh"]

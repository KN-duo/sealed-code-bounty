FROM public.ecr.aws/ubuntu/ubuntu@sha256:5ce7043d3beb84e91bfeecacb5fafc80602bf247a1dd6016bc0fe7d69d707eca
COPY ubuntu-snapshot.sources /etc/apt/scb-snapshot.sources
COPY ubuntu-snapshot-ca.pem /etc/apt/scb-snapshot-ca.pem
COPY kms-build-apt.lock /inputs/kms-build-apt.lock
RUN rm -f /etc/apt/sources.list /etc/apt/sources.list.d/* \
 && cp /etc/apt/scb-snapshot.sources /etc/apt/sources.list.d/scb.sources \
 && apt-get -o Acquire::https::CaInfo=/etc/apt/scb-snapshot-ca.pem update --error-on=any \
 && DEBIAN_FRONTEND=noninteractive xargs -r -a /inputs/kms-build-apt.lock \
      apt-get -o Acquire::https::CaInfo=/etc/apt/scb-snapshot-ca.pem install -y --no-install-recommends \
 && dpkg-query -W -f='${binary:Package}=${Version}\n' | LC_ALL=C sort >/tmp/installed.lock \
 && cmp /inputs/kms-build-apt.lock /tmp/installed.lock \
 && rm -rf /var/lib/apt/lists/*
COPY kms-sources.lock.json /inputs/kms-sources.lock.json
RUN python3 -c 'import json; p=json.load(open("/inputs/kms-sources.lock.json")); print(p["rust_version"],p["rust_archive_sha256"])' >/tmp/rust.lock \
 && read rust_version rust_sha </tmp/rust.lock \
 && curl --fail --show-error --location --proto '=https' --tlsv1.2 \
      "https://static.rust-lang.org/dist/rust-${rust_version}-x86_64-unknown-linux-gnu.tar.xz" -o /tmp/rust.tar.xz \
 && echo "$rust_sha  /tmp/rust.tar.xz" | sha256sum -c - \
 && mkdir /tmp/rust \
 && tar -xf /tmp/rust.tar.xz --strip-components=1 -C /tmp/rust \
 && /tmp/rust/install.sh --prefix=/opt/rust --components=rustc,cargo,rust-std-x86_64-unknown-linux-gnu --disable-ldconfig \
 && rm -rf /tmp/rust /tmp/rust.tar.xz
ENV PATH=/opt/rust/bin:$PATH CARGO_HOME=/opt/cargo GOTOOLCHAIN=local \
    SOURCE_DATE_EPOCH=1700000000 TZ=UTC LC_ALL=C \
    CFLAGS="-ffile-prefix-map=/build=. -fdebug-prefix-map=/build=." \
    CXXFLAGS="-ffile-prefix-map=/build=. -fdebug-prefix-map=/build=." \
    RUSTFLAGS="--remap-path-prefix=/build=. --remap-path-prefix=/opt/cargo=.cargo"
ADD sources.tar /build/
COPY kms-nsm-Cargo.lock /build/aws-nitro-enclaves-nsm-api/Cargo.lock
RUN cargo fetch --locked --manifest-path /build/aws-nitro-enclaves-nsm-api/Cargo.toml
COPY kms-compile.sh /inputs/kms-compile.sh
COPY context-sha256.json /inputs/context-sha256.json
COPY prepared-source-sha256.json /inputs/prepared-source-sha256.json
ENTRYPOINT ["/bin/bash", "/inputs/kms-compile.sh"]

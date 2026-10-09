# Dependency acquisition happens before this Dockerfile, using cargo vendor.
# This compilation stage must be invoked with docker build --network=none.
FROM public.ecr.aws/docker/library/rust:1.89.0-slim-bookworm@sha256:d7fc7de78bb8c1469933aeecbf801314d30d7d6e9f0578bba4cfa285bfa37fe6 AS compile

ARG SCB_BUILD_COMMIT
ARG SOURCE_DATE_EPOCH
ENV SCB_BUILD_COMMIT=${SCB_BUILD_COMMIT} \
    SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} \
    CARGO_INCREMENTAL=0 \
    CARGO_BUILD_JOBS=2 \
    TZ=UTC \
    LC_ALL=C \
    RUSTFLAGS="-C target-cpu=x86-64 --remap-path-prefix=/src=/scb/source --remap-path-prefix=/usr/local/cargo=/scb/cargo"

WORKDIR /src/runner
COPY runner/ /src/runner/
COPY vendor/ /src/vendor/
COPY cargo-config.toml /usr/local/cargo/config.toml

RUN cargo build --release --target x86_64-unknown-linux-gnu \
      --offline --locked --no-default-features --bin scb-runner \
    && mkdir /out \
    && install -m 0555 target/x86_64-unknown-linux-gnu/release/scb-runner /out/scb-runner \
    && rustc --version --verbose > /out/compiler.txt \
    && cargo --version > /out/cargo.txt

FROM scratch AS artifacts
COPY --from=compile /out/ /

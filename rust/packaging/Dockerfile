# syntax=docker/dockerfile:1
# Build on the selected platform; this is not a cross-compilation image.
# Set RUST_IMAGE to a rust:bookworm digest for a pinned toolchain/base image.
ARG RUST_IMAGE=rust:bookworm
FROM ${RUST_IMAGE} AS build
RUN apt-get update \
    && apt-get install --yes --no-install-recommends python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
ARG SOURCE_REVISION=unknown
RUN python3 rust/packaging/package.py build --output /out --revision "${SOURCE_REVISION}" \
    && mkdir /image \
    && tar -xzf /out/Xray-rust-partial-*.tar.gz --strip-components=1 -C /image

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates libgcc-s1 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /usr/local/etc/xray
COPY --from=build /image/ /opt/xray-rust/
ARG SOURCE_REVISION=unknown
LABEL org.opencontainers.image.title="Xray native Rust partial migration" \
    org.opencontainers.image.description="Experimental native Rust CLI; full Go feature and platform parity is not established." \
    org.opencontainers.image.licenses="MPL-2.0" \
    org.opencontainers.image.source="https://github.com/XTLS/Xray-core" \
    org.opencontainers.image.revision="${SOURCE_REVISION}"
USER 65532:65532
WORKDIR /usr/local/etc/xray
ENTRYPOINT ["/opt/xray-rust/xray"]
CMD ["version"]

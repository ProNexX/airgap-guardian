# Offline build: run `cargo vendor vendor` once (on a connected machine) before building.
FROM docker.io/library/rust:1-bookworm AS builder

WORKDIR /build
COPY vendor ./vendor
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN mkdir -p .cargo \
    && printf '%s\n' \
        '[source.crates-io]' \
        'replace-with = "vendored-sources"' \
        '' \
        '[source.vendored-sources]' \
        'directory = "vendor"' \
        > .cargo/config.toml \
    && cargo build --release --locked --offline

FROM docker.io/library/debian:bookworm-slim

COPY --from=builder /build/target/release/airgap-guardian /usr/local/bin/airgap-guardian
COPY testdata /testdata

WORKDIR /work
ENTRYPOINT ["airgap-guardian"]
CMD ["scan", "/testdata"]

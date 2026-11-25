# Multi-stage build for Vaelspire Core (single static-ish Rust binary, zero external DB)
FROM rust:1.100-slim-bookworm AS builder

WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates

RUN cargo build --release -p vaelspire --locked

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home vaelspire \
    && mkdir -p /data \
    && chown vaelspire:vaelspire /data

COPY --from=builder /src/target/release/vaelspire /usr/local/bin/vaelspire

USER vaelspire
WORKDIR /data

ENV VAELSPIRE_BIND=0.0.0.0:8080 \
    VAELSPIRE_SQLITE_PATH=/data/vaelspire.sqlite \
    VAELSPIRE_LOG_FORMAT=json

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8080/health || exit 1

ENTRYPOINT ["vaelspire"]
CMD ["serve"]

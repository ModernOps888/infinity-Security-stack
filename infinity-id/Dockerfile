# ---- Build stage ---------------------------------------------------------
FROM rust:1.94-slim AS builder
WORKDIR /app

# ring / rsa need a C toolchain; ca-certificates for TLS at build time.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential ca-certificates pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY . .
RUN cargo build --release --locked --bin infinity-id --bin infinity-edge

# ---- Runtime stage -------------------------------------------------------
FROM debian:bookworm-slim
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 -s /usr/sbin/nologin infinity

COPY --from=builder --chmod=0755 /app/target/release/infinity-id /usr/local/bin/infinity-id
COPY --from=builder --chmod=0755 /app/target/release/infinity-edge /usr/local/bin/infinity-edge

ENV INFINITY_BIND=0.0.0.0:8080 \
    INFINITY_DATA_DIR=/data \
    INFINITY_DATABASE_URL=sqlite:///data/infinity.db \
    RUST_LOG=info,sqlx=warn

RUN mkdir -p /data && chown infinity:infinity /data && chmod 0700 /data
USER 10001:10001
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["infinity-id", "--healthcheck"]
CMD ["infinity-id"]

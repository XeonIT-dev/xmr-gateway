# ==============================================================================
# xmr-gateway Multi-Stage Production Containerfile (Docker & Podman compatible)
# ==============================================================================
# Build:
#   podman build -t xmr-gateway:latest -f Containerfile .
#   docker build -t xmr-gateway:latest -f Containerfile .
# ==============================================================================

FROM rust:1.94-bookworm AS builder

WORKDIR /build

# 1. Cache external dependency compilation independently from src/ edits
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src migrations \
    && printf 'pub fn _dummy() {}\n' > src/lib.rs \
    && printf 'fn main() {}\n' > src/main.rs \
    && cargo build --release --locked \
    && rm -rf src

# 2. Compile actual xmr-gateway release binary with embedded SQLx migrations
COPY src ./src
COPY migrations ./migrations
RUN touch src/lib.rs src/main.rs \
    && cargo build --release --locked --bin xmr-gateway \
    && strip /build/target/release/xmr-gateway

# ------------------------------------------------------------------------------
# Minimal Hardened Runtime Image (Non-root UID/GID 10001)
# ------------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl sqlite3 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 --system xmr-gateway \
    && useradd --uid 10001 --gid 10001 --system --home-dir /data --shell /usr/sbin/nologin xmr-gateway \
    && install -d -m 0700 -o 10001 -g 10001 /data

COPY --from=builder --chmod=0755 /build/target/release/xmr-gateway /usr/local/bin/xmr-gateway

USER 10001:10001
WORKDIR /data

ENV HOST=0.0.0.0 \
    PORT=8080 \
    DATABASE_URL=sqlite:///data/xmr_gateway.db \
    LOG_FORMAT=json

EXPOSE 8080
STOPSIGNAL SIGTERM

# Anonymous /health probe only (zero secrets; returns {"status":"ok"})
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT:-8080}/health" | grep -q '"status":"ok"' || exit 1

ENTRYPOINT ["/usr/local/bin/xmr-gateway"]

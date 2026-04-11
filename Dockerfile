# syntax=docker/dockerfile:1

# ── Stage 1: Install cargo-chef ──────────────────────────────────────────────
FROM rust:1-slim-bookworm AS chef
RUN apt-get update && apt-get install -y \
    pkg-config libssl-dev \
    libglib2.0-dev libgtk-3-dev libgdk-pixbuf-2.0-dev \
    libpango1.0-dev libcairo2-dev libatk1.0-dev \
    && rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-chef --locked
WORKDIR /build

# ── Stage 2: Prepare recipe (dependency lockfile) ────────────────────────────
FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY xtask ./xtask
COPY agents ./agents
COPY packages ./packages
RUN cargo chef prepare --recipe-path recipe.json

# ── Stage 3: Cook dependencies (CACHED between deploys) ─────────────────────
FROM chef AS builder
COPY --from=planner /build/recipe.json recipe.json
ARG LTO=true
ARG CODEGEN_UNITS=1
ENV CARGO_PROFILE_RELEASE_LTO=${LTO} \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=${CODEGEN_UNITS}
RUN cargo chef cook --release --recipe-path recipe.json

# ── Stage 4: Build application (only YOUR code, ~30s) ───────────────────────
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY xtask ./xtask
COPY agents ./agents
COPY packages ./packages
RUN cargo build --release --bin openfang

# ── Stage 5: Runtime image ──────────────────────────────────────────────────
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    python3 \
    python3-pip \
    python3-venv \
    nodejs \
    npm \
    chromium \
    fonts-liberation \
    libnss3 \
    libatk-bridge2.0-0 \
    libdrm2 \
    libxcomposite1 \
    libxdamage1 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    libpango-1.0-0 \
    libcairo2 \
    libcups2 \
    libxss1 \
    libgtk-3-0 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

ENV CHROME_PATH=/usr/bin/chromium

COPY --from=builder /build/target/release/openfang /usr/local/bin/
COPY --from=builder /build/agents /opt/openfang/agents
EXPOSE 4200
VOLUME /data
ENV OPENFANG_HOME=/data
ENTRYPOINT ["openfang"]
CMD ["start"]

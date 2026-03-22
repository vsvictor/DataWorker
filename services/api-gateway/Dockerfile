FROM rust:1.76-slim-bookworm AS builder
RUN apt-get update && apt-get install -y pkg-config libssl-dev libsasl2-dev cmake make && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
COPY services/api-gateway/ ./services/api-gateway/
RUN cargo build --release -p api-gateway

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates libssl3 libsasl2-2 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/api-gateway /usr/local/bin/api-gateway
COPY deploy/certs/ /app/certs/
CMD ["api-gateway"]

FROM rust:1.76-slim-bookworm AS builder
RUN apt-get update && apt-get install -y pkg-config libssl-dev libsasl2-dev cmake make && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
COPY services/worker/ ./services/worker/
RUN cargo build --release -p worker

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates libssl3 libsasl2-2 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/worker /usr/local/bin/worker
CMD ["worker"]

FROM rust:1.76-slim-bookworm AS builder
RUN apt-get update && apt-get install -y pkg-config libssl-dev libsasl2-dev cmake make && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
COPY services/user-service/ ./services/user-service/
RUN cargo build --release -p user-service

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates libssl3 libsasl2-2 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/user-service /usr/local/bin/user-service
CMD ["user-service"]

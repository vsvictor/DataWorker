# DataWorker – Rust High-Load Event-Driven System

A production-ready monorepo demonstrating a **Rust microservices** architecture with:

- **Event-Driven Architecture (EDA)** using **Redpanda** (Kafka-compatible)
- **OIDC provider** (Authorization Code + PKCE)
- **HTTP/3 (QUIC)** edge via `quinn` + `h3` crates
- **MongoDB** for persistent storage
- **Redis** for caching and session management
- **Async** throughout (Tokio runtime)
- **Leptos WASM** frontend with OIDC PKCE flow

---

## Repository Layout

```
DataWorker/
├── Cargo.toml                  # Workspace root
├── Cargo.lock
├── crates/
│   └── common/                 # Shared: event envelope, config, tracing, H3 helpers
├── services/
│   ├── api-gateway/            # HTTP/3 edge: JWT validation, routing
│   ├── auth-service/           # OIDC provider: authorize/token/jwks/userinfo
│   ├── user-service/           # User CRUD, MongoDB, publishes Kafka events
│   ├── policy-service/         # RBAC/ABAC checks with Redis cache
│   └── worker/                 # Kafka consumer: audit log + cache invalidation
├── ui/                         # Leptos WASM frontend
└── deploy/
    ├── docker-compose.yml
    └── certs/                  # Local CA + per-service TLS certificates
        └── generate-certs.sh
```

---

## Architecture

```
Browser ──HTTP/3──> api-gateway :4433 (QUIC/UDP)
                        │
          ┌─────────────┼────────────────┐
          │             │                │
      auth-service  user-service  policy-service
       :8080          :8081           :8082
          │             │                │
          └─────────────┼────────────────┘
                    Redpanda :9092  (Kafka events)
                    MongoDB  :27017
                    Redis    :6379

worker ──── consumes topics: users, access, auth ──> MongoDB audit_log + Redis invalidation
```

### Event Flow

1. Client calls `POST /users` through the gateway
2. `user-service` persists the user to MongoDB
3. `user-service` publishes `user.created` to the `users` Redpanda topic
4. `worker` consumes the event, writes an audit entry to `audit_log` collection, invalidates Redis cache
5. `policy-service` consumes `access.*` events and invalidates policy cache

### Canonical Event Envelope (`crates/common`)

```json
{
  "id": "uuid-v4",
  "type": "user.created",
  "occurred_at": "2025-01-01T00:00:00Z",
  "trace_id": "optional",
  "version": 1,
  "data": { "user_id": "...", "username": "alice" }
}
```

---

## Quick Start with Docker Compose

### 1. Generate TLS Certificates

```bash
bash deploy/certs/generate-certs.sh
```

This creates a local CA (`ca.crt`) and per-service certificates in `deploy/certs/`.

### 2. Start All Services

```bash
cd deploy/
docker compose up --build
```

Services started:
| Service        | Port (host)        | Protocol |
|----------------|--------------------|----------|
| api-gateway    | 4433/udp           | HTTP/3   |
| auth-service   | 8080/tcp           | HTTP/1.1 |
| user-service   | 8081/tcp           | HTTP/1.1 |
| policy-service | 8083/tcp           | HTTP/1.1 |
| Redpanda       | 9092/tcp, 8082/tcp | Kafka    |
| MongoDB        | 27017/tcp          | MongoDB  |
| Redis          | 6379/tcp           | Redis    |

---

## Happy-Path Flow

### 1. Register a User

```bash
curl -X POST http://localhost:8080/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","email":"alice@example.com","password":"secret123"}'
# → {"id":"<uuid>"}
```

### 2. Get Authorization Code (PKCE)

```bash
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d '=+/' | head -c 43)
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl dgst -binary -sha256 | openssl base64 | tr '+/' '-_' | tr -d '=')

curl -v "http://localhost:8080/authorize?\
response_type=code&client_id=web-client&\
redirect_uri=http://localhost:3000/callback&\
scope=openid+profile+email&\
code_challenge=${CODE_CHALLENGE}&code_challenge_method=S256&\
login_hint=alice&password=secret123"
# → 302 redirect with ?code=<CODE>
```

### 3. Exchange Code for Tokens

```bash
curl -X POST http://localhost:8080/token \
  -d "grant_type=authorization_code&code=<CODE>&\
      redirect_uri=http://localhost:3000/callback&\
      client_id=web-client&code_verifier=${CODE_VERIFIER}"
# → {"access_token":"...","id_token":"...","token_type":"Bearer",...}
```

### 4. Create a User via User-Service

```bash
curl -X POST http://localhost:8081/users \
  -H "Authorization: Bearer <access_token>" \
  -H 'Content-Type: application/json' \
  -d '{"username":"bob","email":"bob@example.com"}'
```

### 5. Verify Audit Log

```bash
docker exec -it <mongo-container> mongosh app --eval \
  "db.audit_log.find().pretty()"
```

### 6. JWKS + UserInfo

```bash
curl http://localhost:8080/jwks.json
curl -H "Authorization: Bearer <token>" http://localhost:8080/userinfo
```

---

## Testing HTTP/3 Endpoints

HTTP/3 is served by the `api-gateway` on UDP port 4433.

```bash
# Using curl ≥ 7.88 with HTTP/3 support
curl --http3 --cacert deploy/certs/ca.crt \
  https://localhost:4433/.well-known/openid-configuration
```

See `crates/common/src/h3_helpers.rs` for the Rust client helper API.

---

## Scaling / Load Balancing

### Docker Compose replicas

```bash
cd deploy/
docker compose up --scale user-service=3 --scale policy-service=2 --build
```

### Notes on QUIC / HTTP/3 Load Balancing

- QUIC uses UDP — ensure your LB supports UDP load balancing
- **Caddy** supports QUIC natively: `caddy reverse-proxy --from :4433 --to gateway:4433`
- **Envoy** supports QUIC as of v1.27+
- For simple setups: run a single stateless `api-gateway` replica (fast, ~1M req/s capable)

### Kubernetes

1. Push images to a container registry
2. Create `Deployment` + `Service` per microservice
3. Use `HorizontalPodAutoscaler` on CPU/RPS
4. Use a QUIC-capable Ingress (Envoy Gateway) for HTTP/3

---

## Certificate Management

```bash
# Generate dev certs (run once)
bash deploy/certs/generate-certs.sh

# Renew (certs expire after 825 days)
rm deploy/certs/*.crt deploy/certs/*.key deploy/certs/*.srl
bash deploy/certs/generate-certs.sh
```

---

## Environment Variables

| Service      | Variable           | Default                        | Description                  |
|--------------|--------------------|--------------------------------|------------------------------|
| auth-service | `MONGO_URI`        | `mongodb://localhost:27017`    | MongoDB connection string    |
| auth-service | `REDIS_URI`        | `redis://localhost:6379`       | Redis URI                    |
| auth-service | `KAFKA_BROKERS`    | `localhost:9092`               | Redpanda/Kafka bootstrap     |
| auth-service | `ISSUER`           | `http://localhost:8080`        | OIDC issuer URL              |
| auth-service | `JWT_SECRET`       | *(must set in prod)*           | **Change in production!**    |
| api-gateway  | `GATEWAY_BIND`     | `0.0.0.0:4433`                 | UDP port for HTTP/3          |
| api-gateway  | `TLS_CERT`         | `deploy/certs/gateway.crt`     | TLS certificate path         |
| api-gateway  | `TLS_KEY`          | `deploy/certs/gateway.key`     | TLS private key path         |

---

## OIDC Endpoints

| Endpoint                                | Description                              |
|-----------------------------------------|------------------------------------------|
| `GET /.well-known/openid-configuration` | Discovery document                       |
| `GET /authorize`                        | Authorization Code + PKCE               |
| `POST /token`                           | Token exchange                           |
| `GET /jwks.json`                        | JSON Web Key Set                         |
| `GET /userinfo`                         | Authenticated user claims                |
| `POST /introspect`                      | Token introspection                      |
| `POST /register`                        | Register a new user (dev helper)         |

---

## Technology Stack

| Layer       | Technology                          |
|-------------|-------------------------------------|
| Runtime     | Tokio (async)                       |
| HTTP API    | Axum                                |
| HTTP/3      | Quinn (QUIC) + h3 crates            |
| Event bus   | Redpanda (Kafka API) via rdkafka    |
| Database    | MongoDB (`mongodb` crate)           |
| Cache       | Redis (`redis` crate)               |
| Auth/JWT    | `jsonwebtoken`, `argon2`            |
| Frontend    | Leptos (Rust WASM)                  |
| Tracing     | `tracing` + `tracing-subscriber`    |

# UI – Leptos WASM Frontend

This is a Rust WebAssembly frontend built with [Leptos](https://leptos.dev/) using the OIDC Authorization Code + PKCE flow.

## Prerequisites

```bash
# Install wasm target
rustup target add wasm32-unknown-unknown

# Install trunk (WASM bundler)
cargo install trunk
```

## Development

```bash
cd ui/
trunk serve --port 3000
```

Open http://localhost:3000 — the app will redirect to the auth-service OIDC authorization endpoint.

## Production build

```bash
trunk build --release
# Output in ui/dist/
```

## Screens

- **Login** – Initiates the OIDC Authorization Code + PKCE flow
- **Users** – Lists all users from the user-service via the api-gateway
- **Create User** – Form to create a new user (authenticated)

## OIDC Flow

1. App generates `code_verifier` (random 32-byte string, base64url-encoded)
2. App computes `code_challenge = BASE64URL(SHA256(code_verifier))`
3. App redirects to `/authorize?response_type=code&code_challenge=...&code_challenge_method=S256`
4. Auth-service validates credentials and issues an authorization `code` (stored in Redis with 5-min TTL)
5. App receives `code` via redirect to `REDIRECT_URI`
6. App exchanges `code + code_verifier` for tokens via `POST /token`
7. App stores `access_token` in `localStorage` and uses it for API requests

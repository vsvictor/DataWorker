//! auth-service: minimal OIDC provider (Authorization Code + PKCE)
//!
//! Endpoints:
//!   GET  /.well-known/openid-configuration
//!   GET  /authorize
//!   POST /token
//!   GET  /jwks.json
//!   GET  /userinfo
//!   POST /introspect
//!   POST /register   (create user)
//!   POST /login      (resource-owner, dev only)

use anyhow::Result;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Duration, Utc};
use common::{
    config::env_or,
    tracing_setup::init_tracing,
};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use mongodb::{bson::doc, Client as MongoClient, Collection};
use rand::RngCore;
use rdkafka::config::ClientConfig as KafkaClientConfig;
use rdkafka::producer::{FutureProducer, FutureRecord};
use redis::aio::ConnectionManager;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration as StdDuration};
use uuid::Uuid;

// ────────────────────────────────────────────────────────────
// Models
// ────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
struct User {
    #[serde(rename = "_id")]
    id: String,
    username: String,
    email: String,
    password_hash: String,
    roles: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    iss: String,
    aud: Vec<String>,
    exp: i64,
    iat: i64,
    email: Option<String>,
    roles: Vec<String>,
    nonce: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct IdTokenClaims {
    sub: String,
    iss: String,
    aud: Vec<String>,
    exp: i64,
    iat: i64,
    email: Option<String>,
    nonce: Option<String>,
    at_hash: Option<String>,
}

// ────────────────────────────────────────────────────────────
// AppState
// ────────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    issuer: String,
    users: Collection<User>,
    redis: ConnectionManager,
    producer: FutureProducer,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    jwt_secret: String,
}

// ────────────────────────────────────────────────────────────
// Handlers
// ────────────────────────────────────────────────────────────

async fn openid_configuration(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    let issuer = &st.issuer;
    Json(serde_json::json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{}/authorize", issuer),
        "token_endpoint": format!("{}/token", issuer),
        "jwks_uri": format!("{}/jwks.json", issuer),
        "userinfo_endpoint": format!("{}/userinfo", issuer),
        "introspection_endpoint": format!("{}/introspect", issuer),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["HS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": ["none"],
        "code_challenge_methods_supported": ["S256"],
        "grant_types_supported": ["authorization_code", "refresh_token"]
    }))
}

#[derive(Deserialize)]
struct AuthorizeParams {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: Option<String>,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    nonce: Option<String>,
    login_hint: Option<String>,
}

/// GET /authorize  — in a real OIDC provider this shows a login form.
/// For MVP we accept `login_hint=<username>&password=<pass>` as query params
/// so that the PKCE flow can be tested without a browser.
#[derive(Deserialize)]
struct AuthorizeWithCreds {
    #[serde(flatten)]
    params: AuthorizeParams,
    password: Option<String>,
}

async fn authorize(
    State(st): State<Arc<AppState>>,
    Query(q): Query<AuthorizeWithCreds>,
) -> Response {
    if q.params.response_type != "code" {
        return (StatusCode::BAD_REQUEST, "unsupported response_type").into_response();
    }
    let username = match &q.params.login_hint {
        Some(u) => u.clone(),
        None => return (StatusCode::BAD_REQUEST, "login_hint required").into_response(),
    };
    let password = match &q.password {
        Some(p) => p.clone(),
        None => return (StatusCode::BAD_REQUEST, "password required").into_response(),
    };

    // Verify credentials
    let user = match st
        .users
        .find_one(doc! { "username": &username })
        .await
    {
        Ok(Some(u)) => u,
        _ => return (StatusCode::UNAUTHORIZED, "invalid credentials").into_response(),
    };

    let valid = {
        if let Ok(parsed) = PasswordHash::new(&user.password_hash) {
            Argon2::default()
                .verify_password(password.as_bytes(), &parsed)
                .is_ok()
        } else {
            false
        }
    };
    if !valid {
        return (StatusCode::UNAUTHORIZED, "invalid credentials").into_response();
    }

    // Generate auth code
    let code = gen_random_string(32);
    let nonce = q.params.nonce.clone();

    // Store code in Redis (TTL 5 min)
    let code_data = serde_json::json!({
        "user_id": user.id,
        "client_id": q.params.client_id,
        "redirect_uri": q.params.redirect_uri,
        "code_challenge": q.params.code_challenge,
        "code_challenge_method": q.params.code_challenge_method,
        "nonce": nonce,
        "scope": q.params.scope,
    });
    let mut redis_conn = st.redis.clone();
    let _: () = redis::cmd("SETEX")
        .arg(format!("auth_code:{}", code))
        .arg(300i64)
        .arg(code_data.to_string())
        .query_async(&mut redis_conn)
        .await
        .unwrap_or(());

    // Redirect back to client
    let mut redirect = format!("{}?code={}", q.params.redirect_uri, code);
    if let Some(state) = &q.params.state {
        redirect.push_str(&format!("&state={}", state));
    }
    axum::response::Redirect::to(&redirect).into_response()
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct TokenRequest {
    grant_type: String,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
}

#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: i64,
    id_token: String,
    refresh_token: String,
    scope: String,
}

async fn token(
    State(st): State<Arc<AppState>>,
    axum::Form(req): axum::Form<TokenRequest>,
) -> Response {
    if req.grant_type == "authorization_code" {
        let code = match &req.code {
            Some(c) => c.clone(),
            None => return (StatusCode::BAD_REQUEST, "missing code").into_response(),
        };

        // Retrieve code from Redis
        let mut redis_conn = st.redis.clone();
        let raw: Option<String> = redis::cmd("GET")
            .arg(format!("auth_code:{}", code))
            .query_async(&mut redis_conn)
            .await
            .unwrap_or(None);

        let code_data: serde_json::Value = match raw {
            Some(s) => serde_json::from_str(&s).unwrap_or_default(),
            None => return (StatusCode::BAD_REQUEST, "invalid or expired code").into_response(),
        };

        // Delete the code (one-time use)
        let _: () = redis::cmd("DEL")
            .arg(format!("auth_code:{}", code))
            .query_async(&mut redis_conn)
            .await
            .unwrap_or(());

        // Verify PKCE
        if let Some(challenge) = code_data["code_challenge"].as_str() {
            if !challenge.is_empty() {
                let verifier = match &req.code_verifier {
                    Some(v) => v.clone(),
                    None => return (StatusCode::BAD_REQUEST, "code_verifier required").into_response(),
                };
                let hash = Sha256::digest(verifier.as_bytes());
                let computed = URL_SAFE_NO_PAD.encode(hash);
                if computed != challenge {
                    return (StatusCode::BAD_REQUEST, "code_challenge mismatch").into_response();
                }
            }
        }

        let user_id = code_data["user_id"].as_str().unwrap_or("").to_string();
        let nonce = code_data["nonce"].as_str().map(|s| s.to_string());
        let scope = code_data["scope"].as_str().unwrap_or("openid").to_string();

        // Load user
        let user = match st
            .users
            .find_one(doc! { "_id": &user_id })
            .await
        {
            Ok(Some(u)) => u,
            _ => return (StatusCode::INTERNAL_SERVER_ERROR, "user not found").into_response(),
        };

        let now = Utc::now();
        let exp = (now + Duration::hours(1)).timestamp();

        // Access token
        let claims = Claims {
            sub: user.id.clone(),
            iss: st.issuer.clone(),
            aud: vec!["api".to_string()],
            exp,
            iat: now.timestamp(),
            email: Some(user.email.clone()),
            roles: user.roles.clone(),
            nonce: nonce.clone(),
        };
        let access_token = jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &st.encoding_key,
        )
        .unwrap();

        // ID token
        let id_claims = IdTokenClaims {
            sub: user.id.clone(),
            iss: st.issuer.clone(),
            aud: vec![req.client_id.clone().unwrap_or_default()],
            exp,
            iat: now.timestamp(),
            email: Some(user.email.clone()),
            nonce,
            at_hash: None,
        };
        let id_token = jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &id_claims,
            &st.encoding_key,
        )
        .unwrap();

        // Refresh token (random, stored in Redis for 30 days)
        let refresh = gen_random_string(40);
        let _: () = redis::cmd("SETEX")
            .arg(format!("refresh:{}", refresh))
            .arg(2592000i64)
            .arg(&user_id)
            .query_async(&mut redis_conn)
            .await
            .unwrap_or(());

        // Publish token.issued event
        let event = common::event::EventEnvelope::new(
            common::event::event_types::TOKEN_ISSUED,
            serde_json::json!({ "user_id": user_id }),
        );
        let payload = serde_json::to_string(&event).unwrap();
        let _ = st
            .producer
            .send(
                FutureRecord::to(common::event::topics::AUTH)
                    .payload(&payload)
                    .key(&user_id),
                StdDuration::from_secs(5),
            )
            .await;

        Json(TokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: 3600,
            id_token,
            refresh_token: refresh,
            scope,
        })
        .into_response()
    } else {
        (StatusCode::BAD_REQUEST, "unsupported grant_type").into_response()
    }
}

/// GET /jwks.json — returns the signing key as a JWK (HS256 = symmetric, so we return a minimal stub)
async fn jwks(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    // For HS256 the "public" verification key IS the secret.
    // In production use RS256 and publish only the public key.
    // Here we expose it as a symmetric JWK for demo purposes.
    let secret_b64 = URL_SAFE_NO_PAD.encode(st.jwt_secret.as_bytes());
    Json(serde_json::json!({
        "keys": [{
            "kty": "oct",
            "use": "sig",
            "alg": "HS256",
            "k": secret_b64,
            "kid": "default"
        }]
    }))
}

#[derive(Deserialize)]
struct UserinfoQuery {
    // access_token can be passed as query param or via Authorization header
    access_token: Option<String>,
}

async fn userinfo(
    State(st): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Query(q): Query<UserinfoQuery>,
) -> Response {
    let token_str = if let Some(t) = q.access_token {
        t
    } else if let Some(auth) = headers.get("authorization") {
        let v = auth.to_str().unwrap_or("");
        v.trim_start_matches("Bearer ").to_string()
    } else {
        return (StatusCode::UNAUTHORIZED, "missing token").into_response();
    };

    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_audience(&["api"]);

    match jsonwebtoken::decode::<Claims>(&token_str, &st.decoding_key, &validation) {
        Ok(data) => {
            let user = st
                .users
                .find_one(doc! { "_id": &data.claims.sub })
                .await
                .ok()
                .flatten();
            if let Some(u) = user {
                Json(serde_json::json!({
                    "sub": u.id,
                    "email": u.email,
                    "username": u.username,
                    "roles": u.roles,
                }))
                .into_response()
            } else {
                (StatusCode::NOT_FOUND, "user not found").into_response()
            }
        }
        Err(e) => (StatusCode::UNAUTHORIZED, e.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
struct IntrospectRequest {
    token: String,
}

async fn introspect(
    State(st): State<Arc<AppState>>,
    axum::Form(req): axum::Form<IntrospectRequest>,
) -> impl IntoResponse {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_audience(&["api"]);

    match jsonwebtoken::decode::<Claims>(&req.token, &st.decoding_key, &validation) {
        Ok(data) => Json(serde_json::json!({
            "active": true,
            "sub": data.claims.sub,
            "exp": data.claims.exp,
            "iat": data.claims.iat,
            "iss": data.claims.iss,
            "roles": data.claims.roles,
        })),
        Err(_) => Json(serde_json::json!({ "active": false })),
    }
}

// ────────────────────────────────────────────────────────────
// Registration (dev helper)
// ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct RegisterRequest {
    username: String,
    email: String,
    password: String,
}

async fn register(
    State(st): State<Arc<AppState>>,
    Json(req): Json<RegisterRequest>,
) -> Response {
    let id = Uuid::new_v4().to_string();
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(req.password.as_bytes(), &salt)
        .unwrap()
        .to_string();

    let user = User {
        id: id.clone(),
        username: req.username.clone(),
        email: req.email.clone(),
        password_hash: hash,
        roles: vec!["user".to_string()],
    };

    match st.users.insert_one(user).await {
        Ok(_) => {
            // Publish user.created event
            let event = common::event::EventEnvelope::new(
                common::event::event_types::USER_CREATED,
                serde_json::json!({ "user_id": id, "username": req.username }),
            );
            let payload = serde_json::to_string(&event).unwrap();
            let _ = st
                .producer
                .send(
                    FutureRecord::to(common::event::topics::USERS)
                        .payload(&payload)
                        .key(&id),
                    StdDuration::from_secs(5),
                )
                .await;

            (StatusCode::CREATED, Json(serde_json::json!({ "id": id }))).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────

fn gen_random_string(len: usize) -> String {
    let mut bytes = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

// ────────────────────────────────────────────────────────────
// main
// ────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing("auth-service");

    let mongo_uri = env_or("MONGO_URI", "mongodb://localhost:27017");
    let redis_uri = env_or("REDIS_URI", "redis://localhost:6379");
    let kafka_brokers = env_or("KAFKA_BROKERS", "localhost:9092");
    let issuer = env_or("ISSUER", "http://localhost:8080");
    let jwt_secret = env_or("JWT_SECRET", "super-secret-key-change-in-prod");
    let bind_addr = env_or("AUTH_BIND", "0.0.0.0:8080");

    // MongoDB
    let mongo = MongoClient::with_uri_str(&mongo_uri).await?;
    let db = mongo.database("app");
    let users: Collection<User> = db.collection("users");

    // Redis
    let redis_client = redis::Client::open(redis_uri.as_str())?;
    let redis_mgr = ConnectionManager::new(redis_client).await?;

    // Kafka producer
    let producer: FutureProducer = KafkaClientConfig::new()
        .set("bootstrap.servers", &kafka_brokers)
        .set("message.timeout.ms", "5000")
        .create()?;

    let encoding_key = EncodingKey::from_secret(jwt_secret.as_bytes());
    let decoding_key = DecodingKey::from_secret(jwt_secret.as_bytes());

    let state = Arc::new(AppState {
        issuer,
        users,
        redis: redis_mgr,
        producer,
        encoding_key,
        decoding_key,
        jwt_secret,
    });

    let app = Router::new()
        .route("/.well-known/openid-configuration", get(openid_configuration))
        .route("/authorize", get(authorize))
        .route("/token", post(token))
        .route("/jwks.json", get(jwks))
        .route("/userinfo", get(userinfo))
        .route("/introspect", post(introspect))
        .route("/register", post(register))
        .with_state(state);

    tracing::info!("auth-service listening on {}", bind_addr);
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

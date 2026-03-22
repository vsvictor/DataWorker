//! api-gateway: HTTP/3 (QUIC) edge service.
//! Accepts HTTP/3 connections from clients, validates JWT, and forwards to
//! internal services.  Also exposes an HTTP/1.1 fallback for health checks.

use anyhow::Result;
use bytes::Bytes;
use common::{
    config::env_or,
    h3_helpers::{make_server_config, make_server_endpoint},
    tracing_setup::init_tracing,
};
use h3::server::RequestStream;
use http::{Request, Response, StatusCode};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use std::{net::SocketAddr, path::PathBuf, sync::Arc};

#[derive(Deserialize)]
#[allow(dead_code)]
struct Claims {
    sub: String,
    exp: i64,
    roles: Vec<String>,
}

#[derive(Clone)]
struct GatewayConfig {
    auth_service_url: String,
    user_service_url: String,
    policy_service_url: String,
    jwt_secret: String,
    http_client: reqwest::Client,
}

async fn handle_request(
    req: Request<()>,
    config: Arc<GatewayConfig>,
    mut stream: RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
) -> Result<()> {
    let path = req.uri().path().to_string();
    let method = req.method().clone();

    tracing::info!(method = %method, path = %path, "Incoming H3 request");

    // Validate JWT (skip for OIDC endpoints)
    let is_public = path.starts_with("/.well-known")
        || path == "/authorize"
        || path == "/token"
        || path == "/jwks.json"
        || path == "/register"
        || path == "/health";

    if !is_public {
        let auth_header = req
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if !auth_header.starts_with("Bearer ") {
            let resp = Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(())?;
            stream.send_response(resp).await?;
            stream
                .send_data(Bytes::from_static(b"Unauthorized"))
                .await?;
            stream.finish().await?;
            return Ok(());
        }

        let token = &auth_header["Bearer ".len()..];
        let key = DecodingKey::from_secret(config.jwt_secret.as_bytes());
        let mut val = Validation::new(Algorithm::HS256);
        val.set_audience(&["api"]);

        if jsonwebtoken::decode::<Claims>(token, &key, &val).is_err() {
            let resp = Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(())?;
            stream.send_response(resp).await?;
            stream
                .send_data(Bytes::from_static(b"Invalid token"))
                .await?;
            stream.finish().await?;
            return Ok(());
        }
    }

    // Route to upstream
    let upstream_url = route_to_upstream(&path, &config);
    tracing::info!(upstream = %upstream_url, "Forwarding request");

    match config.http_client.get(&upstream_url).send().await {
        Ok(upstream_resp) => {
            let status = upstream_resp.status();
            let body = upstream_resp.bytes().await.unwrap_or_default();
            let resp = Response::builder().status(status).body(())?;
            stream.send_response(resp).await?;
            stream.send_data(body).await?;
        }
        Err(e) => {
            tracing::error!(error = %e, "Upstream error");
            let resp = Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(())?;
            stream.send_response(resp).await?;
            stream.send_data(Bytes::from(e.to_string())).await?;
        }
    }
    stream.finish().await?;
    Ok(())
}

fn route_to_upstream(path: &str, config: &GatewayConfig) -> String {
    if path.starts_with("/.well-known")
        || path.starts_with("/authorize")
        || path.starts_with("/token")
        || path.starts_with("/jwks")
        || path.starts_with("/userinfo")
        || path.starts_with("/introspect")
        || path.starts_with("/register")
    {
        format!("{}{}", config.auth_service_url, path)
    } else if path.starts_with("/users") {
        format!("{}{}", config.user_service_url, path)
    } else if path.starts_with("/authorize-policy") {
        format!("{}{}", config.policy_service_url, path)
    } else {
        format!("{}{}", config.auth_service_url, path)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing("api-gateway");

    let bind_addr: SocketAddr = env_or("GATEWAY_BIND", "0.0.0.0:4433").parse()?;
    let cert_path = PathBuf::from(env_or("TLS_CERT", "deploy/certs/gateway.crt"));
    let key_path = PathBuf::from(env_or("TLS_KEY", "deploy/certs/gateway.key"));
    let auth_service_url = env_or("AUTH_SERVICE_URL", "http://localhost:8080");
    let user_service_url = env_or("USER_SERVICE_URL", "http://localhost:8081");
    let policy_service_url = env_or("POLICY_SERVICE_URL", "http://localhost:8082");
    let jwt_secret = env_or("JWT_SECRET", "super-secret-key-change-in-prod");

    let server_cfg = make_server_config(&cert_path, &key_path)?;
    let endpoint = make_server_endpoint(bind_addr, server_cfg)?;

    let config = Arc::new(GatewayConfig {
        auth_service_url,
        user_service_url,
        policy_service_url,
        jwt_secret,
        http_client: reqwest::Client::new(),
    });

    tracing::info!("api-gateway listening on UDP {} (HTTP/3)", bind_addr);

    while let Some(new_conn) = endpoint.accept().await {
        let cfg = config.clone();
        tokio::spawn(async move {
            match new_conn.await {
                Ok(conn) => {
                    let mut h3_conn = match h3::server::Connection::new(h3_quinn::Connection::new(conn)).await {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::error!(error = %e, "H3 connection error");
                            return;
                        }
                    };
                    loop {
                        match h3_conn.accept().await {
                            Ok(Some(resolver)) => {
                                let cfg2 = cfg.clone();
                                tokio::spawn(async move {
                                    match resolver.resolve_request().await {
                                        Ok((req, stream)) => {
                                            if let Err(e) = handle_request(req, cfg2, stream).await {
                                                tracing::error!(error = %e, "Request handling error");
                                            }
                                        }
                                        Err(e) => tracing::error!(error = %e, "Request resolve error"),
                                    }
                                });
                            }
                            Ok(None) => break,
                            Err(e) => {
                                tracing::error!(error = %e, "H3 accept error");
                                break;
                            }
                        }
                    }
                }
                Err(e) => tracing::error!(error = %e, "QUIC connection error"),
            }
        });
    }

    Ok(())
}

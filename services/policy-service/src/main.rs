//! policy-service: RBAC/ABAC authorization checks with Redis caching.
//! Also consumes role/permission events to invalidate cache.

use anyhow::Result;
use axum::{
    extract::State,
    response::{IntoResponse, Json},
    routing::post,
    Router,
};
use common::{config::env_or, tracing_setup::init_tracing};
use mongodb::{bson::doc, Client as MongoClient, Collection};
use rdkafka::{
    config::ClientConfig as KafkaClientConfig,
    consumer::{CommitMode, Consumer, StreamConsumer},
    Message,
};
use redis::aio::ConnectionManager;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Policy {
    #[serde(rename = "_id")]
    id: String,
    subject: String,   // user_id or role
    action: String,    // e.g., "read", "write"
    resource: String,  // e.g., "users/*"
    effect: String,    // "allow" | "deny"
}

#[derive(Deserialize)]
struct AuthzRequest {
    subject: String,
    action: String,
    resource: String,
}

#[derive(Serialize)]
struct AuthzResponse {
    allowed: bool,
    cached: bool,
}

#[derive(Clone)]
struct AppState {
    policies: Collection<Policy>,
    redis: ConnectionManager,
}

async fn authorize(
    State(st): State<Arc<AppState>>,
    Json(req): Json<AuthzRequest>,
) -> impl IntoResponse {
    let cache_key = format!("policy:{}:{}:{}", req.subject, req.action, req.resource);
    let mut redis_conn = st.redis.clone();

    // Check cache
    let cached: Option<String> = redis::cmd("GET")
        .arg(&cache_key)
        .query_async(&mut redis_conn)
        .await
        .unwrap_or(None);

    if let Some(v) = cached {
        return Json(AuthzResponse {
            allowed: v == "allow",
            cached: true,
        });
    }

    // Query MongoDB for policy
    let policy = st
        .policies
        .find_one(doc! {
            "subject": &req.subject,
            "action": &req.action,
            "resource": &req.resource,
        })
        .await
        .unwrap_or(None);

    let allowed = policy
        .as_ref()
        .map(|p| p.effect == "allow")
        .unwrap_or(false);

    // Cache the decision for 60 seconds
    let _: () = redis::cmd("SETEX")
        .arg(&cache_key)
        .arg(60i64)
        .arg(if allowed { "allow" } else { "deny" })
        .query_async(&mut redis_conn)
        .await
        .unwrap_or(());

    Json(AuthzResponse { allowed, cached: false })
}

async fn consume_events(
    brokers: String,
    redis: ConnectionManager,
) {
    let consumer: StreamConsumer = KafkaClientConfig::new()
        .set("bootstrap.servers", &brokers)
        .set("group.id", "policy-service")
        .set("auto.offset.reset", "earliest")
        .create()
        .expect("Failed to create consumer");

    consumer
        .subscribe(&[common::event::topics::ACCESS])
        .expect("Failed to subscribe");

    loop {
        match consumer.recv().await {
            Ok(msg) => {
                if let Some(payload) = msg.payload() {
                    if let Ok(event) = serde_json::from_slice::<common::event::EventEnvelope>(payload) {
                        tracing::info!(event_type = %event.event_type, "Received access event, invalidating cache");
                        // Invalidate related cache keys
                        let mut rc = redis.clone();
                        if let Some(user_id) = event.data["user_id"].as_str() {
                            let pattern = format!("policy:{}:*", user_id);
                            // Simple scan-based invalidation
                            let _: () = redis::cmd("DEL")
                                .arg(format!("policy:{}:*", user_id))
                                .query_async(&mut rc)
                                .await
                                .unwrap_or(());
                            tracing::info!(key = %pattern, "Cache invalidated");
                        }
                    }
                }
                consumer.commit_message(&msg, CommitMode::Async).unwrap();
            }
            Err(e) => tracing::error!(error = %e, "Kafka consumer error"),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing("policy-service");

    let mongo_uri = env_or("MONGO_URI", "mongodb://localhost:27017");
    let redis_uri = env_or("REDIS_URI", "redis://localhost:6379");
    let kafka_brokers = env_or("KAFKA_BROKERS", "localhost:9092");
    let bind_addr = env_or("POLICY_BIND", "0.0.0.0:8082");

    let mongo = MongoClient::with_uri_str(&mongo_uri).await?;
    let db = mongo.database("app");
    let policies: Collection<Policy> = db.collection("policies");

    let redis_client = redis::Client::open(redis_uri.as_str())?;
    let redis_mgr = ConnectionManager::new(redis_client).await?;

    // Spawn event consumer
    tokio::spawn(consume_events(kafka_brokers, redis_mgr.clone()));

    let state = Arc::new(AppState {
        policies,
        redis: redis_mgr,
    });

    let app = Router::new()
        .route("/authorize", post(authorize))
        .with_state(state);

    tracing::info!("policy-service listening on {}", bind_addr);
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

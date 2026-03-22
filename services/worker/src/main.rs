//! worker: consumes domain events from Redpanda, writes audit logs to Mongo,
//! and invalidates Redis cache keys.

use anyhow::Result;
use common::{
    config::env_or,
    event::{topics, EventEnvelope},
    tracing_setup::init_tracing,
};
use mongodb::{bson::doc, Client as MongoClient, Collection};
use rdkafka::{
    config::ClientConfig as KafkaClientConfig,
    consumer::{CommitMode, Consumer, StreamConsumer},
    Message,
};
use redis::aio::ConnectionManager;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Serialize, Deserialize)]
struct AuditEntry {
    event_id: String,
    event_type: String,
    occurred_at: String,
    data: serde_json::Value,
}

struct WorkerState {
    audit_log: Collection<AuditEntry>,
    redis: ConnectionManager,
}

async fn handle_event(state: &WorkerState, event: EventEnvelope) {
    tracing::info!(
        event_id = %event.id,
        event_type = %event.event_type,
        "Processing event"
    );

    // Write audit entry
    let entry = AuditEntry {
        event_id: event.id.to_string(),
        event_type: event.event_type.clone(),
        occurred_at: event.occurred_at.to_rfc3339(),
        data: event.data.clone(),
    };
    if let Err(e) = state.audit_log.insert_one(entry).await {
        tracing::error!(error = %e, "Failed to write audit entry");
    }

    // Invalidate cache based on event type
    let mut redis_conn = state.redis.clone();
    match event.event_type.as_str() {
        "user.created" | "user.updated" | "user.deleted" => {
            if let Some(user_id) = event.data["user_id"].as_str() {
                let key = format!("user_profile:{}", user_id);
                let _: () = redis::cmd("DEL")
                    .arg(&key)
                    .query_async(&mut redis_conn)
                    .await
                    .unwrap_or(());
                tracing::info!(key = %key, "Redis cache invalidated");
            }
        }
        "role.assigned" | "permission.granted" => {
            if let Some(user_id) = event.data["user_id"].as_str() {
                let pattern = format!("policy:{}:*", user_id);
                tracing::info!(pattern = %pattern, "Policy cache would be invalidated (pattern DEL)");
            }
        }
        _ => {}
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing("worker");

    let mongo_uri = env_or("MONGO_URI", "mongodb://localhost:27017");
    let redis_uri = env_or("REDIS_URI", "redis://localhost:6379");
    let kafka_brokers = env_or("KAFKA_BROKERS", "localhost:9092");

    let mongo = MongoClient::with_uri_str(&mongo_uri).await?;
    let db = mongo.database("app");
    let audit_log: Collection<AuditEntry> = db.collection("audit_log");

    let redis_client = redis::Client::open(redis_uri.as_str())?;
    let redis_mgr = ConnectionManager::new(redis_client).await?;

    let state = Arc::new(WorkerState {
        audit_log,
        redis: redis_mgr,
    });

    let consumer: StreamConsumer = KafkaClientConfig::new()
        .set("bootstrap.servers", &kafka_brokers)
        .set("group.id", "worker-service")
        .set("auto.offset.reset", "earliest")
        .create()?;

    consumer.subscribe(&[topics::USERS, topics::ACCESS, topics::AUTH])?;

    tracing::info!("worker started, consuming events");

    loop {
        match consumer.recv().await {
            Ok(msg) => {
                if let Some(payload) = msg.payload() {
                    match serde_json::from_slice::<EventEnvelope>(payload) {
                        Ok(event) => handle_event(&state, event).await,
                        Err(e) => tracing::warn!(error = %e, "Failed to parse event"),
                    }
                }
                consumer.commit_message(&msg, CommitMode::Async).unwrap();
            }
            Err(e) => tracing::error!(error = %e, "Kafka error"),
        }
    }
}

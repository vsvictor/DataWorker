//! user-service: CRUD for users, roles, permissions. Publishes domain events.

use anyhow::Result;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use common::{
    config::env_or,
    event::{event_types, topics, EventEnvelope},
    tracing_setup::init_tracing,
};
use mongodb::{bson::doc, Client as MongoClient, Collection};
use rdkafka::config::ClientConfig as KafkaClientConfig;
use rdkafka::producer::{FutureProducer, FutureRecord};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration as StdDuration};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct User {
    #[serde(rename = "_id")]
    id: String,
    username: String,
    email: String,
    roles: Vec<String>,
    permissions: Vec<String>,
}

#[derive(Deserialize)]
struct CreateUserRequest {
    username: String,
    email: String,
    roles: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct UpdateUserRequest {
    username: Option<String>,
    email: Option<String>,
    roles: Option<Vec<String>>,
    permissions: Option<Vec<String>>,
}

#[derive(Clone)]
struct AppState {
    users: Collection<User>,
    producer: FutureProducer,
}

async fn create_user(
    State(st): State<Arc<AppState>>,
    Json(req): Json<CreateUserRequest>,
) -> impl IntoResponse {
    let id = Uuid::new_v4().to_string();
    let user = User {
        id: id.clone(),
        username: req.username.clone(),
        email: req.email.clone(),
        roles: req.roles.unwrap_or_else(|| vec!["user".to_string()]),
        permissions: vec![],
    };

    match st.users.insert_one(user.clone()).await {
        Ok(_) => {
            let event = EventEnvelope::new(
                event_types::USER_CREATED,
                serde_json::json!({
                    "user_id": id,
                    "username": req.username,
                    "email": req.email,
                }),
            );
            let payload = serde_json::to_string(&event).unwrap();
            let _ = st
                .producer
                .send(
                    FutureRecord::to(topics::USERS)
                        .payload(&payload)
                        .key(&id),
                    StdDuration::from_secs(5),
                )
                .await;
            (StatusCode::CREATED, Json(user)).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn list_users(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    use futures::TryStreamExt;
    match st.users.find(doc! {}).await {
        Ok(cursor) => {
            let users: Vec<User> = cursor.try_collect().await.unwrap_or_default();
            Json(users).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn get_user(
    State(st): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match st.users.find_one(doc! { "_id": &id }).await {
        Ok(Some(u)) => Json(u).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "user not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn update_user(
    State(st): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<UpdateUserRequest>,
) -> impl IntoResponse {
    let mut update_doc = doc! {};
    if let Some(u) = req.username {
        update_doc.insert("username", u);
    }
    if let Some(e) = req.email {
        update_doc.insert("email", e);
    }
    if let Some(r) = req.roles {
        update_doc.insert("roles", r);
    }
    if let Some(p) = req.permissions {
        update_doc.insert("permissions", p);
    }

    match st
        .users
        .update_one(doc! { "_id": &id }, doc! { "$set": update_doc })
        .await
    {
        Ok(r) if r.matched_count > 0 => {
            let event = EventEnvelope::new(
                event_types::USER_UPDATED,
                serde_json::json!({ "user_id": id }),
            );
            let payload = serde_json::to_string(&event).unwrap();
            let _ = st
                .producer
                .send(
                    FutureRecord::to(topics::USERS)
                        .payload(&payload)
                        .key(&id),
                    StdDuration::from_secs(5),
                )
                .await;
            (StatusCode::OK, "updated").into_response()
        }
        Ok(_) => (StatusCode::NOT_FOUND, "user not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn delete_user(
    State(st): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match st.users.delete_one(doc! { "_id": &id }).await {
        Ok(r) if r.deleted_count > 0 => {
            let event = EventEnvelope::new(
                event_types::USER_DELETED,
                serde_json::json!({ "user_id": id }),
            );
            let payload = serde_json::to_string(&event).unwrap();
            let _ = st
                .producer
                .send(
                    FutureRecord::to(topics::USERS)
                        .payload(&payload)
                        .key(&id),
                    StdDuration::from_secs(5),
                )
                .await;
            (StatusCode::NO_CONTENT, "").into_response()
        }
        Ok(_) => (StatusCode::NOT_FOUND, "user not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
struct AssignRoleRequest {
    role: String,
}

async fn assign_role(
    State(st): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<AssignRoleRequest>,
) -> impl IntoResponse {
    match st
        .users
        .update_one(
            doc! { "_id": &id },
            doc! { "$addToSet": { "roles": &req.role } },
        )
        .await
    {
        Ok(r) if r.matched_count > 0 => {
            let event = EventEnvelope::new(
                event_types::ROLE_ASSIGNED,
                serde_json::json!({ "user_id": id, "role": req.role }),
            );
            let payload = serde_json::to_string(&event).unwrap();
            let _ = st
                .producer
                .send(
                    FutureRecord::to(topics::ACCESS)
                        .payload(&payload)
                        .key(&id),
                    StdDuration::from_secs(5),
                )
                .await;
            (StatusCode::OK, "role assigned").into_response()
        }
        Ok(_) => (StatusCode::NOT_FOUND, "user not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing("user-service");

    let mongo_uri = env_or("MONGO_URI", "mongodb://localhost:27017");
    let kafka_brokers = env_or("KAFKA_BROKERS", "localhost:9092");
    let bind_addr = env_or("USER_BIND", "0.0.0.0:8081");

    let mongo = MongoClient::with_uri_str(&mongo_uri).await?;
    let db = mongo.database("app");
    let users: Collection<User> = db.collection("users");

    let producer: FutureProducer = KafkaClientConfig::new()
        .set("bootstrap.servers", &kafka_brokers)
        .set("message.timeout.ms", "5000")
        .create()?;

    let state = Arc::new(AppState { users, producer });

    let app = Router::new()
        .route("/users", post(create_user).get(list_users))
        .route("/users/:id", get(get_user).put(update_user).delete(delete_user))
        .route("/users/:id/roles", post(assign_role))
        .with_state(state);

    tracing::info!("user-service listening on {}", bind_addr);
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

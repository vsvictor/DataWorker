use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

/// Canonical event envelope used across all services.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope {
    /// Unique event ID.
    pub id: Uuid,
    /// Event type, e.g. `user.created`, `role.assigned`.
    #[serde(rename = "type")]
    pub event_type: String,
    /// When the event occurred (UTC).
    pub occurred_at: DateTime<Utc>,
    /// Optional trace/correlation ID.
    pub trace_id: Option<String>,
    /// Schema version.
    pub version: u32,
    /// Domain-specific payload.
    pub data: Value,
}

impl EventEnvelope {
    pub fn new(event_type: impl Into<String>, data: Value) -> Self {
        Self {
            id: Uuid::new_v4(),
            event_type: event_type.into(),
            occurred_at: Utc::now(),
            trace_id: None,
            version: 1,
            data,
        }
    }

    pub fn with_trace(mut self, trace_id: impl Into<String>) -> Self {
        self.trace_id = Some(trace_id.into());
        self
    }
}

// Well-known event type constants
pub mod event_types {
    pub const USER_CREATED: &str = "user.created";
    pub const USER_UPDATED: &str = "user.updated";
    pub const USER_DELETED: &str = "user.deleted";
    pub const ROLE_ASSIGNED: &str = "role.assigned";
    pub const PERMISSION_GRANTED: &str = "permission.granted";
    pub const TOKEN_ISSUED: &str = "token.issued";
    pub const TOKEN_REVOKED: &str = "token.revoked";
    pub const AUDIT_LOGGED: &str = "audit.logged";
}

// Well-known topic names (Redpanda/Kafka)
pub mod topics {
    pub const USERS: &str = "users";
    pub const ACCESS: &str = "access";
    pub const AUTH: &str = "auth";
    pub const AUDIT: &str = "audit";
}

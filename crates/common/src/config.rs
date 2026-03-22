use std::env;

/// Read an env var, panic with a helpful message if missing.
pub fn require_env(key: &str) -> String {
    env::var(key).unwrap_or_else(|_| panic!("Required env var {key} not set"))
}

/// Read an env var with a default.
pub fn env_or(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_owned())
}

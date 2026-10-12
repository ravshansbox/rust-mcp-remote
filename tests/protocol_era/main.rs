//! Tests for the `protocol_era` module, gathered into one test binary.

/// Serializes tests that change process-wide state (environment variables, logging flags).
pub static GLOBAL_STATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

use rust_mcp_remote::protocol_era::LegacyClientIdentity;
use serde_json::{Map, Value, json};

/// Unwraps a JSON object, panicking on any other value.
pub fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => panic!("not an object"),
    }
}

/// A 2025-11-25 client identity with roots capability, as a desktop host would send it.
pub fn identity() -> LegacyClientIdentity {
    LegacyClientIdentity {
        protocol_version: Some("2025-11-25".to_string()),
        capabilities: Some(object(json!({ "roots": {} }))),
        client_info: Some(json!({ "name": "desktop-host", "version": "0.1.0" })),
    }
}

mod discover;
mod initialize;
mod meta;
mod predicates;
mod probe;
mod protocol_era;
mod subscriptions;
mod verdict;

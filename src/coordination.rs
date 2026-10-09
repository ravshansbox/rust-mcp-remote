use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

use crate::mcp_auth_config::read_json_file;

pub const FOLLOWER_PATIENCE_MS: u64 = 3 * 60_000;
pub const REFRESH_FOLLOWER_PATIENCE_MS: u64 = 10_000;
pub const FOLLOWER_POLL_INTERVAL_MS: u64 = 250;
pub const TOKEN_EXPIRY_MARGIN_MS: u64 = 60_000;

pub const PORT_CANDIDATES: u16 = 8;

pub fn callback_port_candidates(callback_port: u16, strict_port: bool) -> Vec<u16> {
    if strict_port {
        return vec![callback_port];
    }
    (0..PORT_CANDIDATES)
        .filter_map(|offset| callback_port.checked_add(offset))
        .collect()
}

pub fn no_free_callback_port_message(candidates: &[u16]) -> String {
    let first = candidates.first().copied().unwrap_or_default();
    let last = candidates.last().copied().unwrap_or_default();
    format!(
        "Could not find a free callback port for this server (tried {first}-{last}). Close whatever is holding those ports, or pass a port as the second argument to choose one."
    )
}

fn coerce_number(value: &Value) -> Option<f64> {
    match value {
        Value::Number(number) => number.as_f64(),
        Value::String(text) => text.trim().parse().ok(),
        _ => None,
    }
}

pub fn has_usable_tokens_at(server_url_hash: &str, now_ms: u64) -> bool {
    let Some(tokens) = read_json_file::<Value>(server_url_hash, "tokens.json") else {
        return false;
    };
    if !tokens.get("access_token").is_some_and(Value::is_string)
        || !tokens.get("token_type").is_some_and(Value::is_string)
    {
        return false;
    }
    let expires_at = tokens.get("expires_at").and_then(coerce_number);
    if let Some(expires_at) = expires_at.filter(|expires_at| *expires_at != 0.0)
        && now_ms as f64 >= expires_at - TOKEN_EXPIRY_MARGIN_MS as f64
    {
        return tokens
            .get("refresh_token")
            .and_then(Value::as_str)
            .is_some_and(|refresh_token| !refresh_token.is_empty());
    }
    true
}

pub fn has_usable_tokens(server_url_hash: &str) -> bool {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or_default();
    has_usable_tokens_at(server_url_hash, now_ms)
}

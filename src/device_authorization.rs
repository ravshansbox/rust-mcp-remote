use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};

use crate::logging::debug_log;

pub const DEVICE_CODE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";

const SLOW_DOWN_INCREMENT_SECONDS: f64 = 5.0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormRequest {
    pub headers: Vec<(String, String)>,
    pub params: Vec<(String, String)>,
}

pub fn build_device_token_request(
    auth_method: &str,
    client_id: &str,
    client_secret: Option<&str>,
    device_code: &str,
    resource: Option<&str>,
) -> Result<FormRequest, String> {
    let mut headers = vec![
        (
            "content-type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        ),
        ("accept".to_string(), "application/json".to_string()),
    ];
    let mut params = vec![
        ("grant_type".to_string(), DEVICE_CODE_GRANT_TYPE.to_string()),
        ("device_code".to_string(), device_code.to_string()),
    ];
    apply_client_authentication(
        auth_method,
        client_id,
        client_secret,
        &mut headers,
        &mut params,
    )?;
    if let Some(resource) = resource {
        set_pair(&mut params, "resource", resource, false);
    }
    Ok(FormRequest { headers, params })
}

pub fn next_poll_interval(
    status: u16,
    body: Option<&Value>,
    interval_seconds: f64,
) -> Result<f64, String> {
    let field = |name: &str| {
        body.and_then(|body| body.get(name))
            .filter(|value| !value.is_null())
    };
    match field("error").and_then(Value::as_str) {
        Some("authorization_pending") => Ok(interval_seconds),
        Some("slow_down") => {
            let interval_seconds = interval_seconds + SLOW_DOWN_INCREMENT_SECONDS;
            debug_log(
                "Device token endpoint asked us to slow down",
                &[json!({ "intervalSeconds": interval_seconds })],
            );
            Ok(interval_seconds)
        }
        Some("access_denied") => Err("Authorization was denied".to_string()),
        Some("expired_token") => Err("The device code expired before it was approved".to_string()),
        _ => {
            let detail = match field("error_description").or_else(|| field("error")) {
                Some(Value::String(text)) => text.clone(),
                Some(other) => other.to_string(),
                None => "unknown error".to_string(),
            };
            Err(format!(
                "Device token request failed (HTTP {status}): {detail}"
            ))
        }
    }
}

pub fn supports_device_authorization(metadata: Option<&Value>) -> bool {
    let Some(metadata) = metadata else {
        return false;
    };
    let has_endpoint = match metadata.get("device_authorization_endpoint") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(Value::Number(number)) => number.as_f64().is_some_and(|value| value != 0.0),
        Some(Value::String(text)) => !text.is_empty(),
        Some(_) => true,
    };
    if !has_endpoint {
        return false;
    }

    match metadata.get("grant_types_supported") {
        Some(Value::Array(grants)) => grants
            .iter()
            .any(|grant| grant.as_str() == Some(DEVICE_CODE_GRANT_TYPE)),
        _ => true,
    }
}

pub fn apply_client_authentication(
    method: &str,
    client_id: &str,
    client_secret: Option<&str>,
    headers: &mut Vec<(String, String)>,
    params: &mut Vec<(String, String)>,
) -> Result<(), String> {
    if method == "client_secret_basic" {
        let Some(client_secret) = client_secret.filter(|secret| !secret.is_empty()) else {
            return Err("client_secret_basic authentication requires a client_secret".to_string());
        };
        let credentials = STANDARD.encode(format!("{client_id}:{client_secret}"));
        set_pair(
            headers,
            "Authorization",
            &format!("Basic {credentials}"),
            true,
        );
        return Ok(());
    }

    if method == "client_secret_post" {
        set_pair(params, "client_id", client_id, false);
        if let Some(client_secret) = client_secret.filter(|secret| !secret.is_empty()) {
            set_pair(params, "client_secret", client_secret, false);
        }
        return Ok(());
    }

    if method != "none" {
        return Err(format!(
            "Unsupported client authentication method: {method}"
        ));
    }

    set_pair(params, "client_id", client_id, false);
    Ok(())
}

fn set_pair(pairs: &mut Vec<(String, String)>, name: &str, value: &str, ignore_case: bool) {
    let matches = |key: &str| {
        if ignore_case {
            key.eq_ignore_ascii_case(name)
        } else {
            key == name
        }
    };
    match pairs.iter().position(|(key, _)| matches(key)) {
        Some(index) => {
            pairs[index].1 = value.to_string();
            let mut position = 0;
            pairs.retain(|(key, _)| {
                let keep = position <= index || !matches(key);
                position += 1;
                keep
            });
        }
        None => pairs.push((name.to_string(), value.to_string())),
    }
}

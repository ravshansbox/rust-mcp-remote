use serde_json::{Map, Value};

pub fn local_answer_for(method: &str) -> Option<Value> {
    match method {
        "ping" | "resources/subscribe" | "resources/unsubscribe" | "logging/setLevel" => {
            Some(Value::Object(Map::new()))
        }
        _ => None,
    }
}

pub fn is_dropped_in_modern_era(method: &str) -> bool {
    matches!(
        method,
        "notifications/initialized" | "notifications/roots/list_changed"
    )
}

pub fn is_modern_only_notification(method: &str) -> bool {
    method == "notifications/subscriptions/acknowledged"
}

pub fn is_input_required_result(result: &Value) -> bool {
    result.get("resultType").and_then(Value::as_str) == Some("input_required")
}

pub fn can_fulfil_input_request(method: &str, params: Option<&Value>) -> bool {
    match method {
        "sampling/createMessage" | "roots/list" => true,
        "elicitation/create" => {
            params
                .and_then(|params| params.get("mode"))
                .and_then(Value::as_str)
                != Some("url")
        }
        _ => false,
    }
}

pub fn client_declared_capability_for(
    method: &str,
    capabilities: Option<&Map<String, Value>>,
) -> bool {
    let required = match method {
        "sampling/createMessage" => "sampling",
        "roots/list" => "roots",
        "elicitation/create" => "elicitation",
        _ => return false,
    };
    capabilities.is_some_and(|capabilities| capabilities.contains_key(required))
}

#[derive(Debug, Clone, PartialEq)]
pub enum TranslatedResult {
    Result(Value),
    Error { code: i64, message: String },
}

pub fn translate_modern_result(result: Value) -> TranslatedResult {
    let Value::Object(mut rest) = result else {
        return TranslatedResult::Result(result);
    };

    match rest.remove("resultType") {
        None => TranslatedResult::Result(Value::Object(rest)),
        Some(Value::String(result_type)) if result_type == "complete" => {
            TranslatedResult::Result(Value::Object(rest))
        }
        Some(Value::String(result_type)) if result_type == "input_required" => {
            TranslatedResult::Error {
                code: -32603,
                message: "The remote server asked for more input mid-request (a 2026-07-28 multi-round-trip request). \
                    The local client speaks a protocol revision with no way to answer that, so the request cannot be completed."
                    .to_string(),
            }
        }
        Some(result_type) => {
            let result_type = match result_type {
                Value::String(text) => text,
                other => other.to_string(),
            };
            TranslatedResult::Error {
                code: -32603,
                message: format!(
                    "The remote server returned a result of an unrecognised type: {result_type}"
                ),
            }
        }
    }
}

pub const MAX_INPUT_REQUIRED_ROUNDS: usize = 10;

pub const MAX_INPUT_REQUESTS_PER_ROUND: usize = 8;

fn is_truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(Value::Number(number)) => number.as_f64().is_some_and(|number| number != 0.0),
        Some(Value::String(text)) => !text.is_empty(),
        Some(Value::Array(_) | Value::Object(_)) => true,
    }
}

pub fn subscription_filter_for(
    capabilities: Option<&Map<String, Value>>,
    resource_subscriptions: &[String],
) -> Option<Value> {
    let announces_changes = |capability: &str| {
        is_truthy(
            capabilities
                .and_then(|capabilities| capabilities.get(capability))
                .and_then(|capability| capability.get("listChanged")),
        )
    };

    let mut filter = Map::new();
    for (capability, key) in [
        ("tools", "toolsListChanged"),
        ("prompts", "promptsListChanged"),
        ("resources", "resourcesListChanged"),
    ] {
        if announces_changes(capability) {
            filter.insert(key.to_string(), Value::Bool(true));
        }
    }
    if !resource_subscriptions.is_empty() {
        filter.insert(
            "resourceSubscriptions".to_string(),
            Value::from(resource_subscriptions.to_vec()),
        );
    }

    (!filter.is_empty()).then_some(Value::Object(filter))
}

pub fn unacknowledged_subscriptions(
    requested: &Map<String, Value>,
    acknowledged: Option<&Value>,
) -> Vec<String> {
    let Some(Value::Object(granted)) = acknowledged else {
        return Vec::new();
    };

    requested
        .iter()
        .filter(|(key, asked)| {
            if key.as_str() == "resourceSubscriptions" {
                let got = granted
                    .get("resourceSubscriptions")
                    .and_then(Value::as_array)
                    .map(Vec::as_slice)
                    .unwrap_or_default();
                return asked
                    .as_array()
                    .is_some_and(|asked| asked.iter().any(|uri| !got.contains(uri)));
            }
            !is_truthy(granted.get(key.as_str()))
        })
        .map(|(key, _)| key.clone())
        .collect()
}

pub fn input_required_retry_params(
    original_params: Option<&Value>,
    responses: &Map<String, Value>,
    request_state: Option<&str>,
) -> Value {
    let mut params = match original_params {
        Some(Value::Object(original)) => original.clone(),
        _ => Map::new(),
    };
    if !responses.is_empty() {
        params.insert(
            "inputResponses".to_string(),
            Value::Object(responses.clone()),
        );
    }
    if let Some(request_state) = request_state {
        params.insert(
            "requestState".to_string(),
            Value::String(request_state.to_string()),
        );
    }
    Value::Object(params)
}

pub const PROTOCOL_VERSION_META_KEY: &str = "io.modelcontextprotocol/protocolVersion";
pub const CLIENT_CAPABILITIES_META_KEY: &str = "io.modelcontextprotocol/clientCapabilities";
pub const CLIENT_INFO_META_KEY: &str = "io.modelcontextprotocol/clientInfo";
pub const SERVER_INFO_META_KEY: &str = "io.modelcontextprotocol/serverInfo";
pub const LOG_LEVEL_META_KEY: &str = "io.modelcontextprotocol/logLevel";
pub const SUBSCRIPTION_ID_META_KEY: &str = "io.modelcontextprotocol/subscriptionId";

#[derive(Clone, Debug, Default, PartialEq)]
pub struct LegacyClientIdentity {
    pub protocol_version: Option<String>,
    pub capabilities: Option<Map<String, Value>>,
    pub client_info: Option<Value>,
}

fn object_at(value: Option<&Value>) -> Map<String, Value> {
    match value {
        Some(Value::Object(map)) => map.clone(),
        _ => Map::new(),
    }
}

fn with_meta(message: &Value, meta: Map<String, Value>) -> Value {
    let mut stamped = object_at(Some(message));
    let mut params = object_at(message.get("params"));
    params.insert("_meta".to_string(), Value::Object(meta));
    stamped.insert("params".to_string(), Value::Object(params));
    Value::Object(stamped)
}

fn keep_or(meta: &mut Map<String, Value>, key: &str, fallback: Value) {
    let kept = match meta.get(key) {
        Some(existing) if !existing.is_null() => existing.clone(),
        _ => fallback,
    };
    meta.insert(key.to_string(), kept);
}

pub fn stamp_log_level(message: Value, log_level: Option<&str>) -> Value {
    let Some(log_level) = log_level.filter(|level| !level.is_empty()) else {
        return message;
    };
    let mut meta = object_at(message.get("params").and_then(|params| params.get("_meta")));
    meta.insert(
        LOG_LEVEL_META_KEY.to_string(),
        Value::String(log_level.to_string()),
    );
    with_meta(&message, meta)
}

pub fn stamp_modern_meta(message: &Value, identity: &LegacyClientIdentity, version: &str) -> Value {
    let mut meta = object_at(message.get("params").and_then(|params| params.get("_meta")));
    keep_or(
        &mut meta,
        PROTOCOL_VERSION_META_KEY,
        Value::String(version.to_string()),
    );
    keep_or(
        &mut meta,
        CLIENT_CAPABILITIES_META_KEY,
        Value::Object(identity.capabilities.clone().unwrap_or_default()),
    );
    if let Some(client_info) = &identity.client_info {
        keep_or(&mut meta, CLIENT_INFO_META_KEY, client_info.clone());
    }
    with_meta(message, meta)
}

pub fn subscriptions_listen_request(
    id: &str,
    identity: &LegacyClientIdentity,
    version: &str,
    notifications: &Map<String, Value>,
) -> Value {
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "subscriptions/listen",
        "params": { "notifications": notifications },
    });
    stamp_modern_meta(&request, identity, version)
}

pub fn strip_subscription_meta(message: Value) -> Value {
    let Some(Value::Object(meta)) = message.get("params").and_then(|params| params.get("_meta"))
    else {
        return message;
    };
    if !meta.contains_key(SUBSCRIPTION_ID_META_KEY) {
        return message;
    }

    let mut rest = meta.clone();
    rest.shift_remove(SUBSCRIPTION_ID_META_KEY);
    let mut params = object_at(message.get("params"));
    if rest.is_empty() {
        params.shift_remove("_meta");
    } else {
        params.insert("_meta".to_string(), Value::Object(rest));
    }
    let mut stripped = object_at(Some(&message));
    stripped.insert("params".to_string(), Value::Object(params));
    Value::Object(stripped)
}

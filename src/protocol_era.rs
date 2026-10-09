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

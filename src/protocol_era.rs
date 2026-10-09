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

use serde_json::{Map, Value, json};

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

pub const FIRST_MODERN_PROTOCOL_VERSION: &str = "2026-07-28";

pub const SUPPORTED_MODERN_VERSIONS: [&str; 1] = [FIRST_MODERN_PROTOCOL_VERSION];

pub const RETIRED_SUBSCRIBE_RESOURCE: &str = "resources/subscribe";
pub const RETIRED_UNSUBSCRIBE_RESOURCE: &str = "resources/unsubscribe";
pub const RETIRED_SET_LOG_LEVEL: &str = "logging/setLevel";

pub fn discover_request(id: &str, identity: &LegacyClientIdentity) -> Value {
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "server/discover",
        "params": {},
    });
    stamp_modern_meta(&request, identity, FIRST_MODERN_PROTOCOL_VERSION)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ProtocolMode {
    #[default]
    Legacy,
    Auto,
}

impl ProtocolMode {
    pub fn as_str(self) -> &'static str {
        match self {
            ProtocolMode::Legacy => "legacy",
            ProtocolMode::Auto => "auto",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum EraVerdict {
    Legacy { reason: String },
    Modern { version: String, discover: Value },
    Incompatible { reason: String },
}

const MODERN_ERROR_CODES: [i64; 1] = [-32022];

pub fn read_era_from_discover_response(message: &Value) -> EraVerdict {
    if let Some(error) = message.get("error").filter(|error| is_truthy(Some(error))) {
        let code = error.get("code");
        if !code
            .and_then(Value::as_i64)
            .is_some_and(|code| MODERN_ERROR_CODES.contains(&code))
        {
            let code = code.map_or("undefined".to_string(), Value::to_string);
            return EraVerdict::Legacy {
                reason: format!("the server answered server/discover with error {code}"),
            };
        }

        let supported = parse_supported_versions(error.get("data"));
        if let Some(version) = supported.as_deref().and_then(choose_modern_version) {
            return EraVerdict::Incompatible {
                reason: format!(
                    "the server asked for protocol version {version}, which the probe already offered"
                ),
            };
        }

        return match supported {
            Some(supported)
                if supported
                    .iter()
                    .all(|offered| offered.as_str() >= FIRST_MODERN_PROTOCOL_VERSION) =>
            {
                EraVerdict::Incompatible {
                    reason: format!(
                        "the server offers {}, and this proxy speaks {}",
                        supported.join(", "),
                        SUPPORTED_MODERN_VERSIONS.join(", ")
                    ),
                }
            }
            Some(supported) => EraVerdict::Legacy {
                reason: format!(
                    "the server offers no modern revision this proxy speaks (it offers {})",
                    supported.join(", ")
                ),
            },
            None => EraVerdict::Legacy {
                reason: "the server offers no modern revision this proxy speaks".to_string(),
            },
        };
    }

    let Some(discover) = message
        .get("result")
        .filter(|result| is_discover_result(result))
    else {
        return EraVerdict::Legacy {
            reason:
                "the server answered server/discover with something that is not a DiscoverResult"
                    .to_string(),
        };
    };

    let supported_versions: Vec<String> = discover["supportedVersions"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|version| version.as_str().map(str::to_string))
        .collect();
    match choose_modern_version(&supported_versions) {
        Some(version) => EraVerdict::Modern {
            version: version.to_string(),
            discover: discover.clone(),
        },
        None => EraVerdict::Incompatible {
            reason: format!(
                "the server offers {}, and this proxy speaks {}",
                supported_versions.join(", "),
                SUPPORTED_MODERN_VERSIONS.join(", ")
            ),
        },
    }
}

fn choose_modern_version(supported_versions: &[String]) -> Option<&'static str> {
    SUPPORTED_MODERN_VERSIONS.into_iter().find(|candidate| {
        supported_versions
            .iter()
            .any(|offered| offered == candidate)
    })
}

fn parse_supported_versions(data: Option<&Value>) -> Option<Vec<String>> {
    let versions: Vec<String> = data?
        .get("supported")?
        .as_array()?
        .iter()
        .filter_map(|entry| entry.as_str().map(str::to_string))
        .collect();
    (!versions.is_empty()).then_some(versions)
}

fn optional(object: &Map<String, Value>, key: &str, valid: impl Fn(&Value) -> bool) -> bool {
    object.get(key).is_none_or(valid)
}

fn is_json_object(value: &Value) -> bool {
    value.is_object()
}

fn is_record_of_json_objects(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|record| record.values().all(is_json_object))
}

fn is_list_changed_object(value: &Value, flags: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        flags
            .iter()
            .all(|flag| optional(object, flag, Value::is_boolean))
    })
}

fn is_tasks_capability(value: &Value) -> bool {
    let Some(tasks) = value.as_object() else {
        return false;
    };
    optional(tasks, "list", is_json_object)
        && optional(tasks, "cancel", is_json_object)
        && optional(tasks, "requests", |requests| {
            requests.as_object().is_some_and(|requests| {
                optional(requests, "tools", |tools| {
                    tools
                        .as_object()
                        .is_some_and(|tools| optional(tools, "call", is_json_object))
                })
            })
        })
}

fn is_server_capabilities(value: &Value) -> bool {
    let Some(capabilities) = value.as_object() else {
        return false;
    };
    optional(capabilities, "experimental", is_record_of_json_objects)
        && optional(capabilities, "logging", is_json_object)
        && optional(capabilities, "completions", is_json_object)
        && optional(capabilities, "prompts", |prompts| {
            is_list_changed_object(prompts, &["listChanged"])
        })
        && optional(capabilities, "resources", |resources| {
            is_list_changed_object(resources, &["subscribe", "listChanged"])
        })
        && optional(capabilities, "tools", |tools| {
            is_list_changed_object(tools, &["listChanged"])
        })
        && optional(capabilities, "tasks", is_tasks_capability)
        && optional(capabilities, "extensions", is_record_of_json_objects)
}

fn is_discover_result(value: &Value) -> bool {
    let Some(result) = value.as_object() else {
        return false;
    };
    optional(result, "_meta", is_json_object)
        && result
            .get("supportedVersions")
            .and_then(Value::as_array)
            .is_some_and(|versions| versions.iter().all(Value::is_string))
        && result
            .get("capabilities")
            .is_some_and(is_server_capabilities)
        && optional(result, "instructions", Value::is_string)
}

pub const LATEST_PROTOCOL_VERSION: &str = "2025-11-25";

pub const SUPPORTED_PROTOCOL_VERSIONS: [&str; 5] = [
    LATEST_PROTOCOL_VERSION,
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
    "2024-10-07",
];

pub fn synthesize_initialize_result(discover: &Value, identity: &LegacyClientIdentity) -> Value {
    let protocol_version = identity
        .protocol_version
        .as_deref()
        .filter(|requested| SUPPORTED_PROTOCOL_VERSIONS.contains(requested))
        .unwrap_or(LATEST_PROTOCOL_VERSION);

    let advertised = discover
        .get("_meta")
        .and_then(|meta| meta.get(SERVER_INFO_META_KEY));
    let server_info = match advertised {
        Some(advertised) if is_truthy(advertised.get("name")) => advertised.clone(),
        _ => json!({ "name": "remote MCP server", "version": FIRST_MODERN_PROTOCOL_VERSION }),
    };

    let capabilities = match discover.get("capabilities") {
        Some(Value::Null) | None => Value::Object(Map::new()),
        Some(capabilities) => capabilities.clone(),
    };

    let mut result = Map::new();
    result.insert("protocolVersion".to_string(), json!(protocol_version));
    result.insert("capabilities".to_string(), capabilities);
    result.insert("serverInfo".to_string(), server_info);
    if is_truthy(discover.get("instructions")) {
        result.insert("instructions".to_string(), discover["instructions"].clone());
    }
    Value::Object(result)
}

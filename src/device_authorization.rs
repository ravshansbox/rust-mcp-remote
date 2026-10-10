use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use url::Url;

use crate::logging::{debug_log, log};

pub const DEVICE_CODE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";

const DEFAULT_POLL_INTERVAL_SECONDS: f64 = 5.0;

const SLOW_DOWN_INCREMENT_SECONDS: f64 = 5.0;

const DEFAULT_EXPIRY_SECONDS: f64 = 30.0 * 60.0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormRequest {
    pub headers: Vec<(String, String)>,
    pub params: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormResponse {
    pub status: u16,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DeviceAuthorizationResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    pub expires_in: Option<f64>,
    pub interval: Option<f64>,
}

pub fn polling_schedule(authorization: &DeviceAuthorizationResponse) -> (f64, f64) {
    (
        authorization
            .interval
            .unwrap_or(DEFAULT_POLL_INTERVAL_SECONDS),
        authorization.expires_in.unwrap_or(DEFAULT_EXPIRY_SECONDS),
    )
}

pub fn error_detail(body: Option<&str>, status_text: &str) -> String {
    match body {
        Some(text) if !text.is_empty() => text.chars().take(500).collect(),
        _ => status_text.to_string(),
    }
}

pub fn verification_prompt_lines(authorization: &DeviceAuthorizationResponse) -> Vec<String> {
    let link = authorization
        .verification_uri_complete
        .as_deref()
        .unwrap_or(&authorization.verification_uri);
    let mut lines = vec![
        String::new(),
        "To authorize this client, visit:".to_string(),
        format!("  {link}"),
    ];
    if authorization.verification_uri_complete.is_none() {
        lines.push(String::new());
        lines.push(format!("And enter the code: {}", authorization.user_code));
    }
    lines.push(String::new());
    lines.push("Waiting for approval...".to_string());
    lines
}

pub fn parse_device_authorization_response(
    body: &Value,
) -> Result<DeviceAuthorizationResponse, String> {
    let required = |name: &str| {
        body.get(name)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    };
    match (
        required("device_code"),
        required("user_code"),
        required("verification_uri"),
    ) {
        (Some(device_code), Some(user_code), Some(verification_uri)) => {
            Ok(DeviceAuthorizationResponse {
                device_code,
                user_code,
                verification_uri,
                verification_uri_complete: body
                    .get("verification_uri_complete")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                expires_in: body.get("expires_in").and_then(Value::as_f64),
                interval: body.get("interval").and_then(Value::as_f64),
            })
        }
        _ => Err(
            "The authorization server returned an incomplete device authorization response"
                .to_string(),
        ),
    }
}

pub fn build_device_authorization_request(
    auth_method: &str,
    client_id: &str,
    client_secret: Option<&str>,
    scope: Option<&str>,
    resource: Option<&str>,
) -> Result<FormRequest, String> {
    let mut headers = form_headers();
    let mut params = Vec::new();
    apply_client_authentication(
        auth_method,
        client_id,
        client_secret,
        &mut headers,
        &mut params,
    )?;
    if let Some(scope) = scope.filter(|scope| !scope.is_empty()) {
        set_pair(&mut params, "scope", scope, false);
    }
    if let Some(resource) = resource {
        set_pair(&mut params, "resource", resource, false);
    }
    Ok(FormRequest { headers, params })
}

pub(crate) fn form_headers() -> Vec<(String, String)> {
    vec![
        (
            "content-type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        ),
        ("accept".to_string(), "application/json".to_string()),
    ]
}

pub fn build_device_token_request(
    auth_method: &str,
    client_id: &str,
    client_secret: Option<&str>,
    device_code: &str,
    resource: Option<&str>,
) -> Result<FormRequest, String> {
    let mut headers = form_headers();
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

pub fn poll_for_tokens(
    token_endpoint: &str,
    authorization: &DeviceAuthorizationResponse,
    request: &FormRequest,
    mut now_ms: impl FnMut() -> f64,
    mut sleep: impl FnMut(f64),
    mut post: impl FnMut(&str, &FormRequest) -> Result<FormResponse, String>,
) -> Result<Value, String> {
    let (mut interval_seconds, expires_in) = polling_schedule(authorization);
    let deadline = now_ms() + expires_in * 1000.0;

    while now_ms() < deadline {
        sleep(interval_seconds);

        let response = post(token_endpoint, request)?;
        let body = serde_json::from_str::<Value>(&response.body).ok();
        if (200..300).contains(&response.status) {
            log("Authorized.", &[]);
            return match body {
                Some(tokens)
                    if tokens.get("access_token").is_some_and(Value::is_string)
                        && tokens.get("token_type").is_some_and(Value::is_string) =>
                {
                    Ok(tokens)
                }
                _ => Err("The token endpoint returned an invalid token response".to_string()),
            };
        }

        interval_seconds = next_poll_interval(response.status, body.as_ref(), interval_seconds)?;
    }

    Err("The device code expired before it was approved".to_string())
}

pub fn authorize_with_device_code(
    metadata: &Value,
    client_information: &Value,
    scope: Option<&str>,
    resource: Option<&Url>,
    now_ms: impl FnMut() -> f64,
    sleep: impl FnMut(f64),
    mut post: impl FnMut(&str, &FormRequest) -> Result<FormResponse, String>,
) -> Result<Value, String> {
    let Some(device_authorization_endpoint) = metadata
        .get("device_authorization_endpoint")
        .and_then(Value::as_str)
    else {
        return Err(
            "The authorization server does not offer a device authorization endpoint".to_string(),
        );
    };
    let Some(token_endpoint) = metadata
        .get("token_endpoint")
        .and_then(Value::as_str)
        .filter(|endpoint| !endpoint.is_empty())
    else {
        return Err("The authorization server metadata has no token endpoint".to_string());
    };

    let supported_methods: Vec<&str> = metadata
        .get("token_endpoint_auth_methods_supported")
        .and_then(Value::as_array)
        .map(|methods| methods.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let auth_method = select_client_auth_method(client_information, &supported_methods);
    let client_id = client_information
        .get("client_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let client_secret = client_information
        .get("client_secret")
        .and_then(Value::as_str);
    let resource = resource.map(Url::as_str);

    let request =
        build_device_authorization_request(auth_method, client_id, client_secret, scope, resource)?;
    debug_log(
        "Requesting device authorization",
        &[json!({ "endpoint": device_authorization_endpoint, "scope": scope })],
    );
    let response = post(device_authorization_endpoint, &request)?;
    if !(200..300).contains(&response.status) {
        return Err(format!(
            "Device authorization request failed (HTTP {}): {}",
            response.status,
            error_detail(Some(&response.body), "")
        ));
    }
    let body = serde_json::from_str::<Value>(&response.body).unwrap_or(Value::Null);
    let authorization = parse_device_authorization_response(&body)?;
    debug_log(
        "Device authorization issued",
        &[json!({
            "verification_uri": authorization.verification_uri,
            "expires_in": authorization.expires_in,
            "interval": authorization.interval,
        })],
    );

    for line in verification_prompt_lines(&authorization) {
        log(&line, &[]);
    }

    let token_request = build_device_token_request(
        auth_method,
        client_id,
        client_secret,
        &authorization.device_code,
        resource,
    )?;
    poll_for_tokens(
        token_endpoint,
        &authorization,
        &token_request,
        now_ms,
        sleep,
        post,
    )
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

pub fn select_client_auth_method(
    client_information: &Value,
    supported_methods: &[&str],
) -> &'static str {
    let has_client_secret = client_information.get("client_secret").is_some();
    let registered = client_information
        .get("token_endpoint_auth_method")
        .and_then(Value::as_str)
        .and_then(|method| {
            ["client_secret_basic", "client_secret_post", "none"]
                .into_iter()
                .find(|known| *known == method)
        });
    if let Some(method) = registered
        && (supported_methods.is_empty() || supported_methods.contains(&method))
    {
        return method;
    }
    if supported_methods.is_empty() {
        return if has_client_secret {
            "client_secret_basic"
        } else {
            "none"
        };
    }
    if has_client_secret && supported_methods.contains(&"client_secret_basic") {
        return "client_secret_basic";
    }
    if has_client_secret && supported_methods.contains(&"client_secret_post") {
        return "client_secret_post";
    }
    if supported_methods.contains(&"none") {
        return "none";
    }
    if has_client_secret {
        "client_secret_post"
    } else {
        "none"
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

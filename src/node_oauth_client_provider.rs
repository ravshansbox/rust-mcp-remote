use base64::Engine;
use base64::alphabet;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::logging::debug_log;

const URL_SAFE_ANY_PADDING: GeneralPurpose = GeneralPurpose::new(
    &alphabet::URL_SAFE,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

const FALLBACK_SCOPE: &str = "openid email profile";

const TOKEN_ENDPOINT_AUTH_METHOD_PREFERENCE: [&str; 3] =
    ["none", "client_secret_post", "client_secret_basic"];

pub fn token_endpoint_auth_method(authorization_server_metadata: Option<&Value>) -> &'static str {
    let Some(supported) = authorization_server_metadata
        .and_then(|metadata| metadata.get("token_endpoint_auth_methods_supported"))
        .and_then(Value::as_array)
        .filter(|supported| !supported.is_empty())
    else {
        return "none";
    };

    let Some(method) = TOKEN_ENDPOINT_AUTH_METHOD_PREFERENCE
        .into_iter()
        .find(|candidate| {
            supported
                .iter()
                .any(|value| value.as_str() == Some(candidate))
        })
    else {
        debug_log(
            "Authorization server advertises no token endpoint auth method this client can perform",
            &[json!({ "token_endpoint_auth_methods_supported": supported })],
        );
        return "none";
    };

    if method != "none" {
        debug_log(
            "Registering with the token endpoint auth method the authorization server advertises",
            &[json!({
                "token_endpoint_auth_method": method,
                "token_endpoint_auth_methods_supported": supported,
            })],
        );
    }
    method
}

pub fn code_challenge_for(code_verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()))
}

pub fn jwt_expires_at(token: &str) -> Option<f64> {
    let payload = token
        .split('.')
        .nth(1)
        .filter(|payload| !payload.is_empty())?;
    let bytes = URL_SAFE_ANY_PADDING.decode(payload).ok()?;
    let claims: Value = serde_json::from_str(&String::from_utf8_lossy(&bytes)).ok()?;
    claims.get("exp")?.as_f64().map(|exp| exp * 1000.0)
}

pub fn bearer_expires_at(use_id_token: bool, tokens: &Value) -> Option<f64> {
    let expires_at = tokens.get("expires_at").and_then(Value::as_f64);
    let id_token = tokens
        .get("id_token")
        .and_then(Value::as_str)
        .filter(|id_token| !id_token.is_empty());
    match id_token {
        Some(id_token) if use_id_token => jwt_expires_at(id_token).or(expires_at),
        _ => expires_at,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthError {
    pub code: String,
    pub message: String,
}

pub fn stale_client_registration_error(value: &Value) -> Option<OAuthError> {
    let response = value.as_object()?;
    let code = response
        .get("error")
        .and_then(Value::as_str)
        .filter(|code| matches!(*code, "invalid_client" | "unauthorized_client"))?;
    let message = response
        .get("error_description")
        .and_then(Value::as_str)
        .unwrap_or("Cached OAuth client registration is no longer valid");
    Some(OAuthError {
        code: code.to_string(),
        message: message.to_string(),
    })
}

pub fn is_issued_state(state: &str) -> bool {
    (1..=64).contains(&state.len())
        && state
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

const TOKEN_EXPIRY_MARGIN_MS: f64 = 60_000.0;

pub fn is_token_expired(expires_at: Option<f64>, now_ms: f64) -> bool {
    expires_at
        .filter(|expires_at| *expires_at != 0.0 && !expires_at.is_nan())
        .is_some_and(|expires_at| now_ms >= expires_at - TOKEN_EXPIRY_MARGIN_MS)
}

pub fn is_sibling_token_fresh(expires_at: Option<f64>, now_ms: f64) -> bool {
    expires_at.is_some_and(|expires_at| now_ms < expires_at - TOKEN_EXPIRY_MARGIN_MS)
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ScopeSources<'a> {
    pub static_oauth_client_metadata: Option<&'a Value>,
    pub www_authenticate_scope: Option<&'a str>,
    pub protected_resource_metadata: Option<&'a Value>,
    pub client_information: Option<&'a Value>,
    pub authorization_server_metadata: Option<&'a Value>,
}

fn non_blank_scope(metadata: Option<&Value>) -> Option<&str> {
    metadata
        .and_then(|metadata| metadata.get("scope"))
        .and_then(Value::as_str)
        .filter(|scope| !scope.trim().is_empty())
}

fn joined_scopes(scopes_supported: &[Value]) -> String {
    scopes_supported
        .iter()
        .map(|scope| match scope {
            Value::String(scope) => scope.clone(),
            other => other.to_string(),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn requested_scope(sources: &ScopeSources) -> Option<String> {
    if let Some(scope) = non_blank_scope(sources.static_oauth_client_metadata) {
        debug_log(
            "Using scope from staticOAuthClientMetadata",
            &[json!({ "scope": scope })],
        );
        return Some(scope.to_string());
    }

    if let Some(scope) = sources
        .www_authenticate_scope
        .filter(|scope| !scope.trim().is_empty())
    {
        debug_log(
            "Using scope from WWW-Authenticate header",
            &[json!({ "scope": scope })],
        );
        return Some(scope.to_string());
    }

    if let Some(resource_scopes) = sources
        .protected_resource_metadata
        .and_then(|metadata| metadata.get("scopes_supported"))
        .and_then(Value::as_array)
    {
        if resource_scopes.is_empty() {
            debug_log(
                "Protected resource advertises no scopes (scopes_supported: []), omitting scope",
                &[],
            );
            return Some(String::new());
        }
        let scope = joined_scopes(resource_scopes);
        debug_log(
            "Using scopes from Protected Resource Metadata",
            &[json!({ "scopes_supported": resource_scopes, "scope": scope })],
        );
        return Some(scope);
    }

    if let Some(scope) = non_blank_scope(sources.client_information) {
        debug_log(
            "Using scope from client registration response",
            &[json!({ "scope": scope })],
        );
        return Some(scope.to_string());
    }

    if let Some(auth_scopes) = sources
        .authorization_server_metadata
        .and_then(|metadata| metadata.get("scopes_supported"))
        .and_then(Value::as_array)
    {
        if auth_scopes.is_empty() {
            debug_log(
                "Authorization server advertises no scopes (scopes_supported: []), omitting scope",
                &[],
            );
            return Some(String::new());
        }
        let scope = joined_scopes(auth_scopes);
        debug_log(
            "Using scopes from Authorization Server Metadata",
            &[json!({ "scopes_supported": auth_scopes, "scope": scope })],
        );
        return Some(scope);
    }

    debug_log("No source describes the scope to request", &[]);
    None
}

pub fn effective_scope(sources: &ScopeSources, has_explicit_token_endpoint: bool) -> String {
    requested_scope(sources).unwrap_or_else(|| {
        if has_explicit_token_endpoint {
            String::new()
        } else {
            FALLBACK_SCOPE.to_string()
        }
    })
}

pub fn scope_request_changed(tokens: &Value, sources: &ScopeSources) -> bool {
    let Some(obtained_for) = tokens.get("requested_scope").and_then(Value::as_str) else {
        return false;
    };
    let Some(requested) = requested_scope(sources) else {
        return false;
    };
    obtained_for != requested
}

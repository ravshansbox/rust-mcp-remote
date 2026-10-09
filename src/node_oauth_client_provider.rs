use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::alphabet;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use url::Url;

use crate::device_authorization::DEVICE_CODE_GRANT_TYPE;
use crate::logging::{debug_log, log};
use crate::mcp_auth_config::{read_config_lease, read_json_file};
use crate::utils::build_redirect_url;

const URL_SAFE_ANY_PADDING: GeneralPurpose = GeneralPurpose::new(
    &alphabet::URL_SAFE,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

const CODE_VERIFIER_PREFIX: &str = "code_verifier_";

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

pub fn as_bearer_tokens(
    use_id_token: bool,
    warned_about_missing_id_token: &mut bool,
    tokens: Option<Value>,
) -> Option<Value> {
    let mut tokens = tokens?;
    if !use_id_token {
        return Some(tokens);
    }

    let Some(id_token) = tokens
        .get("id_token")
        .and_then(Value::as_str)
        .filter(|id_token| !id_token.is_empty())
        .map(str::to_owned)
    else {
        if !*warned_about_missing_id_token {
            *warned_about_missing_id_token = true;
            log(
                "Warning: --use-id-token was passed but the authorization server issued no ID token, so the access token \
                 is being sent instead. An ID token is only returned when `openid` is among the requested scopes.",
                &[],
            );
        }
        return Some(tokens);
    };

    debug_log("Presenting the ID token as the bearer credential", &[]);
    tokens["access_token"] = Value::String(id_token);
    Some(tokens)
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

pub fn use_authorization_state(state: &str, incoming_state: &mut Option<String>) {
    if !is_issued_state(state) {
        log(
            "Ignoring an authorization state this client could not have issued",
            &[],
        );
        debug_log("Rejected authorization state", &[json!({ "state": state })]);
        return;
    }
    *incoming_state = Some(state.to_string());
}

pub fn flow_state<'a>(incoming_state: Option<&'a str>, state: &'a str) -> &'a str {
    incoming_state.unwrap_or(state)
}

const TOKEN_EXPIRY_MARGIN_MS: f64 = 60_000.0;

const TOKEN_STORM_LIMIT: usize = 20;
const TOKEN_STORM_WINDOW_MS: f64 = 30_000.0;

#[derive(Debug, Clone, Default)]
pub struct TokenStormBrake {
    recent_token_writes: Vec<f64>,
}

impl TokenStormBrake {
    pub fn in_token_storm(&mut self, now_ms: f64) -> bool {
        self.recent_token_writes
            .retain(|at| now_ms - at < TOKEN_STORM_WINDOW_MS);
        self.recent_token_writes.len() >= TOKEN_STORM_LIMIT
    }

    pub fn token_storm_error(&self) -> String {
        let seconds = TOKEN_STORM_WINDOW_MS / 1000.0;
        log(
            &format!(
                "Stopping: {TOKEN_STORM_LIMIT} access tokens were issued in the last {seconds}s and the MCP server \
                 rejected them all. Asking for another would only repeat the exchange."
            ),
            &[],
        );
        debug_log(
            "Token exchange loop detected",
            &[
                json!({ "writes": self.recent_token_writes.len(), "windowMs": TOKEN_STORM_WINDOW_MS }),
            ],
        );
        format!(
            "Stopped after {TOKEN_STORM_LIMIT} token exchanges in {seconds}s. The tokens being issued are not accepted \
             by the MCP server - check that its audience and scopes match, or sign in again."
        )
    }

    pub fn guard_against_token_storm(&mut self, now_ms: f64) -> Result<(), String> {
        if self.in_token_storm(now_ms) {
            return Err(self.token_storm_error());
        }
        self.recent_token_writes.push(now_ms);
        Ok(())
    }
}

const AUTHORIZATION_STORM_LIMIT: usize = 5;

#[derive(Debug, Clone, Default)]
pub struct AuthorizationStormBrake {
    recent_authorizations: Vec<f64>,
}

impl AuthorizationStormBrake {
    pub fn guard_against_authorization_storm(&mut self, now_ms: f64) -> Result<(), String> {
        self.recent_authorizations
            .retain(|at| now_ms - at < TOKEN_STORM_WINDOW_MS);

        if self.recent_authorizations.len() >= AUTHORIZATION_STORM_LIMIT {
            let seconds = TOKEN_STORM_WINDOW_MS / 1000.0;
            log(
                &format!(
                    "Stopping: {AUTHORIZATION_STORM_LIMIT} sign-ins were started in the last {seconds}s and none of them completed."
                ),
                &[],
            );
            debug_log(
                "Authorization loop detected",
                &[
                    json!({ "starts": self.recent_authorizations.len(), "windowMs": TOKEN_STORM_WINDOW_MS }),
                ],
            );
            return Err(format!(
                "Stopped after {AUTHORIZATION_STORM_LIMIT} sign-ins in {seconds}s, none of which completed. Opening another \
                 browser tab would only repeat it - check that the server accepts the tokens this client is being issued."
            ));
        }

        self.recent_authorizations.push(now_ms);
        Ok(())
    }
}

pub fn is_token_expired(expires_at: Option<f64>, now_ms: f64) -> bool {
    expires_at
        .filter(|expires_at| *expires_at != 0.0 && !expires_at.is_nan())
        .is_some_and(|expires_at| now_ms >= expires_at - TOKEN_EXPIRY_MARGIN_MS)
}

pub fn is_sibling_token_fresh(expires_at: Option<f64>, now_ms: f64) -> bool {
    expires_at.is_some_and(|expires_at| now_ms < expires_at - TOKEN_EXPIRY_MARGIN_MS)
}

pub const REFRESH_LEASE_FILE: &str = "refresh_in_progress.json";
const REFRESH_LEASE_MS: u64 = 30_000;
const REFRESH_POLL_MS: u64 = 200;

#[derive(Debug, Clone, PartialEq)]
pub enum SiblingRefresh {
    Tokens(Value),
    Released,
    Abandoned,
}

pub fn await_refresh_by_sibling(server_url_hash: &str) -> SiblingRefresh {
    debug_log(
        "Waiting for the instance already refreshing this token",
        &[],
    );

    loop {
        std::thread::sleep(Duration::from_millis(REFRESH_POLL_MS));

        let stored = read_json_file::<Value>(server_url_hash, "tokens.json");
        if let Some(stored) = stored {
            let expires_at = stored.get("expires_at").and_then(Value::as_f64);
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as f64;
            if is_sibling_token_fresh(expires_at, now_ms) {
                return SiblingRefresh::Tokens(stored);
            }
        }

        match read_config_lease(
            server_url_hash,
            REFRESH_LEASE_FILE,
            Duration::from_millis(REFRESH_LEASE_MS),
        ) {
            None => return SiblingRefresh::Released,
            Some(holder) if !holder.live => return SiblingRefresh::Abandoned,
            Some(_) => {}
        }
    }
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

pub fn tokens_to_save(tokens: &Value, effective_scope: &str, now_ms: f64) -> Value {
    let mut saved = tokens.as_object().cloned().unwrap_or_default();
    let expires_at = tokens
        .get("expires_at")
        .filter(|expires_at| !expires_at.is_null())
        .cloned()
        .or_else(|| {
            tokens
                .get("expires_in")
                .and_then(Value::as_f64)
                .filter(|expires_in| *expires_in != 0.0)
                .map(|expires_in| json!(now_ms + expires_in * 1000.0))
        });
    match expires_at {
        Some(expires_at) => saved.insert("expires_at".into(), expires_at),
        None => saved.remove("expires_at"),
    };
    saved.insert("requested_scope".into(), json!(effective_scope));
    Value::Object(saved)
}

fn set_search_param(url: &mut Url, key: &str, value: &str) {
    let mut found = false;
    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .into_owned()
        .filter_map(|(name, existing)| {
            if name != key {
                return Some((name, existing));
            }
            if found {
                return None;
            }
            found = true;
            Some((name, value.to_string()))
        })
        .collect();
    let mut serializer = url.query_pairs_mut();
    serializer.clear().extend_pairs(&pairs);
    if !found {
        serializer.append_pair(key, value);
    }
}

pub fn grant_types(use_client_credentials: bool, use_device_code: bool) -> Vec<&'static str> {
    if use_client_credentials {
        return vec!["client_credentials"];
    }
    if use_device_code {
        return vec![DEVICE_CODE_GRANT_TYPE, "refresh_token"];
    }
    vec!["authorization_code", "refresh_token"]
}

pub struct ClientMetadataSources<'a> {
    pub redirect_url: Option<&'a str>,
    pub token_endpoint_auth_method: &'a str,
    pub grant_types: Vec<&'a str>,
    pub client_name: &'a str,
    pub client_uri: &'a str,
    pub software_id: &'a str,
    pub software_version: &'a str,
    pub static_oauth_client_metadata: Option<&'a Value>,
    pub effective_scope: &'a str,
}

pub fn client_metadata(sources: &ClientMetadataSources) -> Value {
    let mut metadata = json!({
        "redirect_uris": sources.redirect_url.into_iter().collect::<Vec<_>>(),
        "token_endpoint_auth_method": sources.token_endpoint_auth_method,
        "grant_types": sources.grant_types,
        "response_types": ["code"],
        "client_name": sources.client_name,
        "client_uri": sources.client_uri,
        "software_id": sources.software_id,
        "software_version": sources.software_version,
    });
    let fields = metadata.as_object_mut().expect("metadata is an object");
    if let Some(Value::Object(static_metadata)) = sources.static_oauth_client_metadata {
        for (key, value) in static_metadata {
            fields.insert(key.clone(), value.clone());
        }
    }
    if !sources.effective_scope.is_empty() {
        fields.insert("scope".to_string(), json!(sources.effective_scope));
    }
    metadata
}

pub fn owns_pending_flow(authorization_url: &Url, pending_challenge: Option<&str>) -> bool {
    let Some(challenge) = pending_challenge else {
        return true;
    };
    authorization_url
        .query_pairs()
        .find(|(key, _)| key == "code_challenge")
        .is_some_and(|(_, value)| value == challenge)
}

pub fn code_verifier_file(state: &str) -> String {
    format!("{CODE_VERIFIER_PREFIX}{state}.txt")
}

pub fn apply_authorize_params(
    authorization_url: &mut Url,
    authorize_params: &std::collections::BTreeMap<String, String>,
) {
    for (key, value) in authorize_params {
        set_search_param(authorization_url, key, value);
    }

    if !authorize_params.is_empty() {
        debug_log(
            "Added extra parameters to authorization URL",
            &[json!({ "keys": authorize_params.keys().collect::<Vec<_>>() })],
        );
    }
}

pub fn apply_scope(
    authorization_url: &mut Url,
    sources: &ScopeSources,
    has_explicit_token_endpoint: bool,
) {
    let effective_scope = effective_scope(sources, has_explicit_token_endpoint);
    let requested = authorization_url
        .query_pairs()
        .find(|(name, _)| name == "scope")
        .map(|(_, scope)| scope.into_owned());
    let pinned_by_user = non_blank_scope(sources.static_oauth_client_metadata).is_some();
    let resource_scopes = sources
        .protected_resource_metadata
        .and_then(|metadata| metadata.get("scopes_supported"))
        .and_then(Value::as_array)
        .map(|scopes| joined_scopes(scopes));

    if let Some(requested) = requested.filter(|requested| !requested.is_empty())
        && !pinned_by_user
        && requested != effective_scope
        && resource_scopes.as_deref() != Some(requested.as_str())
    {
        log(
            &format!("Authorizing with the scope the server asked for: {requested}"),
            &[],
        );
        debug_log(
            "Keeping a scope this client did not supply",
            &[json!({ "scope": requested, "effectiveScope": effective_scope })],
        );
        return;
    }

    if effective_scope.is_empty() {
        debug_log(
            "Omitting scope parameter from authorization URL (no effective scope)",
            &[],
        );
    } else {
        set_search_param(authorization_url, "scope", &effective_scope);
        debug_log(
            "Added scope parameter to authorization URL",
            &[json!({ "scopes": effective_scope })],
        );
    }
}

pub fn has_explicit_token_endpoint(
    use_client_credentials: bool,
    token_endpoint: Option<&str>,
) -> bool {
    use_client_credentials && token_endpoint.is_some_and(|endpoint| !endpoint.is_empty())
}

pub fn redirect_url(
    has_explicit_token_endpoint: bool,
    host: &str,
    port: u16,
    callback_path: &str,
) -> Option<String> {
    if has_explicit_token_endpoint {
        return None;
    }
    Some(build_redirect_url(host, port, callback_path))
}

pub fn discovery_state(
    use_client_credentials: bool,
    token_endpoint: Option<&str>,
    resource_server_url: &str,
) -> Option<Value> {
    if !has_explicit_token_endpoint(use_client_credentials, token_endpoint) {
        return None;
    }
    let endpoint = Url::parse(token_endpoint?).ok()?;
    let origin = endpoint.origin().ascii_serialization();
    Some(json!({
        "authorizationServerUrl": origin,
        "authorizationServerMetadata": {
            "issuer": origin,
            "token_endpoint": endpoint.as_str(),
            "grant_types_supported": ["client_credentials"],
        },
        "resourceMetadata": {
            "resource": resource_server_url,
            "authorization_servers": [origin],
        },
    }))
}

pub struct TokenRequestSources<'a> {
    pub has_explicit_token_endpoint: bool,
    pub token_endpoint: Option<&'a str>,
    pub client_secret: Option<&'a str>,
    pub static_scope: Option<&'a str>,
    pub scope: Option<&'a str>,
}

pub fn prepare_token_request(
    sources: &TokenRequestSources,
    brake: &mut TokenStormBrake,
    now_ms: f64,
    www_authenticate_scope: &mut Option<String>,
) -> Result<Option<Vec<(&'static str, String)>>, String> {
    if !sources.has_explicit_token_endpoint {
        return Ok(None);
    }
    if brake.in_token_storm(now_ms) {
        return Err(brake.token_storm_error());
    }
    if sources.client_secret.is_none_or(str::is_empty) {
        return Err(
            "The client_credentials grant needs a client secret; supply it with --static-oauth-client-info"
                .to_string(),
        );
    }
    let mut params = vec![("grant_type", "client_credentials".to_string())];
    let effective_scope = sources
        .static_scope
        .map(str::trim)
        .filter(|scope| !scope.is_empty())
        .or(sources.scope)
        .map(str::to_string);
    if let Some(scope) = effective_scope.as_ref().filter(|scope| !scope.is_empty()) {
        params.push(("scope", scope.clone()));
    }
    *www_authenticate_scope = effective_scope;
    if let Some(endpoint) = sources
        .token_endpoint
        .and_then(|endpoint| Url::parse(endpoint).ok())
    {
        log(
            &format!(
                "Requesting a token from {} with the client_credentials grant",
                endpoint.origin().ascii_serialization()
            ),
            &[],
        );
    }
    Ok(Some(params))
}

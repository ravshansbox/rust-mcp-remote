//! A port of the SDK v2 OAuth client flow (`src/client/auth.ts` in @modelcontextprotocol/client):
//! metadata discovery, dynamic client registration, the PKCE authorization request, token
//! exchange and refresh, and the `auth()` orchestrator that ties them together. Metadata, client
//! information and tokens stay serde_json values, checked against the SDK's zod schemas by hand.
//! DPoP is left out: mcp-remote's provider never supplies a `dpop()` hook.

use std::future::Future;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Method, Request, Response};
use serde_json::{Map, Value, json};
use url::Url;

use crate::device_authorization::{apply_client_authentication, select_client_auth_method};
use crate::node_oauth_client_provider::CredentialScope;
use crate::protocol_era::LATEST_PROTOCOL_VERSION;
use crate::streamable_http::{FetchFn, default_fetch, is_within_origin, redirect_target};

const MAX_REDIRECTS: usize = 5;
const AUTHORIZATION_CODE_RESPONSE_TYPE: &str = "code";
const AUTHORIZATION_CODE_CHALLENGE_METHOD: &str = "S256";
const PKCE_MASK: &[u8; 66] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
const PKCE_VERIFIER_LENGTH: usize = 43;

pub const INVALID_CLIENT: &str = "invalid_client";
pub const UNAUTHORIZED_CLIENT: &str = "unauthorized_client";
pub const INVALID_GRANT: &str = "invalid_grant";
pub const INVALID_DPOP_PROOF: &str = "invalid_dpop_proof";
pub const SERVER_ERROR: &str = "server_error";
pub const INVALID_CLIENT_METADATA: &str = "invalid_client_metadata";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuerMismatchKind {
    Metadata,
    AuthorizationResponse,
}

/// The errors `auth()` and its helpers throw, one variant per SDK error class.
#[derive(Debug, Clone, PartialEq)]
pub enum AuthError {
    /// OAuthError: an error response from the authorization server.
    OAuth {
        code: String,
        message: String,
        error_uri: Option<String>,
    },
    IssuerMismatch {
        kind: IssuerMismatchKind,
        expected: String,
        received: Option<String>,
    },
    RegistrationRejected {
        status: u16,
        body: String,
        submitted_metadata: Value,
    },
    InsecureTokenEndpoint(String),
    AuthorizationServerMismatch {
        recorded: String,
        current: String,
    },
    Unauthorized(String),
    /// A request that never got a response: the TypeError discovery passes on instead of falling back.
    Network(String),
    Other(String),
}

impl AuthError {
    pub fn oauth(code: &str, message: impl Into<String>) -> Self {
        AuthError::OAuth {
            code: code.to_owned(),
            message: message.into(),
            error_uri: None,
        }
    }

    pub fn oauth_code(&self) -> Option<&str> {
        match self {
            AuthError::OAuth { code, .. } => Some(code),
            _ => None,
        }
    }
}

fn js_string(value: Option<&str>) -> String {
    value.map_or("undefined".to_owned(), |value| json!(value).to_string())
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::OAuth { message, .. } => formatter.write_str(message),
            AuthError::IssuerMismatch {
                kind,
                expected,
                received,
            } => write!(
                formatter,
                "Issuer mismatch in {}: expected {}, received {}",
                match kind {
                    IssuerMismatchKind::Metadata => "authorization server metadata (RFC 8414 §3.3)",
                    IssuerMismatchKind::AuthorizationResponse =>
                        "authorization response (RFC 9207)",
                },
                js_string(Some(expected)),
                js_string(received.as_deref())
            ),
            AuthError::RegistrationRejected { status, body, .. } => write!(
                formatter,
                "Dynamic Client Registration rejected (HTTP {status}): {body}"
            ),
            AuthError::InsecureTokenEndpoint(endpoint) => write!(
                formatter,
                "Refusing to send credentials to non-https token endpoint '{endpoint}'. OAuth token requests MUST use TLS (localhost / *.localhost / 127.0.0.1 / ::1 are exempt)."
            ),
            AuthError::AuthorizationServerMismatch { recorded, current } => write!(
                formatter,
                "Authorization server mismatch: credentials are bound to {} but this call resolved {}; refusing to present them to a different authorization server",
                js_string(Some(recorded)),
                js_string(Some(current))
            ),
            AuthError::Unauthorized(message)
            | AuthError::Network(message)
            | AuthError::Other(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for AuthError {}

/// What a provider records about discovery between the redirect and the callback.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct DiscoveryState {
    pub authorization_server_url: String,
    pub resource_metadata_url: Option<String>,
    pub resource_metadata: Option<Value>,
    pub authorization_server_metadata: Option<Value>,
}

impl DiscoveryState {
    /// Reads the camelCase object NodeOAuthClientProvider::discovery_state returns.
    pub fn from_value(value: &Value) -> Option<Self> {
        Some(Self {
            authorization_server_url: value.get("authorizationServerUrl")?.as_str()?.to_owned(),
            resource_metadata_url: value
                .get("resourceMetadataUrl")
                .and_then(Value::as_str)
                .map(str::to_owned),
            resource_metadata: value.get("resourceMetadata").cloned(),
            authorization_server_metadata: value.get("authorizationServerMetadata").cloned(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthResult {
    Authorized,
    Redirect,
}

/// The SDK's OAuthClientProvider. Optional TypeScript members are default methods, and a
/// `can_*`/`has_*` method answers whether the provider implements one where the SDK checks.
pub trait OAuthClientProvider: Send + Sync {
    fn redirect_url(&self) -> Option<String>;
    fn client_metadata(&self) -> Value;
    fn client_metadata_url(&self) -> Option<String> {
        None
    }
    fn state(&self) -> impl Future<Output = Result<Option<String>, AuthError>> + Send {
        async { Ok(None) }
    }
    fn client_information(&self, issuer: &str) -> impl Future<Output = Option<Value>> + Send;
    fn can_save_client_information(&self) -> bool {
        true
    }
    fn save_client_information(
        &self,
        client_information: &Value,
        issuer: &str,
    ) -> impl Future<Output = Result<(), AuthError>> + Send;
    fn tokens(&self, issuer: Option<&str>) -> impl Future<Output = Option<Value>> + Send;
    fn save_tokens(
        &self,
        tokens: &Value,
        issuer: &str,
    ) -> impl Future<Output = Result<(), AuthError>> + Send;
    fn redirect_to_authorization(
        &self,
        authorization_url: &Url,
    ) -> impl Future<Output = Result<(), AuthError>> + Send;
    fn save_code_verifier(
        &self,
        code_verifier: &str,
    ) -> impl Future<Output = Result<(), AuthError>> + Send;
    fn code_verifier(&self) -> impl Future<Output = Result<String, AuthError>> + Send;
    fn can_invalidate_credentials(&self) -> bool {
        false
    }
    fn invalidate_credentials(
        &self,
        _scope: CredentialScope,
    ) -> impl Future<Output = Result<(), AuthError>> + Send {
        async { Ok(()) }
    }
    fn has_validate_resource_url(&self) -> bool {
        false
    }
    fn validate_resource_url(
        &self,
        _default_resource: &Url,
        _discovered_resource: Option<&str>,
    ) -> impl Future<Output = Result<Option<Url>, AuthError>> + Send {
        async { Ok(None) }
    }
    fn prepare_token_request(
        &self,
        _scope: Option<&str>,
    ) -> impl Future<Output = Result<Option<Vec<(String, String)>>, AuthError>> + Send {
        async { Ok(None) }
    }
    fn has_add_client_authentication(&self) -> bool {
        false
    }
    fn add_client_authentication(
        &self,
        _headers: &mut Vec<(String, String)>,
        _params: &mut Vec<(String, String)>,
        _token_url: &Url,
        _metadata: Option<&Value>,
    ) -> impl Future<Output = Result<(), AuthError>> + Send {
        async { Ok(()) }
    }
    fn discovery_state(&self) -> impl Future<Output = Option<DiscoveryState>> + Send {
        async { None }
    }
    fn can_save_discovery_state(&self) -> bool {
        false
    }
    fn save_discovery_state(
        &self,
        _state: &DiscoveryState,
    ) -> impl Future<Output = Result<(), AuthError>> + Send {
        async { Ok(()) }
    }
    fn save_authorization_server_url(
        &self,
        _issuer: &str,
    ) -> impl Future<Output = Result<(), AuthError>> + Send {
        async { Ok(()) }
    }
    fn save_resource_url(
        &self,
        _resource: &str,
    ) -> impl Future<Output = Result<(), AuthError>> + Send {
        async { Ok(()) }
    }
}

#[derive(Clone)]
pub struct AuthOptions {
    pub server_url: Url,
    pub authorization_code: Option<String>,
    pub iss: Option<String>,
    pub scope: Option<String>,
    pub resource_metadata_url: Option<Url>,
    pub fetch: Option<FetchFn>,
    pub skip_issuer_metadata_validation: bool,
    pub force_reauthorization: bool,
}

impl AuthOptions {
    pub fn new(server_url: Url) -> Self {
        Self {
            server_url,
            authorization_code: None,
            iss: None,
            scope: None,
            resource_metadata_url: None,
            fetch: None,
            skip_issuer_metadata_validation: false,
            force_reauthorization: false,
        }
    }
}

fn warn(message: &str) {
    eprintln!("{message}");
}

/// SEP-2352 stamp check: a value stamped for another issuer reads back as absent.
pub fn discard_if_issuer_mismatch(
    stored: Option<Value>,
    issuer: &str,
    can_persist_stamp: bool,
) -> Option<Value> {
    let mut stored = stored?;
    match stored.get("issuer") {
        Some(Value::String(stamp)) => issuers_match(stamp, issuer).then_some(stored),
        other => {
            if can_persist_stamp {
                warn(
                    "[mcp-sdk] SEP-2352: stored OAuth credential has no 'issuer' stamp (pre-upgrade storage or provider not round-tripping the value). SEP-2352 isolation is inactive for this read; ensure your provider round-trips the issuer field.",
                );
            }
            if other.is_some()
                && let Some(object) = stored.as_object_mut()
            {
                object.remove("issuer");
            }
            Some(stored)
        }
    }
}

/// Issuer identity, tolerating one trailing `/` difference.
pub fn issuers_match(a: &str, b: &str) -> bool {
    a == b || a.strip_suffix('/') == Some(b) || b.strip_suffix('/') == Some(a)
}

fn is_iss_parameter_supported(metadata: Option<&Value>) -> bool {
    metadata.and_then(|metadata| metadata.get("authorization_response_iss_parameter_supported"))
        == Some(&Value::Bool(true))
}

/// RFC 9207 §2.4 check of the `iss` parameter on an authorization response.
pub fn validate_authorization_response_issuer(
    iss: Option<&str>,
    expected_issuer: Option<&str>,
    iss_parameter_supported: bool,
) -> Result<(), AuthError> {
    let Some(expected) = expected_issuer else {
        return Ok(());
    };
    let mismatch = |received: Option<&str>| AuthError::IssuerMismatch {
        kind: IssuerMismatchKind::AuthorizationResponse,
        expected: expected.to_owned(),
        received: received.map(str::to_owned),
    };
    match iss {
        None if iss_parameter_supported => Err(mismatch(None)),
        None => Ok(()),
        Some(iss) if iss != expected => Err(mismatch(Some(iss))),
        Some(_) => Ok(()),
    }
}

/// The union of space-delimited scope strings, in first-seen order.
pub fn compute_scope_union(scopes: &[Option<&str>]) -> Option<String> {
    let mut seen: Vec<&str> = Vec::new();
    for token in scopes
        .iter()
        .flatten()
        .flat_map(|scope| scope.split_whitespace())
    {
        if !seen.contains(&token) {
            seen.push(token);
        }
    }
    (!seen.is_empty()).then(|| seen.join(" "))
}

/// Whether `union` has a scope token `current` lacks.
pub fn is_strict_scope_superset(union: Option<&str>, current: Option<&str>) -> bool {
    let Some(union) = union.filter(|union| !union.is_empty()) else {
        return false;
    };
    let current: Vec<&str> = current.unwrap_or("").split_whitespace().collect();
    union
        .split_whitespace()
        .any(|token| !current.contains(&token))
}

/// The authorization code and `iss` from a callback, or the error it carries once `iss` checks out.
pub async fn resolve_authorization_callback_params<P: OAuthClientProvider>(
    params: &[(String, String)],
    provider: &P,
    server_url: &Url,
    fetch: Option<&FetchFn>,
) -> Result<(String, Option<String>), AuthError> {
    let get = |name: &str| {
        params
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    };
    let iss = get("iss");
    if let Some(code) = get("code").filter(|code| !code.is_empty()) {
        return Ok((code, iss));
    }
    let mut metadata = provider
        .discovery_state()
        .await
        .and_then(|state| state.authorization_server_metadata);
    if metadata.is_none() {
        metadata = discover_oauth_server_info(server_url, None, fetch, false)
            .await
            .ok()
            .and_then(|info| info.authorization_server_metadata);
    }
    let Some(metadata) = metadata else {
        return Err(AuthError::Unauthorized(
            "Authorization callback failed and the issuer could not be verified".to_owned(),
        ));
    };
    validate_authorization_response_issuer(
        iss.as_deref(),
        metadata.get("issuer").and_then(Value::as_str),
        is_iss_parameter_supported(Some(&metadata)),
    )?;
    if let Some(error) = get("error").filter(|error| !error.is_empty()) {
        return Err(AuthError::OAuth {
            message: get("error_description").unwrap_or_else(|| error.clone()),
            code: error,
            error_uri: get("error_uri"),
        });
    }
    Err(AuthError::Unauthorized(
        "Authorization callback contained neither `code` nor `error`".to_owned(),
    ))
}

fn is_loopback_host(hostname: &str) -> bool {
    hostname == "localhost"
        || hostname.ends_with(".localhost")
        || hostname == "127.0.0.1"
        || hostname == "[::1]"
        || hostname == "::1"
}

/// Refuses a token endpoint that is neither https nor on a loopback host.
pub fn assert_secure_token_endpoint(token_endpoint: &str) -> Result<Url, AuthError> {
    let url = Url::parse(token_endpoint).map_err(|_| AuthError::Other("Invalid URL".to_owned()))?;
    if url.scheme() != "https" && !is_loopback_host(url.host_str().unwrap_or("")) {
        return Err(AuthError::InsecureTokenEndpoint(url.to_string()));
    }
    Ok(url)
}

/// SEP-837: loopback or custom-scheme redirect URIs mean a native application.
pub fn derive_application_type(redirect_uris: Option<&Value>) -> &'static str {
    for raw in redirect_uris
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(url) = raw.as_str().and_then(|raw| Url::parse(raw).ok()) else {
            continue;
        };
        if url.scheme() != "http" && url.scheme() != "https" {
            return "native";
        }
        if is_loopback_host(url.host_str().unwrap_or("")) {
            return "native";
        }
    }
    "web"
}

/// The provider's client metadata with the SDK's `grant_types` and `application_type` defaults.
pub fn resolve_client_metadata<P: OAuthClientProvider>(provider: &P) -> Value {
    let mut metadata = provider.client_metadata();
    let interactive = provider.redirect_url().is_some();
    let application_type = derive_application_type(metadata.get("redirect_uris"));
    if let Some(object) = metadata.as_object_mut() {
        if object.get("grant_types").is_none_or(Value::is_null) {
            if interactive {
                object.insert(
                    "grant_types".to_owned(),
                    json!(["authorization_code", "refresh_token"]),
                );
            } else {
                object.remove("grant_types");
            }
        }
        if object.get("application_type").is_none_or(Value::is_null) {
            object.insert("application_type".to_owned(), json!(application_type));
        }
    }
    metadata
}

/// An OAuthError from an error response body, or a server_error that quotes the body.
pub fn parse_error_response(status: Option<u16>, body: &str) -> AuthError {
    let parsed = serde_json::from_str::<Value>(body)
        .map_err(|error| format!("SyntaxError: {error}"))
        .and_then(|value| {
            let field = |name: &str| match value.get(name) {
                None | Some(Value::Null) if name != "error" => Ok(None),
                Some(Value::String(text)) => Ok(Some(text.clone())),
                _ => Err(format!(
                    "ZodError: expected string at \"{name}\" in the OAuth error response"
                )),
            };
            let code = field("error")?.unwrap_or_default();
            Ok((code, field("error_description")?, field("error_uri")?))
        });
    match parsed {
        Ok((code, description, error_uri)) => AuthError::OAuth {
            message: description.unwrap_or_else(|| code.clone()),
            code,
            error_uri,
        },
        Err(error) => {
            let prefix = status.map_or(String::new(), |status| format!("HTTP {status}: "));
            AuthError::oauth(
                SERVER_ERROR,
                format!("{prefix}Invalid OAuth error response: {error}. Raw body: {body}"),
            )
        }
    }
}

fn warn_credential_invalidation<P: OAuthClientProvider>(
    provider: &P,
    error: &AuthError,
    invalidated: &str,
) {
    let action = if provider.can_invalidate_credentials() {
        format!("invalidating the stored {invalidated} and retrying authorization")
    } else {
        format!(
            "retrying authorization without discarding the stored {invalidated} (provider implements no invalidateCredentials())"
        )
    };
    warn(&format!(
        "[mcp-sdk] OAuth {} — {action}. Cause: {}",
        js_string(error.oauth_code()),
        js_string(Some(&error.to_string()))
    ));
}

/// Runs the whole OAuth flow against an MCP server, retrying once after discarding
/// credentials the authorization server rejected.
pub async fn auth<P: OAuthClientProvider>(
    provider: &P,
    options: &AuthOptions,
) -> Result<AuthResult, AuthError> {
    let error = match auth_internal(provider, options).await {
        Ok(result) => return Ok(result),
        Err(error) => error,
    };
    match error.oauth_code() {
        Some(INVALID_CLIENT | UNAUTHORIZED_CLIENT) => {
            warn_credential_invalidation(provider, &error, "client credentials and tokens");
            provider
                .invalidate_credentials(CredentialScope::Client)
                .await?;
            provider
                .invalidate_credentials(CredentialScope::Tokens)
                .await?;
            auth_internal(provider, options).await
        }
        Some(INVALID_GRANT | INVALID_DPOP_PROOF) => {
            warn_credential_invalidation(provider, &error, "tokens");
            provider
                .invalidate_credentials(CredentialScope::Tokens)
                .await?;
            auth_internal(provider, options).await
        }
        _ => Err(error),
    }
}

/// The requested scope, else the resource's advertised scopes, else the client's, plus
/// offline_access when the server offers it and the client can refresh.
pub fn determine_scope(
    requested_scope: Option<&str>,
    resource_metadata: Option<&Value>,
    auth_server_metadata: Option<&Value>,
    client_metadata: &Value,
) -> Option<String> {
    let strings = |value: Option<&Value>| -> Option<Vec<String>> {
        Some(
            value?
                .as_array()?
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect(),
        )
    };
    let mut effective = requested_scope
        .filter(|scope| !scope.is_empty())
        .map(str::to_owned)
        .or_else(|| {
            strings(resource_metadata.and_then(|metadata| metadata.get("scopes_supported")))
                .map(|scopes| scopes.join(" "))
                .filter(|scope| !scope.is_empty())
        })
        .or_else(|| {
            client_metadata
                .get("scope")
                .and_then(Value::as_str)
                .filter(|scope| !scope.is_empty())
                .map(str::to_owned)
        })?;
    let offers_offline_access =
        strings(auth_server_metadata.and_then(|metadata| metadata.get("scopes_supported")))
            .is_some_and(|scopes| scopes.iter().any(|scope| scope == "offline_access"));
    let can_refresh = strings(client_metadata.get("grant_types"))
        .is_some_and(|grants| grants.iter().any(|grant| grant == "refresh_token"));
    if offers_offline_access
        && !effective.split(' ').any(|scope| scope == "offline_access")
        && can_refresh
    {
        effective = format!("{effective} offline_access");
    }
    Some(effective)
}

fn with_issuer(value: &Value, issuer: &str) -> Value {
    let mut value = value.clone();
    if let Some(object) = value.as_object_mut() {
        object.insert("issuer".to_owned(), json!(issuer));
    }
    value
}

fn has_issuer_stamp(value: &Value) -> bool {
    value.get("issuer").is_some_and(|issuer| !issuer.is_null())
}

async fn auth_internal<P: OAuthClientProvider>(
    provider: &P,
    options: &AuthOptions,
) -> Result<AuthResult, AuthError> {
    let server_url = &options.server_url;
    let fetch = options.fetch.as_ref();
    let client_metadata = resolve_client_metadata(provider);
    let cached_state = provider.discovery_state().await;
    let mut effective_resource_metadata_url = options.resource_metadata_url.clone();
    if effective_resource_metadata_url.is_none()
        && let Some(url) = cached_state
            .as_ref()
            .and_then(|state| state.resource_metadata_url.as_deref())
    {
        effective_resource_metadata_url =
            Some(Url::parse(url).map_err(|_| AuthError::Other("Invalid URL".to_owned()))?);
    }

    let authorization_server_url;
    let mut resource_metadata;
    let metadata;
    let mut fresh_discovery_state = None;
    if let Some(cached) = cached_state
        .as_ref()
        .filter(|state| !state.authorization_server_url.is_empty())
    {
        authorization_server_url = cached.authorization_server_url.clone();
        resource_metadata = cached.resource_metadata.clone();
        let mut changed = false;
        metadata = match &cached.authorization_server_metadata {
            Some(metadata) => Some(metadata.clone()),
            None => {
                let discovered = discover_authorization_server_metadata(
                    &authorization_server_url,
                    fetch,
                    None,
                    options.skip_issuer_metadata_validation,
                )
                .await?;
                changed = discovered.is_some();
                discovered
            }
        };
        if resource_metadata.is_none() {
            match discover_oauth_protected_resource_metadata(
                server_url,
                effective_resource_metadata_url.as_ref(),
                None,
                fetch,
            )
            .await
            {
                Ok(discovered) => {
                    resource_metadata = Some(discovered);
                    changed = true;
                }
                Err(error @ AuthError::Network(_)) => return Err(error),
                Err(_) => {}
            }
        }
        if changed {
            provider
                .save_discovery_state(&DiscoveryState {
                    authorization_server_url: authorization_server_url.clone(),
                    resource_metadata_url: effective_resource_metadata_url
                        .as_ref()
                        .map(Url::to_string),
                    resource_metadata: resource_metadata.clone(),
                    authorization_server_metadata: metadata.clone(),
                })
                .await?;
        }
    } else {
        let info = discover_oauth_server_info(
            server_url,
            effective_resource_metadata_url.as_ref(),
            fetch,
            options.skip_issuer_metadata_validation,
        )
        .await?;
        authorization_server_url = info.authorization_server_url;
        metadata = info.authorization_server_metadata;
        resource_metadata = info.resource_metadata;
        fresh_discovery_state = Some(DiscoveryState {
            authorization_server_url: authorization_server_url.clone(),
            resource_metadata_url: effective_resource_metadata_url.as_ref().map(Url::to_string),
            resource_metadata: resource_metadata.clone(),
            authorization_server_metadata: metadata.clone(),
        });
    }

    let issuer = metadata
        .as_ref()
        .and_then(|metadata| metadata.get("issuer"))
        .and_then(Value::as_str)
        .map_or_else(|| authorization_server_url.clone(), str::to_owned);
    provider.save_authorization_server_url(&issuer).await?;

    if options.authorization_code.is_some() {
        let recorded_issuer = cached_state.as_ref().and_then(|state| {
            state
                .authorization_server_metadata
                .as_ref()
                .and_then(|metadata| metadata.get("issuer"))
                .and_then(Value::as_str)
                .map(str::to_owned)
                .or_else(|| {
                    (!state.authorization_server_url.is_empty())
                        .then(|| state.authorization_server_url.clone())
                })
        });
        match recorded_issuer {
            None if provider.can_save_discovery_state() => {
                return Err(AuthError::AuthorizationServerMismatch {
                    recorded: "discoveryState was not available on the callback leg; ensure your provider persists discoveryState alongside codeVerifier".to_owned(),
                    current: issuer,
                });
            }
            None => warn(
                "[mcp-sdk] OAuthClientProvider does not implement saveDiscoveryState()/discoveryState(); the SEP-2352 callback-leg authorization-server binding cannot be checked. Implement discoveryState (persist alongside codeVerifier) — see docs/migration/upgrade-to-v2.md §SEP-2352.",
            ),
            Some(recorded) if !issuers_match(&recorded, &issuer) => {
                return Err(AuthError::AuthorizationServerMismatch {
                    recorded,
                    current: issuer,
                });
            }
            Some(_) => {}
        }
    }

    if let Some(state) = &fresh_discovery_state {
        provider.save_discovery_state(state).await?;
    }

    let selected_resource =
        select_resource_url(server_url, provider, resource_metadata.as_ref()).await?;
    let resource = match (&selected_resource, &resource_metadata) {
        (Some(_), Some(resource_metadata)) if !provider.has_validate_resource_url() => {
            resource_metadata
                .get("resource")
                .and_then(Value::as_str)
                .map(str::to_owned)
        }
        _ => selected_resource.map(|url| url.to_string()),
    };
    if let Some(resource) = &resource {
        provider.save_resource_url(resource).await?;
    }

    let resolved_scope = determine_scope(
        options.scope.as_deref(),
        resource_metadata.as_ref(),
        metadata.as_ref(),
        &provider.client_metadata(),
    );

    let can_save_client_information = provider.can_save_client_information();
    let raw_client_info = provider.client_information(&issuer).await;
    let mut client_information = discard_if_issuer_mismatch(
        raw_client_info.clone(),
        &issuer,
        can_save_client_information,
    );
    if client_information.is_none()
        && !can_save_client_information
        && let Some(stamp) = raw_client_info
            .as_ref()
            .and_then(|info| info.get("issuer"))
            .and_then(Value::as_str)
            .filter(|stamp| !stamp.is_empty())
    {
        return Err(AuthError::AuthorizationServerMismatch {
            recorded: stamp.to_owned(),
            current: issuer,
        });
    }
    if let Some(info) = client_information
        .as_ref()
        .filter(|info| !has_issuer_stamp(info))
    {
        let stamped = with_issuer(info, &issuer);
        if can_save_client_information {
            provider.save_client_information(&stamped, &issuer).await?;
        }
        client_information = Some(stamped);
    }
    let client_information = match client_information {
        Some(info) => info,
        None => {
            if options.authorization_code.is_some() {
                return Err(AuthError::Other(
                    "Existing OAuth client information is required when exchanging an authorization code".to_owned(),
                ));
            }
            let supports_url_based_client_id = metadata
                .as_ref()
                .and_then(|metadata| metadata.get("client_id_metadata_document_supported"))
                == Some(&Value::Bool(true));
            let client_metadata_url = provider.client_metadata_url();
            if let Some(url) = client_metadata_url
                .as_deref()
                .filter(|url| !url.is_empty() && !is_https_url(url))
            {
                return Err(AuthError::oauth(
                    INVALID_CLIENT_METADATA,
                    format!(
                        "clientMetadataUrl must be a valid HTTPS URL with a non-root pathname, got: {url}"
                    ),
                ));
            }
            match client_metadata_url.filter(|url| supports_url_based_client_id && !url.is_empty())
            {
                Some(url) => {
                    let info = json!({ "client_id": url, "issuer": issuer });
                    if can_save_client_information {
                        provider.save_client_information(&info, &issuer).await?;
                    }
                    info
                }
                None => {
                    if !can_save_client_information {
                        return Err(AuthError::Other(
                            "OAuth client information must be saveable for dynamic registration"
                                .to_owned(),
                        ));
                    }
                    let registered = register_client(
                        &authorization_server_url,
                        metadata.as_ref(),
                        &client_metadata,
                        resolved_scope.as_deref(),
                        fetch,
                    )
                    .await?;
                    let info = with_issuer(&registered, &issuer);
                    provider.save_client_information(&info, &issuer).await?;
                    info
                }
            }
        }
    };

    let non_interactive_flow = provider.redirect_url().is_none();
    if options.authorization_code.is_some() || non_interactive_flow {
        if options.authorization_code.is_some() {
            validate_authorization_response_issuer(
                options.iss.as_deref(),
                metadata
                    .as_ref()
                    .and_then(|metadata| metadata.get("issuer"))
                    .and_then(Value::as_str),
                is_iss_parameter_supported(metadata.as_ref()),
            )?;
        }
        let tokens = fetch_token(
            provider,
            &authorization_server_url,
            FetchTokenOptions {
                metadata: metadata.as_ref(),
                resource: resource.as_deref(),
                authorization_code: options.authorization_code.as_deref(),
                iss: options.iss.as_deref(),
                scope: resolved_scope.as_deref(),
                fetch,
            },
        )
        .await?;
        provider
            .save_tokens(&with_issuer(&tokens, &issuer), &issuer)
            .await?;
        return Ok(AuthResult::Authorized);
    }

    let mut tokens =
        discard_if_issuer_mismatch(provider.tokens(Some(&issuer)).await, &issuer, true);
    if let Some(current) = tokens.as_ref().filter(|tokens| !has_issuer_stamp(tokens)) {
        let stamped = with_issuer(current, &issuer);
        provider.save_tokens(&stamped, &issuer).await?;
        tokens = Some(stamped);
    }
    if let Some(refresh_token) = tokens
        .as_ref()
        .and_then(|tokens| tokens.get("refresh_token"))
        .and_then(Value::as_str)
        .filter(|refresh_token| !refresh_token.is_empty())
        && !options.force_reauthorization
    {
        let refreshed = refresh_authorization(
            &authorization_server_url,
            TokenRequestOptions {
                metadata: metadata.as_ref(),
                client_information: Some(&client_information),
                resource: resource.as_deref(),
                fetch,
            },
            refresh_token,
            Some(provider),
        )
        .await;
        match refreshed {
            Ok(new_tokens) => {
                provider
                    .save_tokens(&with_issuer(&new_tokens, &issuer), &issuer)
                    .await?;
                return Ok(AuthResult::Authorized);
            }
            Err(error @ AuthError::InsecureTokenEndpoint(_)) => return Err(error),
            Err(error) if error.oauth_code().is_none_or(|code| code == SERVER_ERROR) => {
                warn(&format!(
                    "[mcp-sdk] Could not refresh OAuth tokens; falling back to a new authorization request. Cause: {}",
                    js_string(Some(&error.to_string()))
                ));
            }
            Err(error) => return Err(error),
        }
    }

    let state = provider.state().await?;
    let (authorization_url, code_verifier) = start_authorization(
        &authorization_server_url,
        StartAuthorizationOptions {
            metadata: metadata.as_ref(),
            client_information: &client_information,
            redirect_url: &provider.redirect_url().unwrap_or_default(),
            scope: resolved_scope.as_deref(),
            state: state.as_deref(),
            resource: resource.as_deref(),
        },
    )?;
    provider.save_code_verifier(&code_verifier).await?;
    provider
        .redirect_to_authorization(&authorization_url)
        .await?;
    Ok(AuthResult::Redirect)
}

/// SEP-991: a URL-based client id must be https with a path.
pub fn is_https_url(value: &str) -> bool {
    Url::parse(value).is_ok_and(|url| url.scheme() == "https" && url.path() != "/")
}

/// The server URL without its fragment: the default RFC 8707 resource.
pub fn resource_url_from_server_url(url: &Url) -> Url {
    let mut resource = url.clone();
    resource.set_fragment(None);
    resource
}

/// Whether `requested` lies at or under `configured` on the same origin.
pub fn check_resource_allowed(requested: &Url, configured: &Url) -> bool {
    if requested.origin() != configured.origin() {
        return false;
    }
    if requested.path().len() < configured.path().len() {
        return false;
    }
    let with_slash = |path: &str| {
        if path.ends_with('/') {
            path.to_owned()
        } else {
            format!("{path}/")
        }
    };
    with_slash(requested.path()).starts_with(&with_slash(configured.path()))
}

/// The RFC 8707 resource indicator: the provider's choice, else the metadata's resource.
pub async fn select_resource_url<P: OAuthClientProvider>(
    server_url: &Url,
    provider: &P,
    resource_metadata: Option<&Value>,
) -> Result<Option<Url>, AuthError> {
    let default_resource = resource_url_from_server_url(server_url);
    let configured = resource_metadata
        .and_then(|metadata| metadata.get("resource"))
        .and_then(Value::as_str);
    if provider.has_validate_resource_url() {
        return provider
            .validate_resource_url(&default_resource, configured)
            .await;
    }
    if resource_metadata.is_none() {
        return Ok(None);
    }
    let configured = configured.unwrap_or_default();
    let configured_url =
        Url::parse(configured).map_err(|_| AuthError::Other("Invalid URL".to_owned()))?;
    if !check_resource_allowed(&default_resource, &configured_url) {
        return Err(AuthError::Other(format!(
            "Protected resource {configured} does not match expected {default_resource} (or origin)"
        )));
    }
    Ok(Some(configured_url))
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct WwwAuthenticateChallenge {
    pub resource_metadata_url: Option<Url>,
    pub scope: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

/// `resource_metadata`, `scope`, `error` and `error_description` from a Bearer or DPoP challenge.
pub fn extract_www_authenticate_params(header: Option<&str>) -> WwwAuthenticateChallenge {
    let Some(header) = header.filter(|header| !header.is_empty()) else {
        return WwwAuthenticateChallenge::default();
    };
    let mut parts = header.split(' ');
    let scheme = parts.next().unwrap_or("").to_lowercase();
    let rest = parts.next().unwrap_or("");
    if !matches!(scheme.as_str(), "bearer" | "dpop") || rest.is_empty() {
        return WwwAuthenticateChallenge::default();
    }
    WwwAuthenticateChallenge {
        resource_metadata_url: extract_field_from_www_auth(header, "resource_metadata")
            .and_then(|url| Url::parse(&url).ok()),
        scope: extract_field_from_www_auth(header, "scope"),
        error: extract_field_from_www_auth(header, "error"),
        error_description: extract_field_from_www_auth(header, "error_description"),
    }
}

/// The SDK's `${field}=(?:"([^"]+)"|([^\s,]+))` match: the first occurrence that has a value.
pub fn extract_field_from_www_auth(header: &str, field_name: &str) -> Option<String> {
    let needle = format!("{field_name}=");
    let mut from = 0;
    while let Some(offset) = header[from..].find(&needle) {
        let start = from + offset;
        let value = &header[start + needle.len()..];
        if let Some(quoted) = value.strip_prefix('"')
            && let Some(end) = quoted.find('"')
            && end > 0
        {
            return Some(quoted[..end].to_owned());
        }
        let end = value
            .find(|c: char| c.is_whitespace() || c == ',')
            .unwrap_or(value.len());
        if end > 0 {
            return Some(value[..end].to_owned());
        }
        from = start + 1;
    }
    None
}

fn header_map(headers: &[(String, String)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            map.insert(name, value);
        }
    }
    map
}

/// The SDK's fetchWithinOrigin: follows only redirects that keep the method and the origin.
pub async fn fetch_within_origin(
    fetch: Option<&FetchFn>,
    method: Method,
    url: &Url,
    headers: &[(String, String)],
    body: Option<String>,
) -> Result<Response, AuthError> {
    let fetch = fetch.cloned().unwrap_or_else(default_fetch);
    let headers = header_map(headers);
    let mut current = url.clone();
    let mut followed = 0;
    loop {
        let mut request = Request::new(method.clone(), current.clone());
        *request.headers_mut() = headers.clone();
        if let Some(body) = &body {
            *request.body_mut() = Some(body.clone().into());
        }
        let response = fetch(request).await.map_err(AuthError::Network)?;
        let Some(target) = redirect_target(&current, &response) else {
            return Ok(response);
        };
        if followed == MAX_REDIRECTS {
            return Ok(response);
        }
        let keeps_method = method == Method::GET || matches!(response.status().as_u16(), 307 | 308);
        let keeps_userinfo = (target.username().is_empty() && target.password().is_none())
            || (target.username() == current.username() && target.password() == current.password());
        if !keeps_method || !keeps_userinfo || !is_within_origin(&current, &target) {
            return Ok(response);
        }
        let _ = response.bytes().await;
        current = target;
        followed += 1;
    }
}

async fn read_json(response: Response) -> Result<Value, AuthError> {
    let text = response
        .text()
        .await
        .map_err(|error| AuthError::Network(error.to_string()))?;
    serde_json::from_str(&text).map_err(|error| AuthError::Other(format!("SyntaxError: {error}")))
}

fn schema_error(message: String) -> AuthError {
    AuthError::Other(format!("ZodError: {message}"))
}

fn is_safe_url(value: &Value) -> bool {
    value
        .as_str()
        .and_then(|value| Url::parse(value).ok())
        .is_some_and(|url| !matches!(url.scheme(), "javascript" | "data" | "vbscript"))
}

fn is_string_array(value: &Value) -> bool {
    value
        .as_array()
        .is_some_and(|items| items.iter().all(Value::is_string))
}

#[derive(Clone, Copy)]
enum Check {
    String,
    Url,
    SafeUrl,
    /// A SafeUrl where an empty string reads as absent.
    OptionalSafeUrl,
    Strings,
    SafeUrls,
    Bool,
    /// A boolean that reads as absent when it is anything else (zod's `.catch(undefined)`).
    CatchBool,
    Number,
    CoerceNumber,
    Any,
}

/// Checks `object` against (field, check, required) rules; unknown fields are dropped when `strip`.
fn check_object(
    value: &Value,
    rules: &[(&str, Check, bool)],
    strip: bool,
) -> Result<Value, AuthError> {
    let Some(object) = value.as_object() else {
        return Err(schema_error("expected object".to_owned()));
    };
    let mut out = if strip { Map::new() } else { object.clone() };
    for &(name, check, required) in rules {
        let field = object.get(name);
        let Some(field) = field else {
            if required {
                return Err(schema_error(format!("\"{name}\" is required")));
            }
            continue;
        };
        let checked = match check {
            Check::String => field.is_string().then(|| field.clone()),
            Check::Url => field
                .as_str()
                .filter(|text| Url::parse(text).is_ok())
                .map(|_| field.clone()),
            Check::SafeUrl => is_safe_url(field).then(|| field.clone()),
            Check::OptionalSafeUrl if field.as_str() == Some("") => {
                out.remove(name);
                continue;
            }
            Check::OptionalSafeUrl => is_safe_url(field).then(|| field.clone()),
            Check::Strings => is_string_array(field).then(|| field.clone()),
            Check::SafeUrls => field
                .as_array()
                .is_some_and(|items| items.iter().all(is_safe_url))
                .then(|| field.clone()),
            Check::Bool => field.is_boolean().then(|| field.clone()),
            Check::CatchBool => {
                if field.is_boolean() {
                    Some(field.clone())
                } else {
                    out.remove(name);
                    continue;
                }
            }
            Check::Number => field.is_number().then(|| field.clone()),
            Check::CoerceNumber => coerce_number(field),
            Check::Any => Some(field.clone()),
        };
        match checked {
            Some(checked) => {
                out.insert(name.to_owned(), checked);
            }
            None => return Err(schema_error(format!("invalid value at \"{name}\""))),
        }
    }
    Ok(Value::Object(out))
}

fn coerce_number(value: &Value) -> Option<Value> {
    let number = match value {
        Value::Number(_) => return Some(value.clone()),
        Value::Null => 0.0,
        Value::Bool(flag) => f64::from(u8::from(*flag)),
        Value::String(text) if text.trim().is_empty() => 0.0,
        Value::String(text) => text.trim().parse::<f64>().ok()?,
        _ => return None,
    };
    if number.fract() == 0.0 && number.abs() < 9e15 {
        Some(json!(number as i64))
    } else {
        serde_json::Number::from_f64(number).map(Value::Number)
    }
}

pub fn parse_protected_resource_metadata(value: &Value) -> Result<Value, AuthError> {
    use Check::*;
    check_object(
        value,
        &[
            ("resource", Url, true),
            ("authorization_servers", SafeUrls, false),
            ("jwks_uri", Url, false),
            ("scopes_supported", Strings, false),
            ("bearer_methods_supported", Strings, false),
            ("resource_signing_alg_values_supported", Strings, false),
            ("resource_name", String, false),
            ("resource_documentation", String, false),
            ("resource_policy_uri", Url, false),
            ("resource_tos_uri", Url, false),
            ("tls_client_certificate_bound_access_tokens", Bool, false),
            ("authorization_details_types_supported", Strings, false),
            ("dpop_signing_alg_values_supported", Strings, false),
            ("dpop_bound_access_tokens_required", Bool, false),
        ],
        false,
    )
}

pub fn parse_oauth_metadata(value: &Value) -> Result<Value, AuthError> {
    use Check::*;
    check_object(
        value,
        &[
            ("issuer", String, true),
            ("authorization_endpoint", SafeUrl, true),
            ("token_endpoint", SafeUrl, true),
            ("registration_endpoint", SafeUrl, false),
            ("scopes_supported", Strings, false),
            ("response_types_supported", Strings, true),
            ("response_modes_supported", Strings, false),
            ("grant_types_supported", Strings, false),
            ("token_endpoint_auth_methods_supported", Strings, false),
            (
                "token_endpoint_auth_signing_alg_values_supported",
                Strings,
                false,
            ),
            ("service_documentation", SafeUrl, false),
            ("revocation_endpoint", SafeUrl, false),
            ("revocation_endpoint_auth_methods_supported", Strings, false),
            (
                "revocation_endpoint_auth_signing_alg_values_supported",
                Strings,
                false,
            ),
            ("introspection_endpoint", String, false),
            (
                "introspection_endpoint_auth_methods_supported",
                Strings,
                false,
            ),
            (
                "introspection_endpoint_auth_signing_alg_values_supported",
                Strings,
                false,
            ),
            ("code_challenge_methods_supported", Strings, false),
            ("client_id_metadata_document_supported", Bool, false),
            (
                "authorization_response_iss_parameter_supported",
                CatchBool,
                false,
            ),
            ("dpop_signing_alg_values_supported", Strings, false),
        ],
        false,
    )
}

/// OpenID provider metadata. The SDK's schema is a plain z.object, so unknown fields are dropped.
pub fn parse_openid_provider_metadata(value: &Value) -> Result<Value, AuthError> {
    use Check::*;
    let strings = |name| (name, Strings, false);
    check_object(
        value,
        &[
            ("issuer", String, true),
            ("authorization_endpoint", SafeUrl, true),
            ("token_endpoint", SafeUrl, true),
            ("userinfo_endpoint", SafeUrl, false),
            ("jwks_uri", SafeUrl, true),
            ("registration_endpoint", SafeUrl, false),
            strings("scopes_supported"),
            ("response_types_supported", Strings, true),
            strings("response_modes_supported"),
            strings("grant_types_supported"),
            strings("acr_values_supported"),
            ("subject_types_supported", Strings, true),
            ("id_token_signing_alg_values_supported", Strings, true),
            strings("id_token_encryption_alg_values_supported"),
            strings("id_token_encryption_enc_values_supported"),
            strings("userinfo_signing_alg_values_supported"),
            strings("userinfo_encryption_alg_values_supported"),
            strings("userinfo_encryption_enc_values_supported"),
            strings("request_object_signing_alg_values_supported"),
            strings("request_object_encryption_alg_values_supported"),
            strings("request_object_encryption_enc_values_supported"),
            strings("token_endpoint_auth_methods_supported"),
            strings("token_endpoint_auth_signing_alg_values_supported"),
            strings("display_values_supported"),
            strings("claim_types_supported"),
            strings("claims_supported"),
            ("service_documentation", String, false),
            strings("claims_locales_supported"),
            strings("ui_locales_supported"),
            ("claims_parameter_supported", Bool, false),
            ("request_parameter_supported", Bool, false),
            ("request_uri_parameter_supported", Bool, false),
            ("require_request_uri_registration", Bool, false),
            ("op_policy_uri", SafeUrl, false),
            ("op_tos_uri", SafeUrl, false),
            ("client_id_metadata_document_supported", Bool, false),
            (
                "authorization_response_iss_parameter_supported",
                CatchBool,
                false,
            ),
            strings("code_challenge_methods_supported"),
        ],
        true,
    )
}

/// A token response, without `issuer` (only the client stamps that) and unknown fields.
pub fn parse_tokens(value: &Value) -> Result<Value, AuthError> {
    use Check::*;
    let mut value = value.clone();
    if let Some(object) = value.as_object_mut() {
        object.remove("issuer");
    }
    check_object(
        &value,
        &[
            ("access_token", String, true),
            ("id_token", String, false),
            ("token_type", String, true),
            ("expires_in", CoerceNumber, false),
            ("scope", String, false),
            ("refresh_token", String, false),
        ],
        true,
    )
}

/// A registration response (client metadata plus client information), without `issuer`.
pub fn parse_client_information_full(value: &Value) -> Result<Value, AuthError> {
    use Check::*;
    let mut value = value.clone();
    if let Some(object) = value.as_object_mut() {
        object.remove("issuer");
    }
    check_object(
        &value,
        &[
            ("redirect_uris", SafeUrls, true),
            ("token_endpoint_auth_method", String, false),
            ("grant_types", Strings, false),
            ("response_types", Strings, false),
            ("application_type", String, false),
            ("client_name", String, false),
            ("client_uri", SafeUrl, false),
            ("logo_uri", OptionalSafeUrl, false),
            ("scope", String, false),
            ("contacts", Strings, false),
            ("tos_uri", OptionalSafeUrl, false),
            ("policy_uri", String, false),
            ("jwks_uri", SafeUrl, false),
            ("jwks", Any, false),
            ("software_id", String, false),
            ("software_version", String, false),
            ("software_statement", String, false),
            ("client_id", String, true),
            ("client_secret", String, false),
            ("client_id_issued_at", Number, false),
            ("client_secret_expires_at", Number, false),
        ],
        true,
    )
}

fn build_well_known_path(well_known_prefix: &str, pathname: &str) -> String {
    let pathname = pathname.strip_suffix('/').unwrap_or(pathname);
    format!("/.well-known/{well_known_prefix}{pathname}")
}

fn join(base: &Url, path: &str) -> Result<Url, AuthError> {
    base.join(path)
        .map_err(|_| AuthError::Other("Invalid URL".to_owned()))
}

async fn try_metadata_discovery(
    url: &Url,
    protocol_version: &str,
    fetch: Option<&FetchFn>,
) -> Result<Response, AuthError> {
    fetch_within_origin(
        fetch,
        Method::GET,
        url,
        &[(
            "MCP-Protocol-Version".to_owned(),
            protocol_version.to_owned(),
        )],
        None,
    )
    .await
}

fn should_attempt_fallback(response: &Response, pathname: &str) -> bool {
    if pathname == "/" {
        return false;
    }
    let status = response.status();
    (!status.is_success() && status.as_u16() < 500) || status.as_u16() == 502
}

async fn discover_metadata_with_fallback(
    server_url: &Url,
    well_known_type: &str,
    fetch: Option<&FetchFn>,
    protocol_version: Option<&str>,
    metadata_url: Option<&Url>,
) -> Result<Response, AuthError> {
    let protocol_version = protocol_version.unwrap_or(LATEST_PROTOCOL_VERSION);
    let url = match metadata_url {
        Some(url) => url.clone(),
        None => {
            let mut url = join(
                server_url,
                &build_well_known_path(well_known_type, server_url.path()),
            )?;
            url.set_query(server_url.query());
            url
        }
    };
    let response = try_metadata_discovery(&url, protocol_version, fetch).await?;
    if metadata_url.is_none() && should_attempt_fallback(&response, server_url.path()) {
        let _ = response.bytes().await;
        let root = join(server_url, &format!("/.well-known/{well_known_type}"))?;
        return try_metadata_discovery(&root, protocol_version, fetch).await;
    }
    Ok(response)
}

/// RFC 9728 protected resource metadata for an MCP server.
pub async fn discover_oauth_protected_resource_metadata(
    server_url: &Url,
    resource_metadata_url: Option<&Url>,
    protocol_version: Option<&str>,
    fetch: Option<&FetchFn>,
) -> Result<Value, AuthError> {
    let response = discover_metadata_with_fallback(
        server_url,
        "oauth-protected-resource",
        fetch,
        protocol_version,
        resource_metadata_url,
    )
    .await?;
    let status = response.status();
    if status.as_u16() == 404 {
        let _ = response.bytes().await;
        return Err(AuthError::Other(
            "Resource server does not implement OAuth 2.0 Protected Resource Metadata.".to_owned(),
        ));
    }
    if !status.is_success() {
        let _ = response.bytes().await;
        return Err(AuthError::Other(format!(
            "HTTP {} trying to load well-known OAuth protected resource metadata.",
            status.as_u16()
        )));
    }
    parse_protected_resource_metadata(&read_json(response).await?)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryType {
    OAuth,
    Oidc,
}

/// The well-known URLs to try for authorization server metadata, in order.
pub fn build_discovery_urls(authorization_server_url: &Url) -> Vec<(Url, DiscoveryType)> {
    let origin = authorization_server_url.origin().ascii_serialization();
    let at = |path: String| Url::parse(&format!("{origin}{path}")).ok();
    let pathname = authorization_server_url.path();
    let candidates = if pathname == "/" {
        vec![
            (
                at("/.well-known/oauth-authorization-server".to_owned()),
                DiscoveryType::OAuth,
            ),
            (
                at("/.well-known/openid-configuration".to_owned()),
                DiscoveryType::Oidc,
            ),
        ]
    } else {
        let pathname = pathname.strip_suffix('/').unwrap_or(pathname);
        vec![
            (
                at(format!("/.well-known/oauth-authorization-server{pathname}")),
                DiscoveryType::OAuth,
            ),
            (
                at(format!("/.well-known/openid-configuration{pathname}")),
                DiscoveryType::Oidc,
            ),
            (
                at(format!("{pathname}/.well-known/openid-configuration")),
                DiscoveryType::Oidc,
            ),
        ]
    };
    candidates
        .into_iter()
        .filter_map(|(url, kind)| Some((url?, kind)))
        .collect()
}

/// RFC 8414 / OpenID Connect discovery, with the RFC 8414 §3.3 issuer echo check.
pub async fn discover_authorization_server_metadata(
    authorization_server_url: &str,
    fetch: Option<&FetchFn>,
    protocol_version: Option<&str>,
    skip_issuer_validation: bool,
) -> Result<Option<Value>, AuthError> {
    let url = Url::parse(authorization_server_url)
        .map_err(|_| AuthError::Network("Invalid URL".to_owned()))?;
    let headers = [
        (
            "MCP-Protocol-Version".to_owned(),
            protocol_version
                .unwrap_or(LATEST_PROTOCOL_VERSION)
                .to_owned(),
        ),
        ("Accept".to_owned(), "application/json".to_owned()),
    ];
    for (endpoint_url, kind) in build_discovery_urls(&url) {
        let response =
            fetch_within_origin(fetch, Method::GET, &endpoint_url, &headers, None).await?;
        let status = response.status().as_u16();
        if !response.status().is_success() {
            let _ = response.bytes().await;
            if status < 500 || status == 502 {
                continue;
            }
            return Err(AuthError::Other(format!(
                "HTTP {status} trying to load {} metadata from {endpoint_url}",
                match kind {
                    DiscoveryType::OAuth => "OAuth",
                    DiscoveryType::Oidc => "OpenID provider",
                }
            )));
        }
        let body = read_json(response).await?;
        let parsed = match kind {
            DiscoveryType::OAuth => parse_oauth_metadata(&body)?,
            DiscoveryType::Oidc => parse_openid_provider_metadata(&body)?,
        };
        if !skip_issuer_validation {
            let issuer = parsed.get("issuer").and_then(Value::as_str).unwrap_or("");
            let expected = authorization_server_url;
            if !(issuer == expected || expected.strip_suffix('/') == Some(issuer)) {
                return Err(AuthError::IssuerMismatch {
                    kind: IssuerMismatchKind::Metadata,
                    expected: expected.to_owned(),
                    received: Some(issuer.to_owned()),
                });
            }
        }
        return Ok(Some(parsed));
    }
    Ok(None)
}

#[derive(Debug, Clone, PartialEq)]
pub struct OAuthServerInfo {
    pub authorization_server_url: String,
    pub authorization_server_metadata: Option<Value>,
    pub resource_metadata: Option<Value>,
}

/// The authorization server for an MCP server (RFC 9728, falling back to the server's origin)
/// and its metadata.
pub async fn discover_oauth_server_info(
    server_url: &Url,
    resource_metadata_url: Option<&Url>,
    fetch: Option<&FetchFn>,
    skip_issuer_metadata_validation: bool,
) -> Result<OAuthServerInfo, AuthError> {
    let mut resource_metadata = None;
    let mut authorization_server_url = None;
    match discover_oauth_protected_resource_metadata(server_url, resource_metadata_url, None, fetch)
        .await
    {
        Ok(metadata) => {
            authorization_server_url = metadata
                .get("authorization_servers")
                .and_then(Value::as_array)
                .and_then(|servers| servers.first())
                .and_then(Value::as_str)
                .map(str::to_owned);
            resource_metadata = Some(metadata);
        }
        Err(error @ AuthError::Network(_)) => return Err(error),
        Err(_) => {}
    }
    let authorization_server_url = match authorization_server_url {
        Some(url) => url,
        None => join(server_url, "/")?.to_string(),
    };
    let authorization_server_metadata = discover_authorization_server_metadata(
        &authorization_server_url,
        fetch,
        None,
        skip_issuer_metadata_validation,
    )
    .await?;
    Ok(OAuthServerInfo {
        authorization_server_url,
        authorization_server_metadata,
        resource_metadata,
    })
}

/// A random PKCE verifier and its S256 challenge, as pkce-challenge makes them.
pub fn pkce_challenge() -> Result<(String, String), AuthError> {
    let mut bytes = [0u8; PKCE_VERIFIER_LENGTH];
    getrandom::fill(&mut bytes).map_err(|error| AuthError::Other(error.to_string()))?;
    let verifier: String = bytes
        .iter()
        .map(|byte| PKCE_MASK[usize::from(*byte) % PKCE_MASK.len()] as char)
        .collect();
    let challenge = crate::node_oauth_client_provider::code_challenge_for(&verifier);
    Ok((verifier, challenge))
}

/// URLSearchParams.set: replaces the first `name` and drops the rest, or appends.
fn set_search_param(url: &mut Url, name: &str, value: &str) {
    let mut pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
    match pairs.iter().position(|(key, _)| key == name) {
        Some(index) => {
            pairs[index].1 = value.to_owned();
            let mut position = 0;
            pairs.retain(|(key, _)| {
                let keep = position <= index || key != name;
                position += 1;
                keep
            });
        }
        None => pairs.push((name.to_owned(), value.to_owned())),
    }
    url.query_pairs_mut().clear().extend_pairs(pairs);
}

pub struct StartAuthorizationOptions<'a> {
    pub metadata: Option<&'a Value>,
    pub client_information: &'a Value,
    pub redirect_url: &'a str,
    pub scope: Option<&'a str>,
    pub state: Option<&'a str>,
    pub resource: Option<&'a str>,
}

/// The authorization URL to send the user to, and the PKCE verifier to keep for the exchange.
pub fn start_authorization(
    authorization_server_url: &str,
    options: StartAuthorizationOptions,
) -> Result<(Url, String), AuthError> {
    let invalid = |_| AuthError::Other("Invalid URL".to_owned());
    let mut authorization_url = match options.metadata {
        Some(metadata) => {
            let url = Url::parse(
                metadata
                    .get("authorization_endpoint")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
            )
            .map_err(invalid)?;
            let supports = |field: &str, wanted: &str| {
                metadata
                    .get(field)
                    .and_then(Value::as_array)
                    .map(|items| items.iter().any(|item| item.as_str() == Some(wanted)))
            };
            if supports("response_types_supported", AUTHORIZATION_CODE_RESPONSE_TYPE) != Some(true)
            {
                return Err(AuthError::Other(format!(
                    "Incompatible auth server: does not support response type {AUTHORIZATION_CODE_RESPONSE_TYPE}"
                )));
            }
            if supports(
                "code_challenge_methods_supported",
                AUTHORIZATION_CODE_CHALLENGE_METHOD,
            ) == Some(false)
            {
                return Err(AuthError::Other(format!(
                    "Incompatible auth server: does not support code challenge method {AUTHORIZATION_CODE_CHALLENGE_METHOD}"
                )));
            }
            url
        }
        None => Url::parse(authorization_server_url)
            .and_then(|base| base.join("/authorize"))
            .map_err(invalid)?,
    };
    let (code_verifier, code_challenge) = pkce_challenge()?;
    let client_id = options
        .client_information
        .get("client_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    set_search_param(
        &mut authorization_url,
        "response_type",
        AUTHORIZATION_CODE_RESPONSE_TYPE,
    );
    set_search_param(&mut authorization_url, "client_id", client_id);
    set_search_param(&mut authorization_url, "code_challenge", &code_challenge);
    set_search_param(
        &mut authorization_url,
        "code_challenge_method",
        AUTHORIZATION_CODE_CHALLENGE_METHOD,
    );
    set_search_param(&mut authorization_url, "redirect_uri", options.redirect_url);
    if let Some(state) = options.state.filter(|state| !state.is_empty()) {
        set_search_param(&mut authorization_url, "state", state);
    }
    if let Some(scope) = options.scope.filter(|scope| !scope.is_empty()) {
        set_search_param(&mut authorization_url, "scope", scope);
        if scope.split(' ').any(|scope| scope == "offline_access") {
            authorization_url
                .query_pairs_mut()
                .append_pair("prompt", "consent");
        }
    }
    if let Some(resource) = options.resource.filter(|resource| !resource.is_empty()) {
        set_search_param(&mut authorization_url, "resource", resource);
    }
    Ok((authorization_url, code_verifier))
}

/// The form parameters of an authorization_code grant.
pub fn prepare_authorization_code_request(
    authorization_code: &str,
    code_verifier: &str,
    redirect_uri: &str,
) -> Vec<(String, String)> {
    vec![
        ("grant_type".to_owned(), "authorization_code".to_owned()),
        ("code".to_owned(), authorization_code.to_owned()),
        ("code_verifier".to_owned(), code_verifier.to_owned()),
        ("redirect_uri".to_owned(), redirect_uri.to_owned()),
    ]
}

#[derive(Clone, Copy, Default)]
pub struct TokenRequestOptions<'a> {
    pub metadata: Option<&'a Value>,
    pub client_information: Option<&'a Value>,
    pub resource: Option<&'a str>,
    pub fetch: Option<&'a FetchFn>,
}

fn set_param(params: &mut Vec<(String, String)>, name: &str, value: &str) {
    match params.iter_mut().find(|(key, _)| key == name) {
        Some(pair) => pair.1 = value.to_owned(),
        None => params.push((name.to_owned(), value.to_owned())),
    }
}

/// POSTs a token request, authenticating the client the way the provider or the server prefers.
pub async fn execute_token_request<P: OAuthClientProvider>(
    authorization_server_url: &str,
    options: TokenRequestOptions<'_>,
    mut params: Vec<(String, String)>,
    client_authentication: Option<&P>,
) -> Result<Value, AuthError> {
    let token_endpoint = match options
        .metadata
        .and_then(|metadata| metadata.get("token_endpoint"))
        .and_then(Value::as_str)
    {
        Some(endpoint) => endpoint.to_owned(),
        None => Url::parse(authorization_server_url)
            .and_then(|base| base.join("/token"))
            .map_err(|_| AuthError::Other("Invalid URL".to_owned()))?
            .to_string(),
    };
    let token_url = assert_secure_token_endpoint(&token_endpoint)?;
    let mut headers = vec![
        (
            "Content-Type".to_owned(),
            "application/x-www-form-urlencoded".to_owned(),
        ),
        ("Accept".to_owned(), "application/json".to_owned()),
    ];
    if let Some(resource) = options.resource {
        set_param(&mut params, "resource", resource);
    }
    let provider =
        client_authentication.filter(|provider| provider.has_add_client_authentication());
    match provider {
        Some(provider) => {
            provider
                .add_client_authentication(&mut headers, &mut params, &token_url, options.metadata)
                .await?;
        }
        None => {
            if let Some(info) = options.client_information {
                let supported: Vec<&str> = options
                    .metadata
                    .and_then(|metadata| metadata.get("token_endpoint_auth_methods_supported"))
                    .and_then(Value::as_array)
                    .map(|methods| methods.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                let method = select_client_auth_method(info, &supported);
                apply_client_authentication(
                    method,
                    info.get("client_id").and_then(Value::as_str).unwrap_or(""),
                    info.get("client_secret").and_then(Value::as_str),
                    &mut headers,
                    &mut params,
                )
                .map_err(AuthError::Other)?;
            }
        }
    }
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(&params)
        .finish();
    let response = fetch_within_origin(
        options.fetch,
        Method::POST,
        &token_url,
        &headers,
        Some(body),
    )
    .await?;
    let status = response.status();
    if !status.is_success() {
        let text = response.text().await.unwrap_or_default();
        return Err(parse_error_response(Some(status.as_u16()), &text));
    }
    let json = read_json(response).await?;
    match parse_tokens(&json) {
        Ok(tokens) => Ok(tokens),
        Err(_) if json.get("error").is_some() => Err(parse_error_response(None, &json.to_string())),
        Err(error) => Err(error),
    }
}

/// Exchanges an authorization code for tokens, after the RFC 9207 `iss` check.
pub async fn exchange_authorization<P: OAuthClientProvider>(
    authorization_server_url: &str,
    options: TokenRequestOptions<'_>,
    authorization_code: &str,
    iss: Option<&str>,
    code_verifier: &str,
    redirect_uri: &str,
    client_authentication: Option<&P>,
) -> Result<Value, AuthError> {
    validate_authorization_response_issuer(
        iss,
        options
            .metadata
            .and_then(|metadata| metadata.get("issuer"))
            .and_then(Value::as_str),
        is_iss_parameter_supported(options.metadata),
    )?;
    execute_token_request(
        authorization_server_url,
        options,
        prepare_authorization_code_request(authorization_code, code_verifier, redirect_uri),
        client_authentication,
    )
    .await
}

/// Exchanges a refresh token, keeping it when the server does not rotate it.
pub async fn refresh_authorization<P: OAuthClientProvider>(
    authorization_server_url: &str,
    options: TokenRequestOptions<'_>,
    refresh_token: &str,
    client_authentication: Option<&P>,
) -> Result<Value, AuthError> {
    let tokens = execute_token_request(
        authorization_server_url,
        options,
        vec![
            ("grant_type".to_owned(), "refresh_token".to_owned()),
            ("refresh_token".to_owned(), refresh_token.to_owned()),
        ],
        client_authentication,
    )
    .await?;
    let mut merged = json!({ "refresh_token": refresh_token });
    if let (Some(merged), Some(tokens)) = (merged.as_object_mut(), tokens.as_object()) {
        for (key, value) in tokens {
            merged.insert(key.clone(), value.clone());
        }
    }
    Ok(merged)
}

#[derive(Clone, Copy, Default)]
pub struct FetchTokenOptions<'a> {
    pub metadata: Option<&'a Value>,
    pub resource: Option<&'a str>,
    pub authorization_code: Option<&'a str>,
    pub iss: Option<&'a str>,
    pub scope: Option<&'a str>,
    pub fetch: Option<&'a FetchFn>,
}

/// Fetches tokens with the grant the provider prepares, or the authorization_code grant.
pub async fn fetch_token<P: OAuthClientProvider>(
    provider: &P,
    authorization_server_url: &str,
    options: FetchTokenOptions<'_>,
) -> Result<Value, AuthError> {
    if options.authorization_code.is_some() {
        validate_authorization_response_issuer(
            options.iss,
            options
                .metadata
                .and_then(|metadata| metadata.get("issuer"))
                .and_then(Value::as_str),
            is_iss_parameter_supported(options.metadata),
        )?;
    }
    let issuer = options
        .metadata
        .and_then(|metadata| metadata.get("issuer"))
        .and_then(Value::as_str)
        .unwrap_or(authorization_server_url)
        .to_owned();
    let read_client_information = || async {
        let raw = provider.client_information(&issuer).await;
        let checked = discard_if_issuer_mismatch(raw.clone(), &issuer, false);
        if let Some(raw) = raw
            && checked.is_none()
        {
            let recorded = match raw.get("issuer") {
                Some(Value::String(stamp)) => stamp.clone(),
                _ => "undefined".to_owned(),
            };
            return Err(AuthError::AuthorizationServerMismatch {
                recorded,
                current: issuer.clone(),
            });
        }
        Ok(checked)
    };
    let mut client_information = read_client_information().await?;
    let client_metadata = provider.client_metadata();
    let effective_scope = options.scope.map(str::to_owned).or_else(|| {
        client_metadata
            .get("scope")
            .and_then(Value::as_str)
            .map(str::to_owned)
    });
    let params = match provider
        .prepare_token_request(effective_scope.as_deref())
        .await?
    {
        Some(params) => params,
        None => {
            let Some(code) = options.authorization_code.filter(|code| !code.is_empty()) else {
                return Err(AuthError::Other(
                    "Either provider.prepareTokenRequest() or authorizationCode is required"
                        .to_owned(),
                ));
            };
            let Some(redirect_url) = provider.redirect_url() else {
                return Err(AuthError::Other(
                    "redirectUrl is required for authorization_code flow".to_owned(),
                ));
            };
            let code_verifier = provider.code_verifier().await?;
            prepare_authorization_code_request(code, &code_verifier, &redirect_url)
        }
    };
    if client_information.is_none() {
        client_information = read_client_information().await?;
    }
    execute_token_request(
        authorization_server_url,
        TokenRequestOptions {
            metadata: options.metadata,
            client_information: client_information.as_ref(),
            resource: options.resource,
            fetch: options.fetch,
        },
        params,
        Some(provider),
    )
    .await
}

/// RFC 7591 dynamic client registration.
pub async fn register_client(
    authorization_server_url: &str,
    metadata: Option<&Value>,
    client_metadata: &Value,
    scope: Option<&str>,
    fetch: Option<&FetchFn>,
) -> Result<Value, AuthError> {
    let registration_url = match metadata {
        Some(metadata) => {
            let Some(endpoint) = metadata
                .get("registration_endpoint")
                .and_then(Value::as_str)
                .filter(|endpoint| !endpoint.is_empty())
            else {
                return Err(AuthError::Other(
                    "Incompatible auth server: does not support dynamic client registration"
                        .to_owned(),
                ));
            };
            Url::parse(endpoint)
        }
        None => Url::parse(authorization_server_url).and_then(|base| base.join("/register")),
    }
    .map_err(|_| AuthError::Other("Invalid URL".to_owned()))?;
    let mut submitted_metadata = client_metadata.clone();
    if let (Some(scope), Some(object)) = (scope, submitted_metadata.as_object_mut()) {
        object.insert("scope".to_owned(), json!(scope));
    }
    let response = fetch_within_origin(
        fetch,
        Method::POST,
        &registration_url,
        &[("Content-Type".to_owned(), "application/json".to_owned())],
        Some(submitted_metadata.to_string()),
    )
    .await?;
    let status = response.status();
    if !status.is_success() {
        return Err(AuthError::RegistrationRejected {
            status: status.as_u16(),
            body: response.text().await.unwrap_or_default(),
            submitted_metadata,
        });
    }
    parse_client_information_full(&read_json(response).await?)
}

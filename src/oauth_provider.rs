//! The async face of NodeOAuthClientProvider: the `auth::OAuthClientProvider` the ported SDK
//! `auth()` drives. The synchronous provider keeps the state and the file store; this adds the
//! parts of node-oauth-client-provider.ts that talk to the network (the proactive refresh, the
//! client_credentials renewal, the browser, device and client_credentials sign-ins).

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use tokio::sync::OnceCell;
use url::Url;

use crate::auth::{
    AuthError, AuthOptions, DiscoveryState, OAuthClientProvider, TokenRequestOptions, auth,
    refresh_authorization, select_resource_url,
};
use crate::authorization_server_metadata::fetch_authorization_server_metadata;
use crate::client_credentials;
use crate::device_authorization::{
    self, apply_client_authentication, post_form, select_client_auth_method,
    supports_device_authorization,
};
use crate::logging::{debug_log, log};
use crate::mcp_auth_config::release_config_lease;
use crate::node_oauth_client_provider::REFRESH_LEASE_FILE;
use crate::node_oauth_client_provider::{
    ClientRegistrationSource, CredentialScope, NodeOAuthClientProvider, ResourceSelection,
    SiblingRefresh, UNCOORDINATED, apply_authorize_params, apply_scope, await_refresh_by_sibling,
    requested_scope,
};
use crate::open_browser::{open_browser, sanitize_url};
use crate::streamable_http::{FetchFn, default_client};

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
type InFlight<T> = Mutex<Option<Arc<OnceCell<T>>>>;

fn now_ms() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as f64
}

fn other(error: impl ToString) -> AuthError {
    AuthError::Other(error.to_string())
}

pub struct OAuthProvider {
    inner: Arc<Mutex<NodeOAuthClientProvider>>,
    fetch: Option<FetchFn>,
    refresh_in_flight: InFlight<Option<Value>>,
    client_credentials_in_flight: InFlight<Result<(), String>>,
    open_browser: fn(&str) -> bool,
}

impl OAuthProvider {
    /// `fetch` is what a client_credentials renewal hands to `auth()`, as `options.fetchFn` does.
    pub fn new(provider: NodeOAuthClientProvider, fetch: Option<FetchFn>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(provider)),
            fetch,
            refresh_in_flight: Mutex::new(None),
            client_credentials_in_flight: Mutex::new(None),
            open_browser,
        }
    }

    /// Replaces the browser launcher, so tests can follow the authorization URL themselves.
    pub fn with_browser_opener(mut self, open_browser: fn(&str) -> bool) -> Self {
        self.open_browser = open_browser;
        self
    }

    /// The synchronous provider. Never hold this across an await.
    pub fn lock(&self) -> MutexGuard<'_, NodeOAuthClientProvider> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn set_callback_port(&self, port: u16) {
        self.lock().set_callback_port(port);
    }

    pub fn use_authorization_state(&self, state: &str) {
        self.lock().use_authorization_state(state);
    }

    pub async fn get_authorization_server_metadata(&self) -> Option<Value> {
        let (cached, server_url) = {
            let provider = self.lock();
            (
                provider.authorization_server_metadata.clone(),
                provider.options.server_url.clone(),
            )
        };
        debug_log(
            &format!(
                "authorizationServerMetadata: {}",
                cached
                    .as_ref()
                    .map_or("undefined".to_owned(), Value::to_string)
            ),
            &[],
        );
        if cached.is_some() {
            return cached;
        }
        fetch_and_cache_metadata(&self.inner, &server_url).await
    }

    /// Runs `attempt` once for everyone who asks while it is running, as the TypeScript
    /// provider's in-flight promises do.
    async fn join<T: Clone + Send + Sync>(
        slot: &InFlight<T>,
        attempt: impl Future<Output = T>,
    ) -> T {
        let cell = {
            let mut in_flight = slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            in_flight
                .get_or_insert_with(|| Arc::new(OnceCell::new()))
                .clone()
        };
        let result = cell.get_or_init(|| attempt).await.clone();
        let mut in_flight = slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if in_flight
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, &cell))
        {
            *in_flight = None;
        }
        result
    }

    fn renew_client_credentials(&self, scope: Option<String>) -> BoxFuture<'_, Result<(), String>> {
        Box::pin(async move {
            let attempt = async {
                let server_url = self.lock().resource_server_url().to_owned();
                let server_url = Url::parse(&server_url).map_err(|error| error.to_string())?;
                let mut options = AuthOptions::new(server_url);
                options.scope = scope;
                options.fetch = self.fetch.clone();
                auth(self, &options)
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            };
            let attempt: BoxFuture<'_, Result<(), String>> = Box::pin(attempt);
            Self::join(&self.client_credentials_in_flight, attempt).await
        })
    }

    async fn refresh_tokens(&self, refresh_token: &str) -> Option<Value> {
        Self::join(
            &self.refresh_in_flight,
            self.refresh_once_per_host(refresh_token),
        )
        .await
    }

    async fn refresh_once_per_host(&self, refresh_token: &str) -> Option<Value> {
        let (lease, server_url_hash) = {
            let provider = self.lock();
            (
                provider.take_refresh_lease(),
                provider.server_url_hash.clone(),
            )
        };
        let lease = match lease {
            Some(lease) => lease,
            None => {
                let hash = server_url_hash.clone();
                let sibling = tokio::task::spawn_blocking(move || await_refresh_by_sibling(&hash))
                    .await
                    .ok()?;
                match sibling {
                    SiblingRefresh::Tokens(tokens) => {
                        debug_log("Another instance refreshed the token", &[]);
                        return Some(tokens);
                    }
                    SiblingRefresh::Released => return None,
                    SiblingRefresh::Abandoned => self.lock().take_refresh_lease()?,
                }
            }
        };

        let stored_refresh_token = self
            .lock()
            .stored_tokens()
            .and_then(|stored| stored.get("refresh_token")?.as_str().map(str::to_owned));
        let result = self
            .do_refresh_tokens(stored_refresh_token.as_deref().unwrap_or(refresh_token))
            .await;

        if lease != UNCOORDINATED {
            release_config_lease(&server_url_hash, REFRESH_LEASE_FILE, &lease);
        }
        result
    }

    async fn do_refresh_tokens(&self, refresh_token: &str) -> Option<Value> {
        match self.try_refresh_tokens(refresh_token).await {
            Ok(tokens) => tokens,
            Err(error) => {
                debug_log(
                    "Proactive token refresh failed",
                    &[json!(error.to_string())],
                );
                None
            }
        }
    }

    async fn try_refresh_tokens(&self, refresh_token: &str) -> Result<Option<Value>, AuthError> {
        let Some(client_information) = self.lock().client_information() else {
            debug_log(
                "No client information available, cannot refresh proactively",
                &[],
            );
            return Ok(None);
        };

        let metadata = self.get_authorization_server_metadata().await;
        let (protected_resource_metadata, server_url, resource_server_url) = {
            let provider = self.lock();
            (
                provider.protected_resource_metadata.clone(),
                provider.options.server_url.clone(),
                provider.resource_server_url().to_owned(),
            )
        };
        let authorization_server_url = match protected_resource_metadata
            .as_ref()
            .and_then(|metadata| metadata.get("authorization_servers")?.get(0)?.as_str())
        {
            Some(url) => url.to_owned(),
            None => Url::parse(&server_url)
                .and_then(|url| url.join("/"))
                .map_err(other)?
                .to_string(),
        };
        let resource = select_resource_url(
            &Url::parse(&resource_server_url).map_err(other)?,
            self,
            protected_resource_metadata.as_ref(),
        )
        .await?;

        debug_log(
            "Refreshing access token before it expires",
            &[json!({
                "authorizationServerUrl": authorization_server_url,
                "resource": resource.as_ref().map(Url::as_str),
            })],
        );

        let token_request_metadata = metadata.map(|metadata| {
            json!({
                "token_endpoint": metadata.get("token_endpoint"),
                "token_endpoint_auth_methods_supported":
                    metadata.get("token_endpoint_auth_methods_supported"),
            })
        });
        let refreshed = refresh_authorization(
            &authorization_server_url,
            TokenRequestOptions {
                metadata: token_request_metadata.as_ref(),
                client_information: Some(&client_information),
                resource: resource.as_ref().map(Url::as_str),
                fetch: None,
            },
            refresh_token,
            Some(self),
        )
        .await?;

        let now = now_ms();
        self.lock().save_tokens(&refreshed, now).map_err(other)?;
        log("Refreshed the access token before it expired", &[]);

        let mut tokens = refreshed;
        if let Some(expires_in) = tokens
            .get("expires_in")
            .and_then(Value::as_f64)
            .filter(|seconds| *seconds != 0.0)
            && let Some(object) = tokens.as_object_mut()
        {
            object.insert("expires_at".to_owned(), json!(now + expires_in * 1000.0));
        }
        Ok(Some(tokens))
    }

    async fn authorize_with_device_code(&self) -> Result<(), AuthError> {
        let metadata = self
            .get_authorization_server_metadata()
            .await
            .filter(|metadata| supports_device_authorization(Some(metadata)))
            .ok_or_else(|| {
                other("--device-code was passed but the authorization server does not offer the device grant. Remove the flag to sign in through a browser instead.")
            })?;

        let (client_information, scope, resource) = {
            let mut provider = self.lock();
            let client_information = provider.client_information().ok_or_else(|| {
                other("No OAuth client is registered, so there is nothing to authorize")
            })?;
            let scope = Some(provider.effective_scope()).filter(|scope| !scope.is_empty());
            let resource = provider.device_authorization_resource().map_err(other)?;
            (client_information, scope, resource)
        };

        let handle = tokio::runtime::Handle::current();
        let tokens = tokio::task::spawn_blocking(move || {
            device_authorization::authorize_with_device_code(
                &metadata,
                &client_information,
                scope.as_deref(),
                resource.as_ref(),
                now_ms,
                |seconds| std::thread::sleep(Duration::from_secs_f64(seconds.max(0.0))),
                |endpoint, request| handle.block_on(post_form(endpoint, request)),
            )
        })
        .await
        .map_err(other)?
        .map_err(AuthError::Other)?;

        self.lock().save_tokens(&tokens, now_ms()).map_err(other)
    }

    async fn authorize_with_client_credentials(&self) -> Result<(), AuthError> {
        let metadata = self.get_authorization_server_metadata().await.ok_or_else(|| {
            other("Could not discover the authorization server metadata, so there is no token endpoint to ask")
        })?;

        let (client_information, scope, resource) = {
            let mut provider = self.lock();
            let client_information = provider.client_information().ok_or_else(|| {
                other("No OAuth client credentials were supplied; pass them with --static-oauth-client-info")
            })?;
            let scope =
                requested_scope(&provider.scope_sources()).filter(|scope| !scope.is_empty());
            let resource = provider.device_authorization_resource().map_err(other)?;
            (client_information, scope, resource)
        };

        let tokens = client_credentials::authorize_with_client_credentials(
            &metadata,
            &client_information,
            scope.as_deref(),
            resource.as_ref(),
        )
        .await
        .map_err(AuthError::Other)?;

        self.lock().save_tokens(&tokens, now_ms()).map_err(other)
    }

    async fn preflight_cached_dynamic_client_registration(
        &self,
        authorization_url: &Url,
    ) -> Result<(), AuthError> {
        if self.lock().client_registration_source != Some(ClientRegistrationSource::CachedDynamic) {
            return Ok(());
        }

        let response = async {
            let response = default_client()
                .get(authorization_url.as_str())
                .header("Accept", "application/json")
                .timeout(Duration::from_secs(5))
                .send()
                .await
                .map_err(|error| error.to_string())?;
            let status = response.status().as_u16();
            let body = response.text().await.map_err(|error| error.to_string())?;
            Ok::<_, String>((status, body))
        }
        .await;

        self.lock()
            .preflight_cached_dynamic_client_registration(authorization_url, |_| response)
            .map_err(|error| AuthError::oauth(&error.code, error.message))
    }
}

async fn fetch_and_cache_metadata(
    inner: &Mutex<NodeOAuthClientProvider>,
    server_url: &str,
) -> Option<Value> {
    let metadata = fetch_authorization_server_metadata(server_url).await;
    if let Some(scopes_supported) = metadata
        .as_ref()
        .and_then(|metadata| metadata.get("scopes_supported"))
        .filter(|scopes| !scopes.is_null())
    {
        debug_log(
            "Authorization server supports scopes",
            &[json!({ "scopes_supported": scopes_supported })],
        );
    }
    inner
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .authorization_server_metadata = metadata.clone();
    metadata
}

impl OAuthClientProvider for OAuthProvider {
    fn redirect_url(&self) -> Option<String> {
        self.lock().redirect_url()
    }

    fn client_metadata(&self) -> Value {
        self.lock().client_metadata()
    }

    fn client_metadata_url(&self) -> Option<String> {
        self.lock().client_metadata_url.clone()
    }

    async fn state(&self) -> Result<Option<String>, AuthError> {
        Ok(Some(self.lock().next_state(now_ms())))
    }

    async fn client_information(&self, _issuer: &str) -> Option<Value> {
        self.lock().client_information()
    }

    async fn save_client_information(
        &self,
        client_information: &Value,
        _issuer: &str,
    ) -> Result<(), AuthError> {
        self.lock()
            .save_client_information(client_information)
            .map_err(other)
    }

    async fn tokens(&self, _issuer: Option<&str>) -> Option<Value> {
        let (stored, has_explicit_token_endpoint) = {
            let mut provider = self.lock();
            (
                provider.read_stored_tokens(now_ms())?,
                provider.has_explicit_token_endpoint(),
            )
        };
        let tokens = stored.tokens;

        if stored.is_expired && has_explicit_token_endpoint {
            let scope = tokens
                .get("requested_scope")
                .and_then(Value::as_str)
                .or_else(|| tokens.get("scope").and_then(Value::as_str))
                .map(str::to_owned);
            return match self.renew_client_credentials(scope).await {
                Ok(()) => {
                    let mut provider = self.lock();
                    let renewed = provider.stored_tokens();
                    provider.as_bearer_tokens(renewed)
                }
                Err(error) => {
                    debug_log(
                        "Proactive client_credentials renewal failed",
                        &[json!(error)],
                    );
                    log(
                        "Proactive token renewal failed, falling back to the stored token",
                        &[],
                    );
                    self.lock().as_bearer_tokens(Some(tokens))
                }
            };
        }

        if stored.is_expired
            && let Some(refresh_token) = tokens
                .get("refresh_token")
                .and_then(Value::as_str)
                .filter(|refresh_token| !refresh_token.is_empty())
        {
            if let Some(refreshed) = self.refresh_tokens(refresh_token).await {
                return self.lock().as_bearer_tokens(Some(refreshed));
            }
            log(
                "Proactive token refresh failed, falling back to the stored token",
                &[],
            );
        }

        self.lock().as_bearer_tokens(Some(tokens))
    }

    async fn save_tokens(&self, tokens: &Value, _issuer: &str) -> Result<(), AuthError> {
        self.lock().save_tokens(tokens, now_ms()).map_err(other)
    }

    async fn redirect_to_authorization(&self, authorization_url: &Url) -> Result<(), AuthError> {
        let (use_device_code, use_client_credentials, metadata_known, server_url) = {
            let mut provider = self.lock();
            if provider.token_storm_brake.in_token_storm(now_ms()) {
                return Err(other(provider.token_storm_brake.token_storm_error()));
            }
            if !provider.owns_pending_flow(authorization_url) {
                log(
                    "A sign-in for this server is already under way; not starting another",
                    &[],
                );
                debug_log(
                    "Suppressed a concurrent authorization redirect",
                    &[json!({ "state": provider.pending_flow.as_ref().map(|flow| &flow.state) })],
                );
                return Ok(());
            }
            (
                provider.use_device_code,
                provider.use_client_credentials,
                provider.authorization_server_metadata.is_some(),
                provider.options.server_url.clone(),
            )
        };

        if use_device_code {
            return self.authorize_with_device_code().await;
        }
        if use_client_credentials {
            return self.authorize_with_client_credentials().await;
        }

        // Optionally fetch metadata for debugging/informational purposes (non-blocking)
        if !metadata_known {
            let inner = Arc::clone(&self.inner);
            tokio::spawn(async move { fetch_and_cache_metadata(&inner, &server_url).await });
        }

        let mut authorization_url = authorization_url.clone();
        {
            let provider = self.lock();
            apply_scope(
                &mut authorization_url,
                &provider.scope_sources(),
                provider.has_explicit_token_endpoint(),
            );
            apply_authorize_params(&mut authorization_url, &provider.authorize_params);
        }

        log(
            &format!("\nPlease authorize this client by visiting:\n{authorization_url}\n"),
            &[],
        );
        debug_log(
            "Redirecting to authorization URL",
            &[json!(authorization_url.as_str())],
        );

        self.preflight_cached_dynamic_client_registration(&authorization_url)
            .await?;

        self.lock()
            .authorization_storm_brake
            .guard_against_authorization_storm(now_ms())
            .map_err(AuthError::Other)?;

        let sanitized = sanitize_url(authorization_url.as_str()).map_err(AuthError::Other)?;
        let open_browser = self.open_browser;
        let opened = tokio::task::spawn_blocking(move || open_browser(&sanitized))
            .await
            .unwrap_or(false);
        if opened {
            log("Browser opened automatically.", &[]);
        } else {
            log(
                "Could not open a browser automatically. Please copy and paste the URL above into your browser.",
                &[],
            );
        }
        Ok(())
    }

    async fn save_code_verifier(&self, code_verifier: &str) -> Result<(), AuthError> {
        self.lock().save_code_verifier(code_verifier).map_err(other)
    }

    async fn code_verifier(&self) -> Result<String, AuthError> {
        self.lock().code_verifier().map_err(other)
    }

    fn can_invalidate_credentials(&self) -> bool {
        true
    }

    async fn invalidate_credentials(&self, scope: CredentialScope) -> Result<(), AuthError> {
        self.lock().invalidate_credentials(scope);
        Ok(())
    }

    fn has_validate_resource_url(&self) -> bool {
        self.lock().resource_selection != ResourceSelection::SdkDefault
    }

    async fn validate_resource_url(
        &self,
        _default_resource: &Url,
        _discovered_resource: Option<&str>,
    ) -> Result<Option<Url>, AuthError> {
        Ok(self.lock().resource_selection.validate_resource_url())
    }

    async fn prepare_token_request(
        &self,
        scope: Option<&str>,
    ) -> Result<Option<Vec<(String, String)>>, AuthError> {
        let params = self
            .lock()
            .prepare_token_request(scope, now_ms())
            .map_err(AuthError::Other)?;
        Ok(params.map(|params| {
            params
                .into_iter()
                .map(|(name, value)| (name.to_owned(), value))
                .collect()
        }))
    }

    fn has_add_client_authentication(&self) -> bool {
        true
    }

    async fn add_client_authentication(
        &self,
        headers: &mut Vec<(String, String)>,
        params: &mut Vec<(String, String)>,
        _token_url: &Url,
        metadata: Option<&Value>,
    ) -> Result<(), AuthError> {
        let mut provider = self.lock();
        if let Some(client_information) = provider.client_information() {
            let pinned_method = provider
                .static_oauth_client_metadata
                .as_ref()
                .and_then(|metadata| metadata.get("token_endpoint_auth_method"))
                .filter(|method| !method.is_null() && method.as_str() != Some(""))
                .cloned();
            let mut effective = client_information.clone();
            if provider.has_explicit_token_endpoint()
                && let (Some(method), Some(object)) = (pinned_method, effective.as_object_mut())
            {
                object.insert("token_endpoint_auth_method".to_owned(), method);
            }
            let supported: Vec<&str> = metadata
                .and_then(|metadata| metadata.get("token_endpoint_auth_methods_supported"))
                .and_then(Value::as_array)
                .map(|methods| methods.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            let method = select_client_auth_method(&effective, &supported);
            apply_client_authentication(
                method,
                client_information
                    .get("client_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
                client_information
                    .get("client_secret")
                    .and_then(Value::as_str),
                headers,
                params,
            )
            .map_err(AuthError::Other)?;
        }

        let is_refresh = params
            .iter()
            .find(|(name, _)| name == "grant_type")
            .is_some_and(|(_, grant)| grant == "refresh_token");
        if is_refresh && !params.iter().any(|(name, _)| name == "scope") {
            let scope = provider.scope_to_repeat_on_refresh();
            if !scope.is_empty() {
                params.push(("scope".to_owned(), scope.clone()));
                debug_log(
                    "Added the requested scope to the refresh_token grant",
                    &[json!({ "scope": scope })],
                );
            }
        }
        Ok(())
    }

    async fn discovery_state(&self) -> Option<DiscoveryState> {
        self.lock()
            .discovery_state()
            .as_ref()
            .and_then(DiscoveryState::from_value)
    }
}

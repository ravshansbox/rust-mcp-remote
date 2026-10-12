use std::sync::{Arc, Mutex, OnceLock};

use reqwest::Method;
use rust_mcp_remote::auth::{
    AuthError, AuthOptions, AuthResult, DiscoveryState, FetchTokenOptions, IssuerMismatchKind,
    OAuthClientProvider, TokenRequestOptions, discover_authorization_server_metadata,
    discover_oauth_protected_resource_metadata, discover_oauth_server_info, exchange_authorization,
    execute_token_request, fetch_token, fetch_within_origin, refresh_authorization,
    register_client, resolve_authorization_callback_params, resolve_client_metadata,
    select_resource_url,
};
use rust_mcp_remote::node_oauth_client_provider::{CredentialScope, code_challenge_for};
use serde_json::{Value, json};
use tokio::sync::mpsc::UnboundedReceiver;
use url::Url;

use crate::test_server::{RecordedRequest, Reply, reply, serve};

const JSON: (&str, &str) = ("content-type", "application/json");

#[derive(Default)]
struct Store {
    client_information: Option<Value>,
    tokens: Option<Value>,
    code_verifier: Option<String>,
    redirected_to: Option<Url>,
    discovery_state: Option<DiscoveryState>,
    invalidated: Vec<CredentialScope>,
    resource_url: Option<String>,
    validated_resource: Option<(String, Option<String>)>,
    prepared_for_scope: Option<Option<String>>,
}

struct TestProvider {
    store: Mutex<Store>,
    persist_discovery_state: bool,
    /// When false, the provider is read-only for client information.
    persist_client_information: bool,
    /// When set, the provider overrides `validate_resource_url` and returns this.
    resource_override: Option<Option<Url>>,
    /// When set, replaces the default redirect URL and client metadata.
    redirect_url: Option<Option<String>>,
    client_metadata: Option<Value>,
    client_metadata_url: Option<String>,
    /// When set, `prepare_token_request` returns this grant instead of None.
    prepared_grant: Option<Vec<(String, String)>>,
}

impl TestProvider {
    fn new() -> Self {
        Self {
            store: Mutex::new(Store::default()),
            persist_discovery_state: true,
            persist_client_information: true,
            resource_override: None,
            redirect_url: None,
            client_metadata: None,
            client_metadata_url: None,
            prepared_grant: None,
        }
    }

    fn store(&self) -> std::sync::MutexGuard<'_, Store> {
        self.store.lock().unwrap()
    }
}

impl OAuthClientProvider for TestProvider {
    fn redirect_url(&self) -> Option<String> {
        self.redirect_url
            .clone()
            .unwrap_or_else(|| Some("http://localhost:3334/oauth/callback".to_owned()))
    }

    fn client_metadata(&self) -> Value {
        self.client_metadata.clone().unwrap_or_else(|| {
            json!({
                "redirect_uris": ["http://localhost:3334/oauth/callback"],
                "client_name": "test",
                "token_endpoint_auth_method": "none",
            })
        })
    }

    fn client_metadata_url(&self) -> Option<String> {
        self.client_metadata_url.clone()
    }

    async fn state(&self) -> Result<Option<String>, AuthError> {
        Ok(Some("the-state".to_owned()))
    }

    async fn client_information(&self, _issuer: &str) -> Option<Value> {
        self.store().client_information.clone()
    }

    fn can_save_client_information(&self) -> bool {
        self.persist_client_information
    }

    async fn save_client_information(
        &self,
        client_information: &Value,
        _issuer: &str,
    ) -> Result<(), AuthError> {
        self.store().client_information = Some(client_information.clone());
        Ok(())
    }

    async fn tokens(&self, _issuer: Option<&str>) -> Option<Value> {
        self.store().tokens.clone()
    }

    async fn save_tokens(&self, tokens: &Value, _issuer: &str) -> Result<(), AuthError> {
        self.store().tokens = Some(tokens.clone());
        Ok(())
    }

    async fn redirect_to_authorization(&self, authorization_url: &Url) -> Result<(), AuthError> {
        self.store().redirected_to = Some(authorization_url.clone());
        Ok(())
    }

    async fn save_code_verifier(&self, code_verifier: &str) -> Result<(), AuthError> {
        self.store().code_verifier = Some(code_verifier.to_owned());
        Ok(())
    }

    async fn prepare_token_request(
        &self,
        scope: Option<&str>,
    ) -> Result<Option<Vec<(String, String)>>, AuthError> {
        self.store().prepared_for_scope = Some(scope.map(str::to_owned));
        Ok(self.prepared_grant.clone())
    }

    async fn code_verifier(&self) -> Result<String, AuthError> {
        self.store()
            .code_verifier
            .clone()
            .ok_or_else(|| AuthError::Other("no verifier".to_owned()))
    }

    fn can_invalidate_credentials(&self) -> bool {
        true
    }

    async fn invalidate_credentials(&self, scope: CredentialScope) -> Result<(), AuthError> {
        let mut store = self.store();
        store.invalidated.push(scope);
        match scope {
            CredentialScope::Client => store.client_information = None,
            CredentialScope::Tokens => store.tokens = None,
            _ => {}
        }
        Ok(())
    }

    async fn discovery_state(&self) -> Option<DiscoveryState> {
        self.store().discovery_state.clone()
    }

    fn can_save_discovery_state(&self) -> bool {
        self.persist_discovery_state
    }

    async fn save_discovery_state(&self, state: &DiscoveryState) -> Result<(), AuthError> {
        if self.persist_discovery_state {
            self.store().discovery_state = Some(state.clone());
        }
        Ok(())
    }

    fn has_validate_resource_url(&self) -> bool {
        self.resource_override.is_some()
    }

    async fn validate_resource_url(
        &self,
        default_resource: &Url,
        discovered_resource: Option<&str>,
    ) -> Result<Option<Url>, AuthError> {
        self.store().validated_resource = Some((
            default_resource.to_string(),
            discovered_resource.map(str::to_owned),
        ));
        Ok(self.resource_override.clone().flatten())
    }

    async fn save_resource_url(&self, resource: &str) -> Result<(), AuthError> {
        self.store().resource_url = Some(resource.to_owned());
        Ok(())
    }
}

type Respond = dyn Fn(&str, &RecordedRequest) -> Option<Reply> + Send + Sync;

/// An MCP server that is its own authorization server. `respond` can override any path.
async fn auth_server(respond: Arc<Respond>) -> (String, UnboundedReceiver<RecordedRequest>) {
    let base = Arc::new(OnceLock::<String>::new());
    let handler_base = Arc::clone(&base);
    let (url, requests) = serve(Arc::new(move |request: &RecordedRequest| {
        let base = handler_base.get().cloned().unwrap_or_default();
        if let Some(reply) = respond(&base, request) {
            return reply;
        }
        let path = request.path.split('?').next().unwrap_or("");
        match path {
            "/.well-known/oauth-protected-resource/mcp" => reply(
                200,
                &[JSON],
                &json!({"resource": format!("{base}/mcp"), "authorization_servers": [base],
                        "scopes_supported": ["mcp:tools"]})
                .to_string(),
            ),
            "/.well-known/oauth-authorization-server" => reply(
                200,
                &[JSON],
                &json!({
                    "issuer": base,
                    "authorization_endpoint": format!("{base}/authorize"),
                    "token_endpoint": format!("{base}/token"),
                    "registration_endpoint": format!("{base}/register"),
                    "response_types_supported": ["code"],
                    "code_challenge_methods_supported": ["S256"],
                })
                .to_string(),
            ),
            "/register" => {
                let mut info: Value = serde_json::from_str(&request.body).unwrap();
                info["client_id"] = json!("registered-client");
                info["issuer"] = json!("https://smuggled.example");
                reply(201, &[JSON], &info.to_string())
            }
            "/token" => reply(
                200,
                &[JSON],
                r#"{"access_token":"at-1","token_type":"Bearer","expires_in":3600,"refresh_token":"rt-1"}"#,
            ),
            _ => reply(404, &[], "not found"),
        }
    }))
    .await;
    base.set(url.clone()).unwrap();
    (url, requests)
}

fn drain(requests: &mut UnboundedReceiver<RecordedRequest>) -> Vec<RecordedRequest> {
    let mut seen = Vec::new();
    while let Ok(request) = requests.try_recv() {
        seen.push(request);
    }
    seen
}

fn form(body: &str) -> Vec<(String, String)> {
    url::form_urlencoded::parse(body.as_bytes())
        .into_owned()
        .collect()
}

fn param<'a>(pairs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
}

fn options(base: &str) -> AuthOptions {
    AuthOptions::new(Url::parse(&format!("{base}/mcp")).unwrap())
}

#[tokio::test]
async fn first_run_discovers_registers_and_redirects() {
    let (base, mut requests) = auth_server(Arc::new(|_, _| None)).await;
    let provider = Arc::new(TestProvider::new());

    // The future is Send, so the proxy can run auth() on a tokio task.
    let task_provider = Arc::clone(&provider);
    let task_options = options(&base);
    let result =
        tokio::spawn(
            async move { rust_mcp_remote::auth::auth(&*task_provider, &task_options).await },
        )
        .await
        .unwrap();
    assert_eq!(result, Ok(AuthResult::Redirect));

    let paths: Vec<String> = drain(&mut requests).into_iter().map(|r| r.path).collect();
    assert_eq!(
        paths,
        [
            "/.well-known/oauth-protected-resource/mcp",
            "/.well-known/oauth-authorization-server",
            "/register"
        ]
    );

    let store = provider.store();
    let info = store.client_information.clone().unwrap();
    assert_eq!(info["client_id"], "registered-client");
    assert_eq!(
        info["issuer"],
        json!(base),
        "the client stamps the issuer, not the server"
    );
    assert_eq!(
        info["grant_types"],
        json!(["authorization_code", "refresh_token"])
    );
    assert_eq!(info["application_type"], "native");
    assert_eq!(info["scope"], "mcp:tools");
    assert_eq!(
        store
            .discovery_state
            .as_ref()
            .unwrap()
            .authorization_server_url,
        base
    );
    assert_eq!(
        store.resource_url.as_deref(),
        Some(format!("{base}/mcp").as_str())
    );

    let authorize = store.redirected_to.clone().unwrap();
    assert_eq!(authorize.path(), "/authorize");
    let pairs: Vec<(String, String)> = authorize.query_pairs().into_owned().collect();
    assert_eq!(param(&pairs, "client_id"), Some("registered-client"));
    assert_eq!(param(&pairs, "state"), Some("the-state"));
    assert_eq!(param(&pairs, "scope"), Some("mcp:tools"));
    assert_eq!(
        param(&pairs, "resource"),
        Some(format!("{base}/mcp").as_str())
    );
    let verifier = store.code_verifier.clone().unwrap();
    assert_eq!(
        param(&pairs, "code_challenge"),
        Some(code_challenge_for(&verifier).as_str())
    );
}

#[tokio::test]
async fn the_callback_leg_exchanges_the_code_and_stamps_the_tokens() {
    let (base, mut requests) = auth_server(Arc::new(|_, _| None)).await;
    let provider = TestProvider::new();
    rust_mcp_remote::auth::auth(&provider, &options(&base))
        .await
        .unwrap();
    drain(&mut requests);

    let mut callback = options(&base);
    callback.authorization_code = Some("the-code".to_owned());
    let result = rust_mcp_remote::auth::auth(&provider, &callback).await;
    assert_eq!(result, Ok(AuthResult::Authorized));

    let seen = drain(&mut requests);
    assert_eq!(seen.len(), 1, "discovery comes from the saved state");
    assert_eq!(seen[0].path, "/token");
    assert_eq!(
        seen[0].header("content-type"),
        Some("application/x-www-form-urlencoded")
    );
    let body = form(&seen[0].body);
    let verifier = provider.store().code_verifier.clone().unwrap();
    assert_eq!(param(&body, "grant_type"), Some("authorization_code"));
    assert_eq!(param(&body, "code"), Some("the-code"));
    assert_eq!(param(&body, "code_verifier"), Some(verifier.as_str()));
    assert_eq!(
        param(&body, "redirect_uri"),
        Some("http://localhost:3334/oauth/callback")
    );
    assert_eq!(param(&body, "client_id"), Some("registered-client"));
    assert_eq!(
        param(&body, "resource"),
        Some(format!("{base}/mcp").as_str())
    );

    let tokens = provider.store().tokens.clone().unwrap();
    assert_eq!(
        tokens,
        json!({"access_token": "at-1", "token_type": "Bearer", "expires_in": 3600,
               "refresh_token": "rt-1", "issuer": base})
    );
}

#[tokio::test]
async fn the_callback_leg_refuses_a_different_authorization_server() {
    let (base, _requests) = auth_server(Arc::new(|_, _| None)).await;
    let provider = TestProvider::new();
    provider.store().discovery_state = Some(DiscoveryState {
        authorization_server_url: "https://other.example".to_owned(),
        resource_metadata_url: None,
        resource_metadata: None,
        authorization_server_metadata: Some(json!({
            "issuer": base, "authorization_endpoint": format!("{base}/authorize"),
            "token_endpoint": format!("{base}/token"), "response_types_supported": ["code"]
        })),
    });
    let mut callback = options(&base);
    callback.authorization_code = Some("code".to_owned());
    // The recorded issuer and the one this call resolves agree, so the client check runs next.
    let error = rust_mcp_remote::auth::auth(&provider, &callback)
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "Existing OAuth client information is required when exchanging an authorization code"
    );

    let no_state = TestProvider::new();
    no_state.store().client_information = Some(json!({"client_id": "c"}));
    let error = rust_mcp_remote::auth::auth(&no_state, &callback)
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        AuthError::AuthorizationServerMismatch { .. }
    ));
    assert!(
        error
            .to_string()
            .starts_with("Authorization server mismatch: credentials are bound to \"discoveryState was not available"),
        "{error}"
    );
}

#[tokio::test]
async fn stored_refresh_tokens_are_refreshed_and_kept_when_not_rotated() {
    let (base, mut requests) = auth_server(Arc::new(|_, request| {
        (request.path == "/token").then(|| {
            reply(
                200,
                &[JSON],
                r#"{"access_token":"at-2","token_type":"Bearer"}"#,
            )
        })
    }))
    .await;
    let provider = TestProvider::new();
    {
        let mut store = provider.store();
        store.client_information =
            Some(json!({"client_id": "cid", "client_secret": "s", "issuer": base}));
        store.tokens =
            Some(json!({"access_token": "old", "token_type": "Bearer", "refresh_token": "rt-0"}));
    }
    let result = rust_mcp_remote::auth::auth(&provider, &options(&base)).await;
    assert_eq!(result, Ok(AuthResult::Authorized));

    let token_request = drain(&mut requests)
        .into_iter()
        .find(|request| request.path == "/token")
        .unwrap();
    let body = form(&token_request.body);
    assert_eq!(param(&body, "grant_type"), Some("refresh_token"));
    assert_eq!(param(&body, "refresh_token"), Some("rt-0"));
    assert_eq!(
        token_request.header("authorization"),
        Some("Basic Y2lkOnM="),
        "a client with a secret uses client_secret_basic by default"
    );
    assert_eq!(
        provider.store().tokens.clone().unwrap(),
        json!({"refresh_token": "rt-0", "access_token": "at-2", "token_type": "Bearer", "issuer": base})
    );
}

#[tokio::test]
async fn invalid_grant_discards_the_tokens_and_starts_over() {
    let (base, _requests) = auth_server(Arc::new(|_, request| {
        (request.path == "/token").then(|| {
            reply(
                400,
                &[JSON],
                r#"{"error":"invalid_grant","error_description":"refresh token revoked"}"#,
            )
        })
    }))
    .await;
    let provider = TestProvider::new();
    {
        let mut store = provider.store();
        store.client_information = Some(json!({"client_id": "cid", "issuer": base}));
        store.tokens = Some(
            json!({"access_token": "old", "token_type": "Bearer", "refresh_token": "rt-0", "issuer": base}),
        );
    }
    let result = rust_mcp_remote::auth::auth(&provider, &options(&base)).await;
    assert_eq!(result, Ok(AuthResult::Redirect));
    let store = provider.store();
    assert_eq!(store.invalidated, [CredentialScope::Tokens]);
    assert!(store.tokens.is_none());
    let authorize = store.redirected_to.clone().unwrap();
    assert_eq!(authorize.path(), "/authorize");
    let pairs: Vec<(String, String)> = authorize.query_pairs().into_owned().collect();
    assert_eq!(param(&pairs, "client_id"), Some("cid"));
}

#[tokio::test]
async fn a_server_error_on_refresh_falls_back_to_a_new_authorization() {
    let (base, _requests) = auth_server(Arc::new(|_, request| {
        (request.path == "/token").then(|| reply(500, &[], "boom"))
    }))
    .await;
    let provider = TestProvider::new();
    {
        let mut store = provider.store();
        store.client_information = Some(json!({"client_id": "cid", "issuer": base}));
        store.tokens = Some(
            json!({"access_token": "old", "token_type": "Bearer", "refresh_token": "rt-0", "issuer": base}),
        );
    }
    let result = rust_mcp_remote::auth::auth(&provider, &options(&base)).await;
    assert_eq!(result, Ok(AuthResult::Redirect));
    assert!(provider.store().invalidated.is_empty());
}

#[tokio::test]
async fn credentials_stamped_for_another_issuer_are_not_reused() {
    let (base, mut requests) = auth_server(Arc::new(|_, _| None)).await;
    let provider = TestProvider::new();
    {
        let mut store = provider.store();
        store.client_information =
            Some(json!({"client_id": "elsewhere", "issuer": "https://other.example"}));
        store.tokens = Some(
            json!({"access_token": "x", "token_type": "Bearer", "refresh_token": "rt", "issuer": "https://other.example"}),
        );
    }
    let result = rust_mcp_remote::auth::auth(&provider, &options(&base)).await;
    assert_eq!(result, Ok(AuthResult::Redirect));
    let paths: Vec<String> = drain(&mut requests).into_iter().map(|r| r.path).collect();
    assert!(paths.contains(&"/register".to_owned()));
    assert!(!paths.contains(&"/token".to_owned()));
    assert_eq!(
        provider.store().client_information.clone().unwrap()["client_id"],
        "registered-client"
    );
}

#[tokio::test]
async fn a_provider_that_cannot_save_client_information_never_registers() {
    let (base, mut requests) = auth_server(Arc::new(|_, _| None)).await;
    let read_only = || TestProvider {
        persist_client_information: false,
        ..TestProvider::new()
    };

    let provider = read_only();
    let error = rust_mcp_remote::auth::auth(&provider, &options(&base))
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "OAuth client information must be saveable for dynamic registration"
    );

    let provider = read_only();
    provider.store().client_information =
        Some(json!({"client_id": "elsewhere", "issuer": "https://other.example"}));
    let error = rust_mcp_remote::auth::auth(&provider, &options(&base))
        .await
        .unwrap_err();
    assert_eq!(
        error,
        AuthError::AuthorizationServerMismatch {
            recorded: "https://other.example".to_owned(),
            current: base.clone(),
        }
    );

    // Unstamped client information is used as is; the stamp is not saved.
    let provider = read_only();
    provider.store().client_information = Some(json!({"client_id": "pre-registered"}));
    let result = rust_mcp_remote::auth::auth(&provider, &options(&base)).await;
    assert_eq!(result, Ok(AuthResult::Redirect));
    let store = provider.store();
    assert_eq!(
        store.client_information,
        Some(json!({"client_id": "pre-registered"}))
    );
    let pairs: Vec<(String, String)> = store
        .redirected_to
        .as_ref()
        .unwrap()
        .query_pairs()
        .into_owned()
        .collect();
    assert_eq!(param(&pairs, "client_id"), Some("pre-registered"));

    let paths: Vec<String> = drain(&mut requests).into_iter().map(|r| r.path).collect();
    assert!(!paths.contains(&"/register".to_owned()), "{paths:?}");
}

#[tokio::test]
async fn a_client_metadata_url_is_the_client_id_when_the_server_supports_it() {
    let metadata_url = "https://client.example/oauth/metadata.json";
    let with_url = |url: &str| TestProvider {
        client_metadata_url: Some(url.to_owned()),
        ..TestProvider::new()
    };
    let (base, mut requests) = auth_server(Arc::new(|base, request| {
        (request.path == "/.well-known/oauth-authorization-server").then(|| {
            reply(
                200,
                &[JSON],
                &json!({
                    "issuer": base,
                    "authorization_endpoint": format!("{base}/authorize"),
                    "token_endpoint": format!("{base}/token"),
                    "registration_endpoint": format!("{base}/register"),
                    "response_types_supported": ["code"],
                    "code_challenge_methods_supported": ["S256"],
                    "client_id_metadata_document_supported": true,
                })
                .to_string(),
            )
        })
    }))
    .await;

    let provider = with_url(metadata_url);
    let result = rust_mcp_remote::auth::auth(&provider, &options(&base)).await;
    assert_eq!(result, Ok(AuthResult::Redirect));
    {
        let store = provider.store();
        assert_eq!(
            store.client_information,
            Some(json!({"client_id": metadata_url, "issuer": base}))
        );
        let pairs: Vec<(String, String)> = store
            .redirected_to
            .as_ref()
            .unwrap()
            .query_pairs()
            .into_owned()
            .collect();
        assert_eq!(param(&pairs, "client_id"), Some(metadata_url));
    }
    let paths: Vec<String> = drain(&mut requests).into_iter().map(|r| r.path).collect();
    assert!(!paths.contains(&"/register".to_owned()), "{paths:?}");

    // A URL that is not HTTPS with a path is refused before anything is saved.
    for bad in [
        "http://client.example/metadata.json",
        "https://client.example/",
    ] {
        let provider = with_url(bad);
        let error = rust_mcp_remote::auth::auth(&provider, &options(&base))
            .await
            .unwrap_err();
        assert_eq!(error.oauth_code(), Some("invalid_client_metadata"));
        assert_eq!(
            error.to_string(),
            format!(
                "clientMetadataUrl must be a valid HTTPS URL with a non-root pathname, got: {bad}"
            )
        );
        assert_eq!(provider.store().client_information, None);
    }
}

#[tokio::test]
async fn a_client_metadata_url_is_ignored_when_the_server_does_not_support_it() {
    let (base, mut requests) = auth_server(Arc::new(|_, _| None)).await;
    let provider = TestProvider {
        client_metadata_url: Some("https://client.example/oauth/metadata.json".to_owned()),
        ..TestProvider::new()
    };
    let result = rust_mcp_remote::auth::auth(&provider, &options(&base)).await;
    assert_eq!(result, Ok(AuthResult::Redirect));
    assert_eq!(
        provider.store().client_information.as_ref().unwrap()["client_id"],
        "registered-client"
    );
    let paths: Vec<String> = drain(&mut requests).into_iter().map(|r| r.path).collect();
    assert!(paths.contains(&"/register".to_owned()), "{paths:?}");
}

#[tokio::test]
async fn without_resource_metadata_the_server_origin_is_the_authorization_server() {
    let (base, mut requests) = auth_server(Arc::new(|_, request| {
        request
            .path
            .starts_with("/.well-known/oauth-protected-resource")
            .then(|| reply(404, &[], ""))
    }))
    .await;
    let server_url = Url::parse(&format!("{base}/mcp")).unwrap();
    let info = discover_oauth_server_info(&server_url, None, None, false)
        .await
        .unwrap();
    assert_eq!(info.authorization_server_url, format!("{base}/"));
    assert!(info.resource_metadata.is_none());
    assert_eq!(
        info.authorization_server_metadata.unwrap()["issuer"],
        json!(base)
    );
    let paths: Vec<String> = drain(&mut requests).into_iter().map(|r| r.path).collect();
    assert_eq!(
        paths,
        [
            "/.well-known/oauth-protected-resource/mcp",
            "/.well-known/oauth-protected-resource",
            "/.well-known/oauth-authorization-server",
        ]
    );
}

#[tokio::test]
async fn metadata_for_another_issuer_is_rejected() {
    let (base, _requests) = auth_server(Arc::new(|_, request| {
        (request.path == "/.well-known/oauth-authorization-server").then(|| {
            reply(
                200,
                &[JSON],
                &json!({"issuer": "https://evil.example", "authorization_endpoint": "https://evil.example/a",
                        "token_endpoint": "https://evil.example/t", "response_types_supported": ["code"]})
                .to_string(),
            )
        })
    }))
    .await;
    let error = rust_mcp_remote::auth::auth(&TestProvider::new(), &options(&base))
        .await
        .unwrap_err();
    assert_eq!(
        error,
        AuthError::IssuerMismatch {
            kind: IssuerMismatchKind::Metadata,
            expected: base.clone(),
            received: Some("https://evil.example".to_owned())
        }
    );
}

#[tokio::test]
async fn a_rejected_registration_carries_status_body_and_metadata() {
    let (base, _requests) = auth_server(Arc::new(|_, request| {
        (request.path == "/register")
            .then(|| reply(400, &[JSON], r#"{"error":"invalid_redirect_uri"}"#))
    }))
    .await;
    let error = rust_mcp_remote::auth::auth(&TestProvider::new(), &options(&base))
        .await
        .unwrap_err();
    let AuthError::RegistrationRejected {
        status,
        body,
        submitted_metadata,
    } = &error
    else {
        panic!("{error:?}");
    };
    assert_eq!(*status, 400);
    assert_eq!(body, r#"{"error":"invalid_redirect_uri"}"#);
    assert_eq!(submitted_metadata["client_name"], "test");
    assert_eq!(
        error.to_string(),
        r#"Dynamic Client Registration rejected (HTTP 400): {"error":"invalid_redirect_uri"}"#
    );
}

#[tokio::test]
async fn register_client_posts_to_the_advertised_or_default_endpoint() {
    let (base, mut requests) = auth_server(Arc::new(|_, request| {
        (request.path == "/custom-register").then(|| {
            reply(
                201,
                &[JSON],
                r#"{"client_id":"custom","redirect_uris":["http://localhost/cb"]}"#,
            )
        })
    }))
    .await;
    let client_metadata = TestProvider::new().client_metadata();

    // Without metadata the endpoint is /register on the server's origin, and the scope is added.
    let info = register_client(
        &format!("{base}/some/path"),
        None,
        &client_metadata,
        Some("mcp:tools"),
        None,
    )
    .await
    .unwrap();
    assert_eq!(info["client_id"], "registered-client");
    assert!(info.get("issuer").is_none());
    let seen = drain(&mut requests);
    assert_eq!(seen.len(), 1);
    assert_eq!(
        (seen[0].method.as_str(), seen[0].path.as_str()),
        ("POST", "/register")
    );
    assert_eq!(seen[0].header("content-type"), Some("application/json"));
    let submitted: Value = serde_json::from_str(&seen[0].body).unwrap();
    assert_eq!(submitted["scope"], "mcp:tools");
    assert_eq!(submitted["client_name"], "test");

    // The advertised registration_endpoint wins, and no scope is sent unless one is given.
    let metadata = json!({"registration_endpoint": format!("{base}/custom-register")});
    let info = register_client(&base, Some(&metadata), &client_metadata, None, None)
        .await
        .unwrap();
    assert_eq!(info["client_id"], "custom");
    let seen = drain(&mut requests);
    assert_eq!(seen[0].path, "/custom-register");
    let submitted: Value = serde_json::from_str(&seen[0].body).unwrap();
    assert!(submitted.get("scope").is_none());

    // Metadata without a usable registration_endpoint means no dynamic registration.
    for metadata in [json!({}), json!({"registration_endpoint": ""})] {
        assert_eq!(
            register_client(&base, Some(&metadata), &client_metadata, None, None).await,
            Err(AuthError::Other(
                "Incompatible auth server: does not support dynamic client registration".to_owned()
            ))
        );
    }
    assert!(drain(&mut requests).is_empty());
}

#[tokio::test]
async fn execute_token_request_picks_the_endpoint_sets_the_resource_and_authenticates_the_client() {
    let (base, mut requests) = auth_server(Arc::new(|_, request| match request.path.as_str() {
        "/custom-token" => Some(reply(
            200,
            &[JSON],
            r#"{"access_token":"at-2","token_type":"Bearer"}"#,
        )),
        "/error-in-body" => Some(reply(
            200,
            &[JSON],
            r#"{"error":"invalid_grant","error_description":"expired"}"#,
        )),
        "/rejected" => Some(reply(400, &[JSON], r#"{"error":"invalid_client"}"#)),
        _ => None,
    }))
    .await;
    let params = || {
        vec![
            ("grant_type".to_owned(), "refresh_token".to_owned()),
            ("resource".to_owned(), "https://stale.example".to_owned()),
        ]
    };

    // Without metadata the endpoint is /token on the origin; the resource replaces any given one,
    // and the secret goes in the body when the client registered client_secret_post.
    let info = json!({"client_id": "cid", "client_secret": "s3cret",
                      "token_endpoint_auth_method": "client_secret_post"});
    let tokens = execute_token_request::<TestProvider>(
        &format!("{base}/some/path"),
        TokenRequestOptions {
            client_information: Some(&info),
            resource: Some("https://api.example/mcp"),
            ..Default::default()
        },
        params(),
        None,
    )
    .await
    .unwrap();
    assert_eq!(tokens["access_token"], "at-1");
    let seen = drain(&mut requests);
    assert_eq!(seen.len(), 1);
    assert_eq!(
        (seen[0].method.as_str(), seen[0].path.as_str()),
        ("POST", "/token")
    );
    assert_eq!(
        seen[0].header("content-type"),
        Some("application/x-www-form-urlencoded")
    );
    assert_eq!(seen[0].header("accept"), Some("application/json"));
    assert_eq!(seen[0].header("authorization"), None);
    let sent = form(&seen[0].body);
    assert_eq!(param(&sent, "resource"), Some("https://api.example/mcp"));
    assert_eq!(sent.iter().filter(|(key, _)| key == "resource").count(), 1);
    assert_eq!(param(&sent, "client_id"), Some("cid"));
    assert_eq!(param(&sent, "client_secret"), Some("s3cret"));

    // The advertised token_endpoint wins, and a secret defaults to client_secret_basic.
    let metadata = json!({"token_endpoint": format!("{base}/custom-token")});
    let info = json!({"client_id": "cid", "client_secret": "s3cret"});
    let tokens = execute_token_request::<TestProvider>(
        &base,
        TokenRequestOptions {
            metadata: Some(&metadata),
            client_information: Some(&info),
            ..Default::default()
        },
        params(),
        None,
    )
    .await
    .unwrap();
    assert_eq!(tokens["access_token"], "at-2");
    let seen = drain(&mut requests);
    assert_eq!(seen[0].path, "/custom-token");
    assert_eq!(
        seen[0].header("authorization"),
        Some("Basic Y2lkOnMzY3JldA==")
    );
    let sent = form(&seen[0].body);
    assert_eq!(param(&sent, "client_secret"), None);
    assert_eq!(param(&sent, "resource"), Some("https://stale.example"));

    // An error object in a 200 body and a non-2xx status both become OAuth errors.
    for (path, code, message) in [
        ("/error-in-body", "invalid_grant", "expired"),
        ("/rejected", "invalid_client", "invalid_client"),
    ] {
        let metadata = json!({"token_endpoint": format!("{base}{path}")});
        let error = execute_token_request::<TestProvider>(
            &base,
            TokenRequestOptions {
                metadata: Some(&metadata),
                ..Default::default()
            },
            params(),
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(
            error,
            AuthError::OAuth {
                code: code.to_owned(),
                message: message.to_owned(),
                error_uri: None,
            }
        );
    }
}

#[tokio::test]
async fn fetch_token_exchanges_the_code_with_stored_client_information() {
    let (base, mut requests) = auth_server(Arc::new(|_, _| None)).await;
    let provider = TestProvider::new();

    // Without a prepared grant, an authorization code is required.
    let error = fetch_token(&provider, &base, FetchTokenOptions::default())
        .await
        .unwrap_err();
    assert_eq!(
        error,
        AuthError::Other(
            "Either provider.prepareTokenRequest() or authorizationCode is required".to_owned()
        )
    );

    // The code is exchanged with the stored verifier, redirect URL and client_id.
    provider.store().code_verifier = Some("the-verifier".to_owned());
    provider.store().client_information = Some(json!({"client_id": "cid", "issuer": base}));
    let tokens = fetch_token(
        &provider,
        &base,
        FetchTokenOptions {
            authorization_code: Some("the-code"),
            resource: Some("https://api.example/mcp"),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(tokens["access_token"], "at-1");
    let seen = drain(&mut requests);
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].path, "/token");
    let sent = form(&seen[0].body);
    assert_eq!(param(&sent, "grant_type"), Some("authorization_code"));
    assert_eq!(param(&sent, "code"), Some("the-code"));
    assert_eq!(param(&sent, "code_verifier"), Some("the-verifier"));
    assert_eq!(
        param(&sent, "redirect_uri"),
        Some("http://localhost:3334/oauth/callback")
    );
    assert_eq!(param(&sent, "resource"), Some("https://api.example/mcp"));
    assert_eq!(param(&sent, "client_id"), Some("cid"));

    // Client information stamped with another issuer is never presented.
    provider.store().client_information =
        Some(json!({"client_id": "cid", "issuer": "https://other.example"}));
    let error = fetch_token(
        &provider,
        &base,
        FetchTokenOptions {
            authorization_code: Some("the-code"),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();
    assert_eq!(
        error,
        AuthError::AuthorizationServerMismatch {
            recorded: "https://other.example".to_owned(),
            current: base.clone(),
        }
    );
    assert!(drain(&mut requests).is_empty());
}

#[tokio::test]
async fn fetch_token_refuses_an_unusable_code_exchange_unsent() {
    let (base, mut requests) = auth_server(Arc::new(|_, _| None)).await;
    let provider = TestProvider::new();
    provider.store().code_verifier = Some("the-verifier".to_owned());
    let with_code = |code| FetchTokenOptions {
        authorization_code: Some(code),
        ..Default::default()
    };

    // An empty code counts as no code at all.
    assert_eq!(
        fetch_token(&provider, &base, with_code(""))
            .await
            .unwrap_err(),
        AuthError::Other(
            "Either provider.prepareTokenRequest() or authorizationCode is required".to_owned()
        )
    );

    // The authorization_code grant needs a redirect URL.
    let no_redirect = TestProvider {
        redirect_url: Some(None),
        ..TestProvider::new()
    };
    assert_eq!(
        fetch_token(&no_redirect, &base, with_code("the-code"))
            .await
            .unwrap_err(),
        AuthError::Other("redirectUrl is required for authorization_code flow".to_owned())
    );

    // A foreign iss is refused when the server promises the parameter.
    let metadata = json!({
        "issuer": base,
        "authorization_response_iss_parameter_supported": true,
    });
    assert_eq!(
        fetch_token(
            &provider,
            &base,
            FetchTokenOptions {
                metadata: Some(&metadata),
                iss: Some("https://evil.example"),
                ..with_code("the-code")
            },
        )
        .await
        .unwrap_err(),
        AuthError::IssuerMismatch {
            kind: IssuerMismatchKind::AuthorizationResponse,
            expected: base.clone(),
            received: Some("https://evil.example".to_owned()),
        }
    );
    assert!(drain(&mut requests).is_empty());
}

#[tokio::test]
async fn fetch_token_sends_the_grant_the_provider_prepares() {
    let (base, mut requests) = auth_server(Arc::new(|_, _| None)).await;
    let provider = TestProvider {
        prepared_grant: Some(vec![
            ("grant_type".to_owned(), "client_credentials".to_owned()),
            ("scope".to_owned(), "read".to_owned()),
        ]),
        client_metadata: Some(json!({
            "redirect_uris": ["http://localhost:3334/oauth/callback"],
            "token_endpoint_auth_method": "none",
            "scope": "read",
        })),
        ..TestProvider::new()
    };
    provider.store().client_information = Some(json!({"client_id": "cid", "issuer": base}));

    // No authorization code is needed, and the scope comes from the client metadata.
    let tokens = fetch_token(&provider, &base, FetchTokenOptions::default())
        .await
        .unwrap();
    assert_eq!(tokens["access_token"], "at-1");
    assert_eq!(
        provider.store().prepared_for_scope,
        Some(Some("read".to_owned()))
    );
    let seen = drain(&mut requests);
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].path, "/token");
    let sent = form(&seen[0].body);
    assert_eq!(param(&sent, "grant_type"), Some("client_credentials"));
    assert_eq!(param(&sent, "scope"), Some("read"));
    assert_eq!(param(&sent, "client_id"), Some("cid"));
    assert_eq!(param(&sent, "code"), None);
    assert_eq!(param(&sent, "redirect_uri"), None);

    // An explicit scope wins over the client metadata.
    fetch_token(
        &provider,
        &base,
        FetchTokenOptions {
            scope: Some("write"),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(
        provider.store().prepared_for_scope,
        Some(Some("write".to_owned()))
    );
}

#[tokio::test]
async fn exchange_authorization_checks_iss_before_sending_the_code() {
    let (base, mut requests) = auth_server(Arc::new(|_, _| None)).await;
    let metadata = json!({
        "issuer": base,
        "token_endpoint": format!("{base}/token"),
        "authorization_response_iss_parameter_supported": true,
    });
    let exchange = |iss: Option<String>| {
        let (base, metadata) = (&base, &metadata);
        async move {
            exchange_authorization::<TestProvider>(
                base,
                TokenRequestOptions {
                    metadata: Some(metadata),
                    client_information: Some(&json!({"client_id": "cid"})),
                    ..Default::default()
                },
                "the-code",
                iss.as_deref(),
                "the-verifier",
                "http://localhost:3334/oauth/callback",
                None,
            )
            .await
        }
    };
    let mismatch = |received: Option<&str>| AuthError::IssuerMismatch {
        kind: IssuerMismatchKind::AuthorizationResponse,
        expected: base.clone(),
        received: received.map(str::to_owned),
    };

    // A missing iss, when the server promises one, and a foreign iss are refused unsent.
    assert_eq!(exchange(None).await.unwrap_err(), mismatch(None));
    assert_eq!(
        exchange(Some("https://evil.example".to_owned()))
            .await
            .unwrap_err(),
        mismatch(Some("https://evil.example"))
    );
    assert!(drain(&mut requests).is_empty());

    // The matching iss lets the authorization_code grant through.
    let tokens = exchange(Some(base.clone())).await.unwrap();
    assert_eq!(tokens["access_token"], "at-1");
    let seen = drain(&mut requests);
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].path, "/token");
    let sent = form(&seen[0].body);
    assert_eq!(param(&sent, "grant_type"), Some("authorization_code"));
    assert_eq!(param(&sent, "code"), Some("the-code"));
    assert_eq!(param(&sent, "code_verifier"), Some("the-verifier"));
    assert_eq!(
        param(&sent, "redirect_uri"),
        Some("http://localhost:3334/oauth/callback")
    );
    assert_eq!(param(&sent, "client_id"), Some("cid"));
}

#[tokio::test]
async fn token_requests_refuse_plain_http_off_loopback() {
    let metadata = json!({"token_endpoint": "http://as.example/token"});
    let error = refresh_authorization::<TestProvider>(
        "http://as.example",
        TokenRequestOptions {
            metadata: Some(&metadata),
            ..Default::default()
        },
        "rt",
        None,
    )
    .await
    .unwrap_err();
    assert_eq!(
        error,
        AuthError::InsecureTokenEndpoint("http://as.example/token".to_owned())
    );
}

#[tokio::test]
async fn select_resource_url_takes_the_metadata_resource_only_when_it_covers_the_server() {
    let provider = TestProvider::new();
    let server = Url::parse("https://api.example/mcp/v1#frag").unwrap();
    let select = |metadata: Option<Value>| {
        let (server, provider) = (&server, &provider);
        async move {
            select_resource_url(server, provider, metadata.as_ref())
                .await
                .map(|resource| resource.map(String::from))
        }
    };

    assert_eq!(select(None).await.unwrap(), None);
    assert_eq!(
        select(Some(json!({"resource": "https://api.example/mcp"})))
            .await
            .unwrap()
            .as_deref(),
        Some("https://api.example/mcp")
    );
    assert_eq!(
        select(Some(json!({"resource": "https://api.example/"})))
            .await
            .unwrap()
            .as_deref(),
        Some("https://api.example/")
    );

    let error = select(Some(json!({"resource": "https://api.example/other"})))
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.contains(
            "https://api.example/other does not match expected https://api.example/mcp/v1"
        ),
        "{error}"
    );
    let error = select(Some(json!({"resource": "https://other.example/mcp"})))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("does not match"), "{error}");
    let error = select(Some(json!({}))).await.unwrap_err();
    assert_eq!(error.to_string(), "Invalid URL");
}

#[tokio::test]
async fn select_resource_url_defers_to_the_providers_validate_resource_url() {
    let server = Url::parse("https://api.example/mcp/v1#frag").unwrap();
    let chosen = Url::parse("https://elsewhere.example/resource").unwrap();
    let provider = TestProvider {
        resource_override: Some(Some(chosen.clone())),
        ..TestProvider::new()
    };

    // The provider's answer wins, even for a resource the default check would reject.
    let metadata = json!({"resource": "https://other.example/mcp"});
    let resource = select_resource_url(&server, &provider, Some(&metadata))
        .await
        .unwrap();
    assert_eq!(resource, Some(chosen));
    assert_eq!(
        provider.store().validated_resource,
        Some((
            "https://api.example/mcp/v1".to_owned(),
            Some("https://other.example/mcp".to_owned())
        ))
    );

    // It is asked even without metadata, and may decline to pick a resource.
    let provider = TestProvider {
        resource_override: Some(None),
        ..TestProvider::new()
    };
    assert_eq!(
        select_resource_url(&server, &provider, Some(&json!({})))
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        provider.store().validated_resource,
        Some(("https://api.example/mcp/v1".to_owned(), None))
    );
    provider.store().validated_resource = None;
    select_resource_url(&server, &provider, None).await.unwrap();
    assert_eq!(
        provider.store().validated_resource,
        Some(("https://api.example/mcp/v1".to_owned(), None))
    );
}

#[tokio::test]
async fn resolve_authorization_callback_params_checks_iss_before_surfacing_an_error() {
    let params = |pairs: &[(&str, &str)]| -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect()
    };
    let unreachable = Url::parse("http://127.0.0.1:9/mcp").unwrap();
    let provider = TestProvider::new();

    // A code is returned as is, with no discovery.
    assert_eq!(
        resolve_authorization_callback_params(
            &params(&[("code", "c-1"), ("iss", "https://as.example")]),
            &provider,
            &unreachable,
            None,
        )
        .await
        .unwrap(),
        ("c-1".to_owned(), Some("https://as.example".to_owned()))
    );

    provider.store().discovery_state = Some(DiscoveryState {
        authorization_server_url: "https://as.example".to_owned(),
        resource_metadata_url: None,
        resource_metadata: None,
        authorization_server_metadata: Some(json!({
            "issuer": "https://as.example",
            "authorization_response_iss_parameter_supported": true,
        })),
    });
    let resolve = |pairs: Vec<(String, String)>| {
        let (provider, unreachable) = (&provider, &unreachable);
        async move {
            resolve_authorization_callback_params(&pairs, provider, unreachable, None)
                .await
                .unwrap_err()
        }
    };
    let mismatch = |received: Option<&str>| AuthError::IssuerMismatch {
        kind: IssuerMismatchKind::AuthorizationResponse,
        expected: "https://as.example".to_owned(),
        received: received.map(str::to_owned),
    };

    assert_eq!(
        resolve(params(&[("code", ""), ("error", "access_denied")])).await,
        mismatch(None)
    );
    assert_eq!(
        resolve(params(&[
            ("error", "access_denied"),
            ("iss", "https://evil.example")
        ]))
        .await,
        mismatch(Some("https://evil.example"))
    );
    assert_eq!(
        resolve(params(&[
            ("error", "access_denied"),
            ("error_description", "User said no"),
            ("error_uri", "https://as.example/help"),
            ("iss", "https://as.example"),
        ]))
        .await,
        AuthError::OAuth {
            code: "access_denied".to_owned(),
            message: "User said no".to_owned(),
            error_uri: Some("https://as.example/help".to_owned()),
        }
    );
    assert_eq!(
        resolve(params(&[
            ("error", "access_denied"),
            ("iss", "https://as.example")
        ]))
        .await,
        AuthError::OAuth {
            code: "access_denied".to_owned(),
            message: "access_denied".to_owned(),
            error_uri: None,
        }
    );
    assert_eq!(
        resolve(params(&[("iss", "https://as.example")])).await,
        AuthError::Unauthorized(
            "Authorization callback contained neither `code` nor `error`".to_owned()
        )
    );
}

#[tokio::test]
async fn resolve_authorization_callback_params_discovers_metadata_when_none_is_recorded() {
    let error_params = vec![("error".to_owned(), "server_error".to_owned())];
    let provider = TestProvider::new();

    // Discovered metadata does not advertise the iss parameter, so a missing iss passes.
    let (base, _requests) = auth_server(Arc::new(|_, _| None)).await;
    let server = Url::parse(&format!("{base}/mcp")).unwrap();
    let error = resolve_authorization_callback_params(&error_params, &provider, &server, None)
        .await
        .unwrap_err();
    assert_eq!(error, AuthError::oauth("server_error", "server_error"));

    let (base, _requests) = auth_server(Arc::new(|_, _| Some(reply(404, &[], "not found")))).await;
    let server = Url::parse(&format!("{base}/mcp")).unwrap();
    let error = resolve_authorization_callback_params(&error_params, &provider, &server, None)
        .await
        .unwrap_err();
    assert_eq!(
        error,
        AuthError::Unauthorized(
            "Authorization callback failed and the issuer could not be verified".to_owned()
        )
    );
}

#[test]
fn resolve_client_metadata_fills_only_missing_grant_types_and_application_type() {
    // Interactive: the SDK defaults, with a loopback redirect making it native.
    let metadata = resolve_client_metadata(&TestProvider::new());
    assert_eq!(
        metadata["grant_types"],
        json!(["authorization_code", "refresh_token"])
    );
    assert_eq!(metadata["application_type"], "native");

    // Without a redirect URL a null grant_types is dropped, and https redirects are web.
    let provider = TestProvider {
        redirect_url: Some(None),
        client_metadata: Some(json!({
            "redirect_uris": ["https://app.example/cb"],
            "grant_types": null,
            "application_type": null,
        })),
        ..TestProvider::new()
    };
    let metadata = resolve_client_metadata(&provider);
    assert!(metadata.get("grant_types").is_none());
    assert_eq!(metadata["application_type"], "web");

    // Values the provider sets are kept as they are.
    let provider = TestProvider {
        redirect_url: Some(None),
        client_metadata: Some(json!({
            "redirect_uris": ["http://localhost:1/cb"],
            "grant_types": ["client_credentials"],
            "application_type": "web",
        })),
        ..TestProvider::new()
    };
    let metadata = resolve_client_metadata(&provider);
    assert_eq!(metadata["grant_types"], json!(["client_credentials"]));
    assert_eq!(metadata["application_type"], "web");
}

/// Serves `{base}/tenant` discovery: `status_for` picks each well-known path's status, and a
/// 200 returns OIDC metadata whose issuer is `issuer(base)`.
async fn tenant_discovery(
    status_for: fn(&str) -> u16,
    issuer: fn(&str) -> String,
) -> (String, UnboundedReceiver<RecordedRequest>) {
    let base = Arc::new(OnceLock::<String>::new());
    let handler_base = Arc::clone(&base);
    let (url, requests) = serve(Arc::new(move |request: &RecordedRequest| {
        let base = handler_base.get().cloned().unwrap_or_default();
        let status = status_for(&request.path);
        if status != 200 {
            return reply(status, &[], "");
        }
        reply(
            200,
            &[JSON],
            &json!({
                "issuer": issuer(&base),
                "authorization_endpoint": format!("{base}/authorize"),
                "token_endpoint": format!("{base}/token"),
                "jwks_uri": format!("{base}/jwks"),
                "response_types_supported": ["code"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"],
            })
            .to_string(),
        )
    }))
    .await;
    base.set(url.clone()).unwrap();
    (url, requests)
}

#[tokio::test]
async fn discover_authorization_server_metadata_walks_the_well_known_urls() {
    // 4xx and 502 move on to the next candidate; the path-suffixed OIDC URL answers.
    let (base, mut requests) = tenant_discovery(
        |path| match path {
            "/.well-known/oauth-authorization-server/tenant" => 404,
            "/.well-known/openid-configuration/tenant" => 502,
            _ => 200,
        },
        |base| format!("{base}/tenant"),
    )
    .await;
    let metadata = discover_authorization_server_metadata(
        &format!("{base}/tenant"),
        None,
        Some("2025-06-18"),
        false,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(metadata["issuer"], json!(format!("{base}/tenant")));
    let seen = drain(&mut requests);
    let paths: Vec<&str> = seen.iter().map(|r| r.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            "/.well-known/oauth-authorization-server/tenant",
            "/.well-known/openid-configuration/tenant",
            "/tenant/.well-known/openid-configuration",
        ]
    );
    assert!(
        seen.iter()
            .all(|r| r.header("mcp-protocol-version") == Some("2025-06-18"))
    );

    // Every candidate missing is no metadata, not an error.
    let (base, _requests) = tenant_discovery(|_| 404, |base| base.to_owned()).await;
    let result =
        discover_authorization_server_metadata(&format!("{base}/tenant"), None, None, false).await;
    assert_eq!(result, Ok(None));

    // Any other 5xx stops the walk.
    let (base, mut requests) = tenant_discovery(|_| 500, |base| base.to_owned()).await;
    let error =
        discover_authorization_server_metadata(&format!("{base}/tenant"), None, None, false)
            .await
            .unwrap_err();
    assert!(
        matches!(&error, AuthError::Other(message) if message.starts_with("HTTP 500 trying to load OAuth metadata")),
        "{error:?}"
    );
    assert_eq!(drain(&mut requests).len(), 1);

    // A foreign issuer is refused unless validation is skipped.
    let (base, _requests) = tenant_discovery(|_| 200, |_| "https://evil.example".to_owned()).await;
    let expected = format!("{base}/tenant");
    assert_eq!(
        discover_authorization_server_metadata(&expected, None, None, false).await,
        Err(AuthError::IssuerMismatch {
            kind: IssuerMismatchKind::Metadata,
            expected: expected.clone(),
            received: Some("https://evil.example".to_owned()),
        })
    );
    let metadata = discover_authorization_server_metadata(&expected, None, None, true)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(metadata["issuer"], "https://evil.example");
}

/// Serves protected resource metadata for `{base}/mcp`: `status_for` picks each path's status.
async fn resource_discovery(
    status_for: fn(&str) -> u16,
) -> (String, UnboundedReceiver<RecordedRequest>) {
    let base = Arc::new(OnceLock::<String>::new());
    let handler_base = Arc::clone(&base);
    let (url, requests) = serve(Arc::new(move |request: &RecordedRequest| {
        let base = handler_base.get().cloned().unwrap_or_default();
        let status = status_for(&request.path);
        if status != 200 {
            return reply(status, &[], "");
        }
        reply(
            200,
            &[JSON],
            &json!({ "resource": format!("{base}/mcp"), "authorization_servers": [base] })
                .to_string(),
        )
    }))
    .await;
    base.set(url.clone()).unwrap();
    (url, requests)
}

#[tokio::test]
async fn discover_oauth_protected_resource_metadata_falls_back_to_the_root_and_names_failures() {
    // A 4xx on the path-suffixed URL (query kept) falls back to the root well-known URL.
    let (base, mut requests) = resource_discovery(|path| {
        if path == "/.well-known/oauth-protected-resource" {
            200
        } else {
            404
        }
    })
    .await;
    let server = Url::parse(&format!("{base}/mcp?tenant=a")).unwrap();
    let metadata =
        discover_oauth_protected_resource_metadata(&server, None, Some("2025-06-18"), None)
            .await
            .unwrap();
    assert_eq!(metadata["resource"], json!(format!("{base}/mcp")));
    let seen = drain(&mut requests);
    let paths: Vec<&str> = seen.iter().map(|r| r.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            "/.well-known/oauth-protected-resource/mcp?tenant=a",
            "/.well-known/oauth-protected-resource",
        ]
    );
    assert!(
        seen.iter()
            .all(|r| r.header("mcp-protocol-version") == Some("2025-06-18"))
    );

    // An explicit metadata URL is the only one tried, and a 404 there means no support.
    let explicit = Url::parse(&format!("{base}/custom")).unwrap();
    assert_eq!(
        discover_oauth_protected_resource_metadata(&server, Some(&explicit), None, None).await,
        Err(AuthError::Other(
            "Resource server does not implement OAuth 2.0 Protected Resource Metadata.".to_owned()
        ))
    );
    assert_eq!(drain(&mut requests).len(), 1);

    // A 5xx other than 502 does not fall back and names the status.
    let (base, mut requests) = resource_discovery(|_| 500).await;
    let server = Url::parse(&format!("{base}/mcp")).unwrap();
    assert_eq!(
        discover_oauth_protected_resource_metadata(&server, None, None, None).await,
        Err(AuthError::Other(
            "HTTP 500 trying to load well-known OAuth protected resource metadata.".to_owned()
        ))
    );
    assert_eq!(drain(&mut requests).len(), 1);
}

#[tokio::test]
async fn fetch_within_origin_follows_only_redirects_that_keep_method_origin_and_userinfo() {
    let (other, _) = serve(Arc::new(|_: &RecordedRequest| reply(200, &[], "other"))).await;
    let other = Arc::new(other);
    let handler_other = Arc::clone(&other);
    let own = Arc::new(OnceLock::<String>::new());
    let handler_own = Arc::clone(&own);
    let (base, mut requests) = serve(Arc::new(move |request: &RecordedRequest| {
        let cross = format!("{handler_other}/x");
        let own = handler_own.get().cloned().unwrap_or_default();
        let userinfo = own.replacen("http://", "http://user:pw@", 1) + "/final";
        match request.path.as_str() {
            "/same" => reply(302, &[("location", "/final")], ""),
            "/keep" => reply(307, &[("location", "/final")], ""),
            "/cross" => reply(302, &[("location", cross.as_str())], ""),
            "/userinfo" => reply(302, &[("location", userinfo.as_str())], ""),
            "/loop" => reply(302, &[("location", "/loop")], ""),
            _ => reply(200, &[], "final"),
        }
    }))
    .await;
    own.set(base.clone()).unwrap();
    let fetch = |path: &str, method: Method| {
        let url = Url::parse(&format!("{base}{path}")).unwrap();
        async move {
            fetch_within_origin(
                None,
                method,
                &url,
                &[("x-test".to_owned(), "1".to_owned())],
                None,
            )
            .await
            .unwrap()
        }
    };

    // A same-origin GET redirect is followed and keeps the headers.
    let response = fetch("/same", Method::GET).await;
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "final");
    let seen = drain(&mut requests);
    assert_eq!(
        seen.iter().map(|r| r.path.as_str()).collect::<Vec<_>>(),
        ["/same", "/final"]
    );
    assert!(seen.iter().all(|r| r.header("x-test") == Some("1")));

    // A POST follows a 307 (method kept) but not a 302.
    let response = fetch("/keep", Method::POST).await;
    assert_eq!(response.status(), 200);
    let seen = drain(&mut requests);
    assert_eq!(
        seen.iter().map(|r| r.method.as_str()).collect::<Vec<_>>(),
        ["POST", "POST"]
    );
    assert_eq!(fetch("/same", Method::POST).await.status(), 302);
    assert_eq!(drain(&mut requests).len(), 1);

    // Redirects to another origin or with new userinfo come back unfollowed.
    assert_eq!(fetch("/cross", Method::GET).await.status(), 302);
    assert_eq!(fetch("/userinfo", Method::GET).await.status(), 302);
    assert_eq!(drain(&mut requests).len(), 2);

    // At most five redirects are followed; the sixth comes back as is.
    assert_eq!(fetch("/loop", Method::GET).await.status(), 302);
    assert_eq!(drain(&mut requests).len(), 6);
}

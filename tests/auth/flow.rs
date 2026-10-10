use std::sync::{Arc, Mutex, OnceLock};

use rust_mcp_remote::auth::{
    AuthError, AuthOptions, AuthResult, DiscoveryState, IssuerMismatchKind, OAuthClientProvider,
    TokenRequestOptions, discover_oauth_server_info, refresh_authorization,
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
}

struct TestProvider {
    store: Mutex<Store>,
    persist_discovery_state: bool,
}

impl TestProvider {
    fn new() -> Self {
        Self {
            store: Mutex::new(Store::default()),
            persist_discovery_state: true,
        }
    }

    fn store(&self) -> std::sync::MutexGuard<'_, Store> {
        self.store.lock().unwrap()
    }
}

impl OAuthClientProvider for TestProvider {
    fn redirect_url(&self) -> Option<String> {
        Some("http://localhost:3334/oauth/callback".to_owned())
    }

    fn client_metadata(&self) -> Value {
        json!({
            "redirect_uris": ["http://localhost:3334/oauth/callback"],
            "client_name": "test",
            "token_endpoint_auth_method": "none",
        })
    }

    async fn state(&self) -> Result<Option<String>, AuthError> {
        Ok(Some("the-state".to_owned()))
    }

    async fn client_information(&self, _issuer: &str) -> Option<Value> {
        self.store().client_information.clone()
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
    assert!(store.redirected_to.is_some());
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

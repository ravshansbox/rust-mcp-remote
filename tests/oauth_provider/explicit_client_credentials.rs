//! A port of explicit-client-credentials.test.ts: the client_credentials grant against an
//! explicit token endpoint, driven through the Client, the streamable HTTP transport and the
//! real provider, with an MCP server whose discovery URLs all redirect to an enterprise login.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use rust_mcp_remote::auth::OAuthClientProvider;
use rust_mcp_remote::client::Client;
use rust_mcp_remote::connect::RemoteTransport;
use rust_mcp_remote::mcp_auth_config::{read_json_file, write_json_file};
use rust_mcp_remote::node_oauth_client_provider::{NodeOAuthClientProvider, OAuthProviderOptions};
use rust_mcp_remote::oauth_provider::OAuthProvider;
use rust_mcp_remote::streamable_http::{
    StreamableHttpClientTransport, StreamableHttpOptions, fetch_with_headers,
};
use serde_json::{Value, json};
use url::Url;

use crate::test_server::{RecordedRequest, Reply, reply, serve};
use crate::use_temporary_config_dir;

const JSON: (&str, &str) = ("content-type", "application/json");
const TOKEN_PATH: &str = "/oauth2/v1/token";

static OPENED: Mutex<Vec<String>> = Mutex::new(Vec::new());

fn record_opened(url: &str) -> bool {
    OPENED.lock().unwrap().push(url.to_owned());
    true
}

fn unique_hash() -> String {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    format!(
        "explicit-client-credentials-{}",
        COUNTER.fetch_add(1, Ordering::SeqCst)
    )
}

fn now_ms() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as f64
}

fn tool() -> Value {
    json!({"name": "mcp_search", "description": "Search records", "inputSchema": {"type": "object"}})
}

#[derive(Debug, Clone)]
struct TokenRequest {
    headers: Vec<(String, String)>,
    params: Vec<(String, String)>,
}

impl TokenRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    fn param(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

#[derive(Debug, Clone, PartialEq)]
struct McpRequest {
    method: String,
    bearer: Option<String>,
}

/// The TestNetwork: the token endpoint, the MCP server, and a discovery redirect for every
/// other URL.
#[derive(Default)]
struct NetworkState {
    token_requests: Vec<TokenRequest>,
    mcp_requests: Vec<McpRequest>,
    discovery_requests: Vec<String>,
    accepted_token: String,
    challenge_metadata_url: Option<String>,
    challenge_scope: Option<String>,
    reject_all_tokens: bool,
    token_failure: bool,
    token_unavailable: bool,
}

struct Network {
    base: String,
    state: Arc<Mutex<NetworkState>>,
}

impl Network {
    async fn start() -> Network {
        let state = Arc::new(Mutex::new(NetworkState {
            accepted_token: "issued-1".to_owned(),
            ..Default::default()
        }));
        let handler_state = Arc::clone(&state);
        let base = Arc::new(OnceLock::<String>::new());
        let handler_base = Arc::clone(&base);
        let (url, _requests) = serve(Arc::new(move |request: &RecordedRequest| {
            let base = handler_base.get().cloned().unwrap_or_default();
            handle(&mut handler_state.lock().unwrap(), &base, request)
        }))
        .await;
        base.set(url.clone()).unwrap();
        Network { base: url, state }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, NetworkState> {
        self.state.lock().unwrap()
    }

    fn server_url(&self) -> String {
        format!("{}/mcp", self.base)
    }

    fn token_endpoint(&self) -> String {
        format!("{}{TOKEN_PATH}", self.base)
    }

    fn token_requests(&self) -> Vec<TokenRequest> {
        self.state().token_requests.clone()
    }

    fn bearers_for(&self, method: &str) -> Vec<Option<String>> {
        self.state()
            .mcp_requests
            .iter()
            .filter(|request| request.method == method)
            .map(|request| request.bearer.clone())
            .collect()
    }

    fn assert_no_discovery(&self) {
        assert_eq!(self.state().discovery_requests, Vec::<String>::new());
    }
}

fn json_reply(status: u16, body: Value) -> Reply {
    reply(status, &[JSON], &body.to_string())
}

fn handle(state: &mut NetworkState, base: &str, request: &RecordedRequest) -> Reply {
    let path = request.path.split('?').next().unwrap_or("");
    if path == TOKEN_PATH {
        state.token_requests.push(TokenRequest {
            headers: request.headers.clone(),
            params: url::form_urlencoded::parse(request.body.as_bytes())
                .into_owned()
                .collect(),
        });
        if state.token_failure {
            return json_reply(
                400,
                json!({"error": "invalid_client", "error_description": "Client credentials rejected"}),
            );
        }
        if state.token_unavailable {
            return json_reply(
                503,
                json!({"error": "temporarily_unavailable", "error_description": "Token endpoint unavailable"}),
            );
        }
        let access_token = format!("issued-{}", state.token_requests.len());
        state.accepted_token = access_token.clone();
        return json_reply(
            200,
            json!({"access_token": access_token, "token_type": "Bearer", "expires_in": 3600}),
        );
    }
    if path != "/mcp" {
        state.discovery_requests.push(request.path.clone());
        if path == "/login" {
            return reply(
                200,
                &[("content-type", "text/html")],
                "<html>Enterprise sign-in</html>",
            );
        }
        let login = format!("{base}/login");
        return reply(302, &[("location", login.as_str())], "");
    }
    if request.method == "GET" {
        return reply(405, &[], "");
    }
    let message: Value = serde_json::from_str(&request.body).unwrap();
    let bearer = request.header("authorization").map(str::to_owned);
    state.mcp_requests.push(McpRequest {
        method: message["method"].as_str().unwrap_or("").to_owned(),
        bearer: bearer.clone(),
    });
    if state.reject_all_tokens || bearer != Some(format!("Bearer {}", state.accepted_token)) {
        let mut challenge = vec![r#"realm="MCP""#.to_owned()];
        if let Some(url) = &state.challenge_metadata_url {
            challenge.push(format!(r#"resource_metadata="{url}""#));
        }
        if let Some(scope) = &state.challenge_scope {
            challenge.push(format!(r#"scope="{scope}""#));
        }
        let header = format!("Bearer {}", challenge.join(", "));
        return reply(
            401,
            &[("www-authenticate", header.as_str())],
            "Token required",
        );
    }
    let Some(id) = message.get("id") else {
        return reply(202, &[], "");
    };
    let result = if message["method"] == "initialize" {
        json!({"protocolVersion": "2025-03-26", "capabilities": {"tools": {}},
            "serverInfo": {"name": "mcp-simulator", "version": "1"}})
    } else {
        json!({"tools": [tool()]})
    };
    json_reply(200, json!({"jsonrpc": "2.0", "id": id, "result": result}))
}

fn provider_with(
    network: &Network,
    hash: &str,
    options: OAuthProviderOptions,
    fetch_headers: &[(String, String)],
) -> Arc<OAuthProvider> {
    use_temporary_config_dir();
    let provider = NodeOAuthClientProvider::new(OAuthProviderOptions {
        server_url: network.server_url(),
        token_endpoint: Some(network.token_endpoint()),
        server_url_hash: hash.to_owned(),
        host: "localhost".to_owned(),
        callback_port: 0,
        use_client_credentials: Some(true),
        static_oauth_client_info: options.static_oauth_client_info.clone().or_else(|| {
            Some(json!({"client_id": "machine-client", "client_secret": "test-secret", "redirect_uris": []}))
        }),
        ..options
    })
    .unwrap();
    Arc::new(
        OAuthProvider::new(provider, fetch_with_headers(None, fetch_headers))
            .with_browser_opener(record_opened),
    )
}

fn provider(network: &Network, hash: &str) -> Arc<OAuthProvider> {
    provider_with(network, hash, OAuthProviderOptions::default(), &[])
}

async fn connect_with(
    network: &Network,
    provider: &Arc<OAuthProvider>,
    headers: &[(String, String)],
) -> Result<Client, String> {
    let (transport, events) = StreamableHttpClientTransport::new(
        Url::parse(&network.server_url()).unwrap(),
        StreamableHttpOptions {
            oauth: Some(Arc::new(Arc::clone(provider))),
            headers: headers.to_vec(),
            ..Default::default()
        },
    );
    transport.start().unwrap();
    let connecting = Client::connect(
        "explicit-auth-regression",
        "1",
        RemoteTransport::Http(transport),
        events,
    );
    match tokio::time::timeout(Duration::from_secs(2), connecting).await {
        Ok(result) => result.map_err(|error| error.message),
        Err(_) => Err("connect timed out".to_owned()),
    }
}

async fn connect(network: &Network, provider: &Arc<OAuthProvider>) -> Result<Client, String> {
    connect_with(network, provider, &[]).await
}

async fn list_tools(client: &Client) -> Result<Value, String> {
    client
        .request_with_timeout("tools/list", None, Duration::from_secs(5))
        .await
        .map(|result| result["tools"].clone())
        .map_err(|error| error.message)
}

fn expire_cached_token(hash: &str, expires_at: f64) {
    let mut cached: Value = read_json_file(hash, "tokens.json").unwrap();
    cached["expires_at"] = json!(expires_at);
    write_json_file(hash, "tokens.json", &cached).unwrap();
}

fn assert_no_browser(network: &Network) {
    assert!(
        !OPENED
            .lock()
            .unwrap()
            .iter()
            .any(|url| url.contains(&network.base)),
        "the browser must not be opened"
    );
}

fn bearer(token: &str) -> Option<String> {
    Some(format!("Bearer {token}"))
}

#[tokio::test]
async fn initializes_and_lists_tools_from_a_cold_cache_without_discovery_or_browser() {
    let network = Network::start().await;
    let hash = unique_hash();
    let client = connect(&network, &provider(&network, &hash)).await.unwrap();

    assert_eq!(list_tools(&client).await.unwrap(), json!([tool()]));
    assert_eq!(network.token_requests().len(), 1);
    network.assert_no_discovery();
    assert_no_browser(&network);
    assert_eq!(
        network.bearers_for("initialize"),
        [None, bearer("issued-1")]
    );
    let cached: Value = read_json_file(&hash, "tokens.json").unwrap();
    assert_eq!(cached["access_token"], "issued-1");
    assert!(cached["expires_at"].as_f64().unwrap() > now_ms());
    assert!(cached.get("refresh_token").is_none());
    client.close();
}

#[tokio::test]
async fn replaces_a_rejected_unexpired_cached_token_and_retries_initialize() {
    let network = Network::start().await;
    let hash = unique_hash();
    use_temporary_config_dir();
    write_json_file(
        &hash,
        "tokens.json",
        &json!({"access_token": "stale-token", "token_type": "Bearer", "expires_in": 3600,
            "expires_at": now_ms() + 3_600_000.0}),
    )
    .unwrap();

    let client = connect(&network, &provider(&network, &hash)).await.unwrap();

    assert_eq!(list_tools(&client).await.unwrap(), json!([tool()]));
    assert_eq!(network.token_requests().len(), 1);
    assert_eq!(
        network.bearers_for("initialize"),
        [bearer("stale-token"), bearer("issued-1")]
    );
    network.assert_no_discovery();
    client.close();
}

#[tokio::test]
async fn reacquires_a_token_and_retries_tools_list_after_authorization_expires_on_the_server() {
    let network = Network::start().await;
    let hash = unique_hash();
    let client = connect(&network, &provider(&network, &hash)).await.unwrap();
    {
        let mut state = network.state();
        state.accepted_token = "revoked".to_owned();
        state.challenge_metadata_url = Some(format!(
            "{}/different-identity/.well-known/oauth-protected-resource",
            network.base
        ));
    }

    assert_eq!(list_tools(&client).await.unwrap(), json!([tool()]));
    assert_eq!(network.token_requests().len(), 2);
    assert_eq!(
        network.bearers_for("tools/list"),
        [bearer("issued-1"), bearer("issued-2")]
    );
    network.assert_no_discovery();
    client.close();
}

#[tokio::test]
async fn renews_an_expired_token_before_tools_list_on_an_initialized_transport() {
    let network = Network::start().await;
    let hash = unique_hash();
    let client = connect(&network, &provider(&network, &hash)).await.unwrap();
    expire_cached_token(&hash, now_ms() - 1000.0);

    assert_eq!(list_tools(&client).await.unwrap(), json!([tool()]));
    assert_eq!(network.token_requests().len(), 2);
    assert_eq!(network.bearers_for("tools/list"), [bearer("issued-2")]);
    network.assert_no_discovery();
    client.close();
}

#[tokio::test]
async fn keeps_sending_a_still_accepted_token_when_renewal_inside_the_expiry_margin_fails() {
    let network = Network::start().await;
    let hash = unique_hash();
    let client = connect(&network, &provider(&network, &hash)).await.unwrap();
    expire_cached_token(&hash, now_ms() + 30_000.0);
    network.state().token_unavailable = true;

    assert_eq!(list_tools(&client).await.unwrap(), json!([tool()]));
    assert_eq!(network.token_requests().len(), 2);
    assert_eq!(network.bearers_for("tools/list"), [bearer("issued-1")]);
    network.assert_no_discovery();
    client.close();
}

#[tokio::test]
async fn reports_the_token_endpoint_failure_once_the_stored_token_is_refused() {
    let network = Network::start().await;
    let hash = unique_hash();
    let client = connect(&network, &provider(&network, &hash)).await.unwrap();
    expire_cached_token(&hash, now_ms() - 1000.0);
    {
        let mut state = network.state();
        state.accepted_token = "revoked".to_owned();
        state.token_unavailable = true;
    }

    let error = list_tools(&client).await.unwrap_err();
    assert!(
        error.contains("Token endpoint unavailable"),
        "unexpected error: {error}"
    );
    // The first token, the renewal that failed, and the single retry after the 401.
    assert_eq!(network.token_requests().len(), 3);
    network.assert_no_discovery();
    client.close();
}

#[tokio::test]
async fn renews_through_the_same_fetch_as_a_401_retry_so_both_carry_the_transport_headers() {
    let network = Network::start().await;
    let hash = unique_hash();
    let headers = vec![("X-Tenant".to_owned(), "acme".to_owned())];
    let provider = provider_with(&network, &hash, OAuthProviderOptions::default(), &headers);
    let client = connect_with(&network, &provider, &headers).await.unwrap();
    expire_cached_token(&hash, now_ms() - 1000.0);

    assert_eq!(list_tools(&client).await.unwrap(), json!([tool()]));
    assert_eq!(
        network
            .token_requests()
            .iter()
            .map(|request| request.header("x-tenant"))
            .collect::<Vec<_>>(),
        [Some("acme"), Some("acme")]
    );
    client.close();
}

#[tokio::test]
async fn renews_an_expired_cached_token_without_a_refresh_token_sharing_concurrent_renewal() {
    let network = Network::start().await;
    let hash = unique_hash();
    use_temporary_config_dir();
    write_json_file(
        &hash,
        "tokens.json",
        &json!({"access_token": "expired", "token_type": "Bearer", "expires_in": 3600,
            "expires_at": now_ms() - 1000.0}),
    )
    .unwrap();
    let provider = provider(&network, &hash);

    let (first, second, third) = tokio::join!(
        provider.tokens(None),
        provider.tokens(None),
        provider.tokens(None)
    );
    let issued: Vec<Value> = [first, second, third]
        .into_iter()
        .map(|tokens| tokens.unwrap()["access_token"].clone())
        .collect();
    assert_eq!(
        issued,
        [json!("issued-1"), json!("issued-1"), json!("issued-1")]
    );
    let token_requests = network.token_requests();
    assert_eq!(token_requests.len(), 1);
    assert_eq!(
        token_requests[0].param("grant_type"),
        Some("client_credentials")
    );

    let client = connect(&network, &provider).await.unwrap();
    assert_eq!(list_tools(&client).await.unwrap(), json!([tool()]));
    assert!(
        network
            .state()
            .mcp_requests
            .iter()
            .all(|request| request.bearer == bearer("issued-1"))
    );
    network.assert_no_discovery();
    client.close();
}

async fn auth_method_wins_over_client_info(auth_method: &str) -> TokenRequest {
    let network = Network::start().await;
    let hash = unique_hash();
    let conflicting = if auth_method == "client_secret_basic" {
        "client_secret_post"
    } else {
        "client_secret_basic"
    };
    let provider = provider_with(
        &network,
        &hash,
        OAuthProviderOptions {
            static_oauth_client_info: Some(json!({
                "client_id": "machine-client", "client_secret": "test-secret",
                "redirect_uris": [], "token_endpoint_auth_method": conflicting,
            })),
            static_oauth_client_metadata: Some(
                json!({"redirect_uris": [], "token_endpoint_auth_method": auth_method}),
            ),
            ..Default::default()
        },
        &[],
    );
    connect(&network, &provider).await.unwrap().close();

    let request = network.token_requests()[0].clone();
    assert_eq!(request.param("grant_type"), Some("client_credentials"));
    assert_eq!(request.param("scope"), None);
    // An explicit token endpoint does not advertise RFC 8707 support on the MCP server's behalf.
    assert_eq!(request.param("resource"), None);
    request
}

#[tokio::test]
async fn uses_metadata_client_secret_basic_over_a_conflicting_client_info_method() {
    let request = auth_method_wins_over_client_info("client_secret_basic").await;
    assert_eq!(
        request.header("authorization"),
        Some("Basic bWFjaGluZS1jbGllbnQ6dGVzdC1zZWNyZXQ=")
    );
    assert_eq!(request.param("client_id"), None);
    assert_eq!(request.param("client_secret"), None);
}

#[tokio::test]
async fn uses_metadata_client_secret_post_over_a_conflicting_client_info_method() {
    let request = auth_method_wins_over_client_info("client_secret_post").await;
    assert_eq!(request.header("authorization"), None);
    assert_eq!(request.param("client_id"), Some("machine-client"));
    assert_eq!(request.param("client_secret"), Some("test-secret"));
}

async fn explicit_scope_and_resource(skip_resource_parameter: bool) {
    let network = Network::start().await;
    let hash = unique_hash();
    let provider = provider_with(
        &network,
        &hash,
        OAuthProviderOptions {
            static_oauth_client_metadata: Some(json!({"redirect_uris": [], "scope": "mcp.read"})),
            authorize_resource: Some(format!("{}/api", network.base)),
            skip_resource_parameter: Some(skip_resource_parameter),
            ..Default::default()
        },
        &[],
    );
    connect(&network, &provider).await.unwrap().close();

    let request = network.token_requests()[0].clone();
    assert_eq!(request.param("scope"), Some("mcp.read"));
    let resource = format!("{}/api", network.base);
    assert_eq!(
        request.param("resource"),
        (!skip_resource_parameter).then_some(resource.as_str())
    );
    network.assert_no_discovery();
}

#[tokio::test]
async fn preserves_explicit_scope_and_sends_the_resource() {
    explicit_scope_and_resource(false).await;
}

#[tokio::test]
async fn preserves_explicit_scope_and_honors_resource_omission() {
    explicit_scope_and_resource(true).await;
}

#[tokio::test]
async fn preserves_the_configured_scope_when_a_401_challenge_requests_a_conflicting_scope() {
    let network = Network::start().await;
    let hash = unique_hash();
    network.state().challenge_scope = Some("mcp.admin".to_owned());
    let provider = provider_with(
        &network,
        &hash,
        OAuthProviderOptions {
            static_oauth_client_metadata: Some(json!({"redirect_uris": [], "scope": "mcp.read"})),
            ..Default::default()
        },
        &[],
    );
    let client = connect(&network, &provider).await.unwrap();
    {
        let mut state = network.state();
        state.accepted_token = "revoked".to_owned();
        state.challenge_scope = Some("mcp.write".to_owned());
    }

    assert_eq!(list_tools(&client).await.unwrap(), json!([tool()]));
    assert_eq!(
        network
            .token_requests()
            .iter()
            .map(|request| request.param("scope").map(str::to_owned))
            .collect::<Vec<_>>(),
        [Some("mcp.read".to_owned()), Some("mcp.read".to_owned())]
    );
    network.assert_no_discovery();
    client.close();
}

#[tokio::test]
async fn retains_a_challenge_scope_across_expiry_and_restart_when_the_token_response_omits_scope() {
    let network = Network::start().await;
    let hash = unique_hash();
    network.state().challenge_scope = Some("mcp.read".to_owned());
    let client = connect(&network, &provider(&network, &hash)).await.unwrap();
    let cached: Value = read_json_file(&hash, "tokens.json").unwrap();
    assert!(cached.get("scope").is_none());
    assert_eq!(cached["requested_scope"], "mcp.read");
    expire_cached_token(&hash, now_ms() - 1000.0);

    assert_eq!(list_tools(&client).await.unwrap(), json!([tool()]));
    client.close();
    expire_cached_token(&hash, now_ms() - 1000.0);
    network.state().challenge_scope = None;
    let restarted = connect(&network, &provider(&network, &hash)).await.unwrap();

    assert_eq!(list_tools(&restarted).await.unwrap(), json!([tool()]));
    assert_eq!(
        network
            .token_requests()
            .iter()
            .map(|request| request.param("scope").map(str::to_owned))
            .collect::<Vec<_>>(),
        vec![Some("mcp.read".to_owned()); 3]
    );
    network.assert_no_discovery();
    restarted.close();
}

#[tokio::test]
async fn stops_after_the_freshly_acquired_token_is_rejected_instead_of_looping() {
    let network = Network::start().await;
    let hash = unique_hash();
    network.state().reject_all_tokens = true;

    let error = connect(&network, &provider(&network, &hash))
        .await
        .err()
        .unwrap();
    assert!(
        error.contains("401 after re-authentication"),
        "unexpected error: {error}"
    );
    assert_eq!(network.token_requests().len(), 1);
    assert_eq!(network.state().mcp_requests.len(), 2);
    network.assert_no_discovery();
}

#[tokio::test]
async fn reports_a_token_endpoint_rejection_without_discovery_or_browser_fallback() {
    let network = Network::start().await;
    let hash = unique_hash();
    network.state().token_failure = true;

    let error = connect(&network, &provider(&network, &hash))
        .await
        .err()
        .unwrap();
    assert!(
        error.contains("Client credentials rejected"),
        "unexpected error: {error}"
    );
    assert!(network.token_requests().len() <= 2);
    network.assert_no_discovery();
    assert_no_browser(&network);
}

#[tokio::test]
async fn reports_a_missing_client_secret_without_a_token_request_or_browser_fallback() {
    let network = Network::start().await;
    let hash = unique_hash();
    let provider = provider_with(
        &network,
        &hash,
        OAuthProviderOptions {
            static_oauth_client_info: Some(
                json!({"client_id": "machine-client", "redirect_uris": []}),
            ),
            ..Default::default()
        },
        &[],
    );

    let error = connect(&network, &provider).await.err().unwrap();
    assert!(
        error.contains("needs a client secret"),
        "unexpected error: {error}"
    );
    assert_eq!(network.token_requests().len(), 0);
    network.assert_no_discovery();
    assert_no_browser(&network);
}

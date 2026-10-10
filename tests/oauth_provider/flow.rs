use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use rust_mcp_remote::auth::{AuthOptions, AuthResult, OAuthClientProvider, auth};
use rust_mcp_remote::mcp_auth_config::{read_json_file, write_json_file};
use rust_mcp_remote::node_oauth_client_provider::{NodeOAuthClientProvider, OAuthProviderOptions};
use rust_mcp_remote::oauth_provider::OAuthProvider;
use rust_mcp_remote::streamable_http::{
    StreamableHttpClientTransport, StreamableHttpOptions, TransportError,
};
use serde_json::{Value, json};
use tokio::sync::mpsc::UnboundedReceiver;
use url::Url;

use crate::test_server::{RecordedRequest, reply, serve};
use crate::use_temporary_config_dir;

const JSON: (&str, &str) = ("content-type", "application/json");

static OPENED: Mutex<Vec<String>> = Mutex::new(Vec::new());

fn record_opened(url: &str) -> bool {
    OPENED.lock().unwrap().push(url.to_owned());
    true
}

fn unique_hash(name: &str) -> String {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    format!("{name}-{}", COUNTER.fetch_add(1, Ordering::SeqCst))
}

/// An MCP server that is its own authorization server.
async fn auth_server() -> (String, UnboundedReceiver<RecordedRequest>) {
    let base = Arc::new(OnceLock::<String>::new());
    let handler_base = Arc::clone(&base);
    let (url, requests) = serve(Arc::new(move |request: &RecordedRequest| {
        let base = handler_base.get().cloned().unwrap_or_default();
        let path = request.path.split('?').next().unwrap_or("");
        let form: Vec<(String, String)> = url::form_urlencoded::parse(request.body.as_bytes())
            .into_owned()
            .collect();
        let grant = form
            .iter()
            .find(|(key, _)| key == "grant_type")
            .map(|(_, value)| value.as_str());
        match path {
            "/.well-known/oauth-protected-resource/mcp" => reply(
                200,
                &[JSON],
                &json!({"resource": format!("{base}/mcp"), "authorization_servers": [base]})
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
                    "scopes_supported": ["mcp:tools"],
                })
                .to_string(),
            ),
            "/register" => {
                let mut info: Value = serde_json::from_str(&request.body).unwrap();
                info["client_id"] = json!("registered-client");
                reply(201, &[JSON], &info.to_string())
            }
            "/token" => match grant {
                Some("authorization_code") => reply(
                    200,
                    &[JSON],
                    r#"{"access_token":"at-1","token_type":"Bearer","expires_in":3600,"refresh_token":"rt-1"}"#,
                ),
                Some("refresh_token") => reply(
                    200,
                    &[JSON],
                    r#"{"access_token":"at-2","token_type":"Bearer","expires_in":3600}"#,
                ),
                Some("client_credentials") => reply(
                    200,
                    &[JSON],
                    r#"{"access_token":"cc-1","token_type":"Bearer","expires_in":3600}"#,
                ),
                _ => reply(400, &[JSON], r#"{"error":"unsupported_grant_type"}"#),
            },
            "/mcp" if request.header("authorization") == Some("Bearer at-1") => reply(
                200,
                &[JSON],
                r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"fake","version":"1"}}}"#,
            ),
            "/mcp" => {
                let header = format!(
                    r#"Bearer resource_metadata="{base}/.well-known/oauth-protected-resource/mcp""#
                );
                reply(401, &[("www-authenticate", header.as_str())], "no")
            }
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

fn provider(base: &str, hash: &str, options: OAuthProviderOptions) -> OAuthProvider {
    use_temporary_config_dir();
    let provider = NodeOAuthClientProvider::new(OAuthProviderOptions {
        server_url: base.to_owned(),
        resource_server_url: Some(format!("{base}/mcp")),
        callback_port: 3334,
        host: "localhost".to_owned(),
        server_url_hash: hash.to_owned(),
        ..options
    })
    .unwrap();
    OAuthProvider::new(provider, None).with_browser_opener(record_opened)
}

fn now_ms() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as f64
}

#[tokio::test]
async fn signs_in_through_the_browser_and_then_redeems_the_code() {
    let (base, mut requests) = auth_server().await;
    let hash = unique_hash("browser");
    // proxy.ts discovers the metadata first and hands it to the provider.
    let provider = Arc::new(provider(
        &base,
        &hash,
        OAuthProviderOptions {
            authorization_server_metadata: Some(
                json!({"issuer": base, "scopes_supported": ["mcp:tools"]}),
            ),
            ..Default::default()
        },
    ));
    let options = AuthOptions::new(Url::parse(&format!("{base}/mcp")).unwrap());

    // The future is Send, so the proxy can run auth() on a tokio task.
    let task_provider = Arc::clone(&provider);
    let task_options = options.clone();
    let result = tokio::spawn(async move { auth(&*task_provider, &task_options).await })
        .await
        .unwrap();
    assert_eq!(result, Ok(AuthResult::Redirect));

    let client_info: Value = read_json_file(&hash, "client_info.json").unwrap();
    assert_eq!(client_info["client_id"], "registered-client");
    assert_eq!(
        client_info["redirect_uris"],
        json!(["http://localhost:3334/oauth/callback"])
    );

    let opened = OPENED
        .lock()
        .unwrap()
        .iter()
        .find(|url| url.contains(&base))
        .cloned()
        .expect("the browser was sent to the authorization URL");
    let opened = Url::parse(&opened).unwrap();
    let query: Vec<(String, String)> = opened.query_pairs().into_owned().collect();
    assert_eq!(opened.path(), "/authorize");
    assert_eq!(param(&query, "client_id"), Some("registered-client"));
    assert_eq!(param(&query, "scope"), Some("mcp:tools"));
    assert_eq!(param(&query, "resource"), Some(&*format!("{base}/mcp")));
    let state = param(&query, "state").unwrap().to_owned();
    drain(&mut requests);

    // The callback leg, as the proxy runs it once the code arrives.
    provider.use_authorization_state(&state);
    let mut callback = options.clone();
    callback.authorization_code = Some("the-code".to_owned());
    assert_eq!(
        auth(&*provider, &callback).await,
        Ok(AuthResult::Authorized)
    );

    let token_request = drain(&mut requests)
        .into_iter()
        .find(|request| request.path == "/token")
        .unwrap();
    let token_form = form(&token_request.body);
    assert_eq!(param(&token_form, "grant_type"), Some("authorization_code"));
    assert_eq!(param(&token_form, "code"), Some("the-code"));
    assert_eq!(param(&token_form, "client_id"), Some("registered-client"));
    assert!(param(&token_form, "code_verifier").is_some());

    let saved: Value = read_json_file(&hash, "tokens.json").unwrap();
    assert_eq!(saved["access_token"], "at-1");
    assert!(saved["expires_at"].as_f64().unwrap() > now_ms());
    assert_eq!(provider.tokens(None).await.unwrap()["access_token"], "at-1");
}

#[tokio::test]
async fn refreshes_an_expiring_token_before_handing_it_out() {
    let (base, mut requests) = auth_server().await;
    let hash = unique_hash("refresh");
    let provider = provider(&base, &hash, OAuthProviderOptions::default());
    write_json_file(
        &hash,
        "client_info.json",
        &json!({"client_id": "registered-client", "redirect_uris": ["http://localhost:3334/oauth/callback"]}),
    )
    .unwrap();
    write_json_file(
        &hash,
        "tokens.json",
        &json!({
            "access_token": "at-1",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "rt-1",
            "scope": "mcp:tools",
            "requested_scope": "mcp:tools",
            "expires_at": now_ms() - 1000.0,
        }),
    )
    .unwrap();

    let tokens = provider.tokens(None).await.unwrap();
    assert_eq!(tokens["access_token"], "at-2");
    assert_eq!(
        tokens["refresh_token"], "rt-1",
        "an unrotated refresh token is kept"
    );

    let token_request = drain(&mut requests)
        .into_iter()
        .find(|request| request.path == "/token")
        .unwrap();
    let token_form = form(&token_request.body);
    assert_eq!(param(&token_form, "grant_type"), Some("refresh_token"));
    assert_eq!(param(&token_form, "refresh_token"), Some("rt-1"));
    assert_eq!(param(&token_form, "scope"), Some("mcp:tools"));
    assert_eq!(param(&token_form, "client_id"), Some("registered-client"));

    let saved: Value = read_json_file(&hash, "tokens.json").unwrap();
    assert_eq!(saved["access_token"], "at-2");
    assert!(saved["expires_at"].as_f64().unwrap() > now_ms());
}

#[tokio::test]
async fn renews_an_expiring_client_credentials_token_through_auth() {
    let (base, mut requests) = auth_server().await;
    let hash = unique_hash("client-credentials");
    let provider = provider(
        &base,
        &hash,
        OAuthProviderOptions {
            use_client_credentials: Some(true),
            token_endpoint: Some(format!("{base}/token")),
            static_oauth_client_info: Some(
                json!({"client_id": "machine", "client_secret": "s3cret"}),
            ),
            ..Default::default()
        },
    );
    write_json_file(
        &hash,
        "tokens.json",
        &json!({
            "access_token": "old",
            "token_type": "Bearer",
            "expires_in": 3600,
            "expires_at": now_ms() - 1000.0,
        }),
    )
    .unwrap();

    let tokens = provider.tokens(None).await.unwrap();
    assert_eq!(tokens["access_token"], "cc-1");

    let seen = drain(&mut requests);
    assert_eq!(
        seen.iter()
            .map(|request| request.path.as_str())
            .collect::<Vec<_>>(),
        ["/token"],
        "the explicit token endpoint skips discovery"
    );
    let token_form = form(&seen[0].body);
    assert_eq!(param(&token_form, "grant_type"), Some("client_credentials"));
    assert!(
        seen[0]
            .header("authorization")
            .is_some_and(|value| value.starts_with("Basic ")),
        "the secret goes in the Basic header"
    );
}

#[tokio::test]
async fn signs_in_with_client_credentials_instead_of_opening_a_browser() {
    let (base, mut requests) = auth_server().await;
    let hash = unique_hash("cc-redirect");
    let provider = provider(
        &base,
        &hash,
        OAuthProviderOptions {
            use_client_credentials: Some(true),
            static_oauth_client_info: Some(
                json!({"client_id": "machine", "client_secret": "s3cret"}),
            ),
            ..Default::default()
        },
    );
    let authorization_url = Url::parse(&format!("{base}/authorize?client_id=machine")).unwrap();

    provider
        .redirect_to_authorization(&authorization_url)
        .await
        .unwrap();

    let saved: Value = read_json_file(&hash, "tokens.json").unwrap();
    assert_eq!(saved["access_token"], "cc-1");
    let token_request = drain(&mut requests)
        .into_iter()
        .find(|request| request.path == "/token")
        .unwrap();
    let token_form = form(&token_request.body);
    assert_eq!(param(&token_form, "grant_type"), Some("client_credentials"));
    assert_eq!(
        param(&token_form, "resource"),
        None,
        "without resource metadata the SDK default sends no resource"
    );
}

#[tokio::test]
async fn add_client_authentication_repeats_the_granted_scope_on_refresh() {
    let hash = unique_hash("scope-on-refresh");
    let provider = provider(
        "https://auth.example.com",
        &hash,
        OAuthProviderOptions::default(),
    );
    write_json_file(&hash, "client_info.json", &json!({"client_id": "abc"})).unwrap();
    write_json_file(
        &hash,
        "tokens.json",
        &json!({"access_token": "a", "token_type": "Bearer", "scope": "granted"}),
    )
    .unwrap();

    let mut headers = Vec::new();
    let mut params = vec![("grant_type".to_owned(), "refresh_token".to_owned())];
    provider
        .add_client_authentication(
            &mut headers,
            &mut params,
            &Url::parse("https://auth.example.com/token").unwrap(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        params,
        [
            ("grant_type".to_owned(), "refresh_token".to_owned()),
            ("client_id".to_owned(), "abc".to_owned()),
            ("scope".to_owned(), "granted".to_owned()),
        ]
    );
    assert!(headers.is_empty());
}

#[tokio::test]
async fn the_transport_signs_in_on_a_401_and_finish_auth_lets_the_retry_through() {
    let (base, mut requests) = auth_server().await;
    let hash = unique_hash("transport");
    let provider = Arc::new(provider(&base, &hash, OAuthProviderOptions::default()));
    let initialize = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "test", "version": "1"}}});
    let (transport, _events) = StreamableHttpClientTransport::new(
        Url::parse(&format!("{base}/mcp")).unwrap(),
        StreamableHttpOptions {
            oauth: Some(Arc::new(Arc::clone(&provider))),
            ..Default::default()
        },
    );
    transport.start().unwrap();

    // The 401 runs auth(), which registers a client and sends the browser off to sign in.
    assert_eq!(
        transport.send(&initialize).await,
        Err(TransportError::Unauthorized("Unauthorized".to_owned()))
    );
    let opened = OPENED
        .lock()
        .unwrap()
        .iter()
        .find(|url| url.contains(&base))
        .cloned()
        .expect("the browser was sent to the authorization URL");
    let opened = Url::parse(&opened).unwrap();
    let query: Vec<(String, String)> = opened.query_pairs().into_owned().collect();
    assert_eq!(param(&query, "client_id"), Some("registered-client"));
    assert_eq!(param(&query, "resource"), Some(&*format!("{base}/mcp")));
    drain(&mut requests);

    // The callback brings the code back; finishAuth redeems it and the retry goes through.
    provider.use_authorization_state(param(&query, "state").unwrap());
    transport.finish_auth("the-code", None).await.unwrap();
    let token_request = drain(&mut requests)
        .into_iter()
        .find(|request| request.path == "/token")
        .unwrap();
    assert_eq!(param(&form(&token_request.body), "code"), Some("the-code"));

    transport.send(&initialize).await.unwrap();
    let post = drain(&mut requests)
        .into_iter()
        .find(|request| request.path == "/mcp")
        .unwrap();
    assert_eq!(post.header("authorization"), Some("Bearer at-1"));
    let tokens: Value = read_json_file(&hash, "tokens.json").unwrap();
    assert_eq!(tokens["access_token"], "at-1");
}

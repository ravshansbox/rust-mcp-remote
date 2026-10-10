use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rust_mcp_remote::mcp_auth_config::read_json_file;
use rust_mcp_remote::node_oauth_client_provider::{NodeOAuthClientProvider, OAuthProviderOptions};
use serde_json::{Value, json};

static ENVIRONMENT: Mutex<()> = Mutex::new(());

const HASH: &str = "authorize-with-client-credentials-test";

fn with_temporary_config_dir<T>(action: impl FnOnce() -> T) -> T {
    let _guard = ENVIRONMENT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let directory: PathBuf = std::env::temp_dir().join(format!(
        "mcp-remote-authorize-with-client-credentials-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).expect("create temporary directory");
    unsafe { std::env::set_var("MCP_REMOTE_CONFIG_DIR", &directory) };
    let result = action();
    unsafe { std::env::remove_var("MCP_REMOTE_CONFIG_DIR") };
    std::fs::remove_dir_all(&directory).expect("remove temporary directory");
    result
}

fn provider(options: OAuthProviderOptions) -> NodeOAuthClientProvider {
    NodeOAuthClientProvider::new(OAuthProviderOptions {
        server_url: "https://mcp.example.com/mcp".to_string(),
        callback_port: 3334,
        host: "localhost".to_string(),
        server_url_hash: HASH.to_string(),
        use_client_credentials: Some(true),
        ..options
    })
    .unwrap()
}

fn client_info() -> Value {
    json!({ "client_id": "machine", "client_secret": "secret" })
}

fn metadata() -> Value {
    json!({ "issuer": "https://auth.example.com", "token_endpoint": "https://auth.example.com/token" })
}

#[test]
fn fails_when_the_authorization_server_metadata_is_missing() {
    with_temporary_config_dir(|| {
        let mut provider = provider(OAuthProviderOptions {
            static_oauth_client_info: Some(client_info()),
            ..Default::default()
        });

        let result = provider.authorize_with_client_credentials(
            0.0,
            || Ok(None),
            |_, _, _, _| panic!("no token request expected"),
        );

        assert_eq!(
            result,
            Err("Could not discover the authorization server metadata, so there is no token endpoint to ask".to_string())
        );
    });
}

#[test]
fn passes_on_a_metadata_discovery_error() {
    with_temporary_config_dir(|| {
        let mut provider = provider(OAuthProviderOptions::default());

        let result = provider.authorize_with_client_credentials(
            0.0,
            || Err("discovery failed".to_string()),
            |_, _, _, _| panic!("no token request expected"),
        );

        assert_eq!(result, Err("discovery failed".to_string()));
    });
}

#[test]
fn fails_when_no_client_credentials_were_supplied() {
    with_temporary_config_dir(|| {
        let mut provider = provider(OAuthProviderOptions::default());

        let result = provider.authorize_with_client_credentials(
            0.0,
            || Ok(Some(metadata())),
            |_, _, _, _| panic!("no token request expected"),
        );

        assert_eq!(
            result,
            Err("No OAuth client credentials were supplied; pass them with --static-oauth-client-info".to_string())
        );
    });
}

#[test]
fn requests_tokens_with_the_requested_scope_and_resource_and_saves_them() {
    with_temporary_config_dir(|| {
        let mut provider = provider(OAuthProviderOptions {
            static_oauth_client_info: Some(client_info()),
            static_oauth_client_metadata: Some(json!({ "scope": "read write" })),
            protected_resource_metadata: Some(json!({ "resource": "https://mcp.example.com/" })),
            ..Default::default()
        });
        let received = Mutex::new(None);

        let result = provider.authorize_with_client_credentials(
            1_000.0,
            || Ok(Some(metadata())),
            |metadata, client_information, scope, resource| {
                *received.lock().unwrap() = Some((
                    metadata.clone(),
                    client_information.clone(),
                    scope.map(str::to_string),
                    resource.map(|resource| resource.to_string()),
                ));
                Ok(json!({ "access_token": "machine-token", "token_type": "Bearer" }))
            },
        );

        assert_eq!(result, Ok(()));
        assert_eq!(
            received.into_inner().unwrap(),
            Some((
                metadata(),
                client_info(),
                Some("read write".to_string()),
                Some("https://mcp.example.com/".to_string())
            ))
        );
        let saved = read_json_file::<Value>(HASH, "tokens.json").expect("tokens saved");
        assert_eq!(saved["access_token"], json!("machine-token"));
    });
}

#[test]
fn asks_for_no_scope_rather_than_the_openid_fallback() {
    with_temporary_config_dir(|| {
        let mut provider = provider(OAuthProviderOptions {
            static_oauth_client_info: Some(client_info()),
            ..Default::default()
        });
        let received_scope = Mutex::new(Some(Some(String::new())));

        let result = provider.authorize_with_client_credentials(
            1_000.0,
            || Ok(Some(metadata())),
            |_, _, scope, resource| {
                *received_scope.lock().unwrap() = Some(scope.map(str::to_string));
                assert_eq!(resource, None);
                Ok(json!({ "access_token": "machine-token", "token_type": "Bearer" }))
            },
        );

        assert_eq!(result, Ok(()));
        assert_eq!(received_scope.into_inner().unwrap(), Some(None));
    });
}

#[test]
fn does_not_save_tokens_when_the_token_request_fails() {
    with_temporary_config_dir(|| {
        let mut provider = provider(OAuthProviderOptions {
            static_oauth_client_info: Some(client_info()),
            ..Default::default()
        });

        let result = provider.authorize_with_client_credentials(
            1_000.0,
            || Ok(Some(metadata())),
            |_, _, _, _| Err("token request failed".to_string()),
        );

        assert_eq!(result, Err("token request failed".to_string()));
        assert_eq!(read_json_file::<Value>(HASH, "tokens.json"), None);
    });
}

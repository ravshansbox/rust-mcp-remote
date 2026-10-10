use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rust_mcp_remote::mcp_auth_config::read_json_file;
use rust_mcp_remote::node_oauth_client_provider::{NodeOAuthClientProvider, OAuthProviderOptions};
use serde_json::{Value, json};

use crate::GLOBAL_STATE as ENVIRONMENT;

const HASH: &str = "authorize-with-device-code-test";

const NO_DEVICE_GRANT: &str = "--device-code was passed but the authorization server does not offer the device grant. Remove the flag to sign in through a browser instead.";

fn with_temporary_config_dir<T>(action: impl FnOnce() -> T) -> T {
    let _guard = ENVIRONMENT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let directory: PathBuf = std::env::temp_dir().join(format!(
        "mcp-remote-authorize-with-device-code-{}-{nanos}",
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
        use_device_code: Some(true),
        ..options
    })
    .unwrap()
}

fn client_info() -> Value {
    json!({ "client_id": "device-client" })
}

fn metadata() -> Value {
    json!({
        "issuer": "https://auth.example.com",
        "token_endpoint": "https://auth.example.com/token",
        "device_authorization_endpoint": "https://auth.example.com/device"
    })
}

#[test]
fn fails_when_the_authorization_server_metadata_is_missing() {
    with_temporary_config_dir(|| {
        let mut provider = provider(OAuthProviderOptions {
            static_oauth_client_info: Some(client_info()),
            ..Default::default()
        });

        let result = provider.authorize_with_device_code(
            0.0,
            || Ok(None),
            |_, _, _, _| panic!("no device flow expected"),
        );

        assert_eq!(result, Err(NO_DEVICE_GRANT.to_string()));
    });
}

#[test]
fn fails_when_the_server_does_not_offer_the_device_grant() {
    with_temporary_config_dir(|| {
        let mut provider = provider(OAuthProviderOptions {
            static_oauth_client_info: Some(client_info()),
            ..Default::default()
        });

        let result = provider.authorize_with_device_code(
            0.0,
            || {
                Ok(Some(json!({
                    "issuer": "https://auth.example.com",
                    "token_endpoint": "https://auth.example.com/token"
                })))
            },
            |_, _, _, _| panic!("no device flow expected"),
        );

        assert_eq!(result, Err(NO_DEVICE_GRANT.to_string()));
    });
}

#[test]
fn passes_on_a_metadata_discovery_error() {
    with_temporary_config_dir(|| {
        let mut provider = provider(OAuthProviderOptions::default());

        let result = provider.authorize_with_device_code(
            0.0,
            || Err("discovery failed".to_string()),
            |_, _, _, _| panic!("no device flow expected"),
        );

        assert_eq!(result, Err("discovery failed".to_string()));
    });
}

#[test]
fn fails_when_no_client_is_registered() {
    with_temporary_config_dir(|| {
        let mut provider = provider(OAuthProviderOptions::default());

        let result = provider.authorize_with_device_code(
            0.0,
            || Ok(Some(metadata())),
            |_, _, _, _| panic!("no device flow expected"),
        );

        assert_eq!(
            result,
            Err("No OAuth client is registered, so there is nothing to authorize".to_string())
        );
    });
}

#[test]
fn runs_the_device_flow_with_the_scope_and_resource_and_saves_the_tokens() {
    with_temporary_config_dir(|| {
        let mut provider = provider(OAuthProviderOptions {
            static_oauth_client_info: Some(client_info()),
            static_oauth_client_metadata: Some(json!({ "scope": "read write" })),
            protected_resource_metadata: Some(json!({ "resource": "https://mcp.example.com/" })),
            ..Default::default()
        });
        let received = Mutex::new(None);

        let result = provider.authorize_with_device_code(
            1_000.0,
            || Ok(Some(metadata())),
            |metadata, client_information, scope, resource| {
                *received.lock().unwrap() = Some((
                    metadata.clone(),
                    client_information.clone(),
                    scope.map(str::to_string),
                    resource.map(|resource| resource.to_string()),
                ));
                Ok(json!({ "access_token": "device-token", "token_type": "Bearer" }))
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
        assert_eq!(saved["access_token"], json!("device-token"));
    });
}

#[test]
fn asks_for_the_openid_fallback_scope_when_nothing_was_requested() {
    with_temporary_config_dir(|| {
        let mut provider = provider(OAuthProviderOptions {
            static_oauth_client_info: Some(client_info()),
            ..Default::default()
        });
        let received_scope = Mutex::new(None);

        let result = provider.authorize_with_device_code(
            1_000.0,
            || Ok(Some(metadata())),
            |_, _, scope, resource| {
                *received_scope.lock().unwrap() = Some(scope.map(str::to_string));
                assert_eq!(resource, None);
                Ok(json!({ "access_token": "device-token", "token_type": "Bearer" }))
            },
        );

        assert_eq!(result, Ok(()));
        assert_eq!(
            received_scope.into_inner().unwrap(),
            Some(Some("openid email profile".to_string()))
        );
    });
}

#[test]
fn does_not_save_tokens_when_the_device_flow_fails() {
    with_temporary_config_dir(|| {
        let mut provider = provider(OAuthProviderOptions {
            static_oauth_client_info: Some(client_info()),
            ..Default::default()
        });

        let result = provider.authorize_with_device_code(
            1_000.0,
            || Ok(Some(metadata())),
            |_, _, _, _| Err("device flow failed".to_string()),
        );

        assert_eq!(result, Err("device flow failed".to_string()));
        assert_eq!(read_json_file::<Value>(HASH, "tokens.json"), None);
    });
}

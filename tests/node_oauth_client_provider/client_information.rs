use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use rust_mcp_remote::mcp_auth_config::write_json_file;
use rust_mcp_remote::node_oauth_client_provider::{
    ClientRegistrationSource, NodeOAuthClientProvider, OAuthProviderOptions,
};
use serde_json::{Value, json};

use crate::GLOBAL_STATE as ENVIRONMENT;

const HASH: &str = "client-information-test";

const METADATA_URL: &str = "https://client.example.com/metadata.json";

fn with_temporary_config_dir<T>(action: impl FnOnce() -> T) -> T {
    let _guard = ENVIRONMENT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let directory: PathBuf = std::env::temp_dir().join(format!(
        "mcp-remote-client-information-{}-{nanos}",
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
        server_url: "https://auth.example.com".to_string(),
        callback_port: 3334,
        host: "localhost".to_string(),
        server_url_hash: HASH.to_string(),
        ..options
    })
    .unwrap()
}

fn cache_client(client_id: &str) -> Value {
    let client = json!({ "client_id": client_id, "redirect_uris": [] });
    write_json_file(HASH, "client_info.json", &client).unwrap();
    client
}

#[test]
fn static_client_info_wins_over_the_cache() {
    with_temporary_config_dir(|| {
        cache_client("cached");
        let static_client = json!({ "client_id": "static" });
        let mut provider = provider(OAuthProviderOptions {
            static_oauth_client_info: Some(static_client.clone()),
            ..Default::default()
        });

        assert_eq!(provider.client_information(), Some(static_client.clone()));
        assert_eq!(provider.client_info, Some(static_client));
        assert_eq!(
            provider.client_registration_source,
            Some(ClientRegistrationSource::Static)
        );
    });
}

#[test]
fn a_supported_metadata_document_identifies_the_client() {
    with_temporary_config_dir(|| {
        cache_client("cached");
        let mut provider = provider(OAuthProviderOptions {
            client_metadata_url: Some(METADATA_URL.to_string()),
            authorization_server_metadata: Some(
                json!({ "client_id_metadata_document_supported": true }),
            ),
            ..Default::default()
        });

        assert_eq!(
            provider.client_information(),
            Some(json!({ "client_id": METADATA_URL }))
        );
        assert_eq!(provider.client_info, None);
        assert_eq!(
            provider.client_registration_source,
            Some(ClientRegistrationSource::ClientIdMetadataDocument)
        );
    });
}

#[test]
fn an_unsupported_metadata_document_falls_back_to_the_cache() {
    with_temporary_config_dir(|| {
        let cached = cache_client("cached");
        let mut provider = provider(OAuthProviderOptions {
            client_metadata_url: Some(METADATA_URL.to_string()),
            authorization_server_metadata: Some(json!({})),
            ..Default::default()
        });

        assert_eq!(provider.client_information(), Some(cached));
        assert_eq!(
            provider.client_registration_source,
            Some(ClientRegistrationSource::CachedDynamic)
        );
    });
}

#[test]
fn a_cached_client_is_read_and_marked_cached() {
    with_temporary_config_dir(|| {
        let cached = cache_client("cached");
        let mut provider = provider(OAuthProviderOptions::default());

        assert_eq!(provider.client_information(), Some(cached.clone()));
        assert_eq!(provider.client_info, Some(cached));
        assert_eq!(
            provider.client_registration_source,
            Some(ClientRegistrationSource::CachedDynamic)
        );
    });
}

#[test]
fn a_fresh_registration_stays_fresh_when_read_back() {
    with_temporary_config_dir(|| {
        let mut provider = provider(OAuthProviderOptions::default());
        provider
            .save_client_information(&json!({ "client_id": "fresh", "redirect_uris": [] }))
            .unwrap();

        provider.client_information();

        assert_eq!(
            provider.client_registration_source,
            Some(ClientRegistrationSource::FreshDynamic)
        );
    });
}

#[test]
fn no_cached_client_returns_none() {
    with_temporary_config_dir(|| {
        let mut provider = provider(OAuthProviderOptions::default());

        assert_eq!(provider.client_information(), None);
        assert_eq!(provider.client_registration_source, None);
    });
}

#[test]
fn a_cached_file_without_a_client_id_is_ignored() {
    with_temporary_config_dir(|| {
        write_json_file(HASH, "client_info.json", &json!({ "redirect_uris": [] })).unwrap();
        let mut provider = provider(OAuthProviderOptions::default());

        assert_eq!(provider.client_information(), None);
    });
}

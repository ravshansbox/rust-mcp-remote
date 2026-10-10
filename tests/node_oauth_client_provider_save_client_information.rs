use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rust_mcp_remote::mcp_auth_config::{config_file_path, read_json_file};
use rust_mcp_remote::node_oauth_client_provider::{
    ClientRegistrationSource, NodeOAuthClientProvider, OAuthProviderOptions,
};
use serde_json::{Value, json};

static ENVIRONMENT: Mutex<()> = Mutex::new(());

const HASH: &str = "save-client-information-test";

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
        "mcp-remote-save-client-information-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).expect("create temporary directory");
    unsafe { std::env::set_var("MCP_REMOTE_CONFIG_DIR", &directory) };
    let result = action();
    unsafe { std::env::remove_var("MCP_REMOTE_CONFIG_DIR") };
    std::fs::remove_dir_all(&directory).expect("remove temporary directory");
    result
}

fn provider(client_metadata_url: Option<&str>) -> NodeOAuthClientProvider {
    NodeOAuthClientProvider::new(OAuthProviderOptions {
        server_url: "https://auth.example.com".to_string(),
        callback_port: 3334,
        host: "localhost".to_string(),
        server_url_hash: HASH.to_string(),
        client_metadata_url: client_metadata_url.map(str::to_string),
        ..Default::default()
    })
    .unwrap()
}

#[test]
fn saving_a_new_registration_writes_it_and_marks_it_fresh() {
    with_temporary_config_dir(|| {
        let mut provider = provider(None);
        let client = json!({ "client_id": "fresh", "redirect_uris": [] });

        provider.save_client_information(&client).unwrap();

        assert_eq!(
            read_json_file::<Value>(HASH, "client_info.json"),
            Some(client.clone())
        );
        assert_eq!(provider.client_info, Some(client));
        assert_eq!(
            provider.client_registration_source,
            Some(ClientRegistrationSource::FreshDynamic)
        );
    });
}

#[test]
fn restamping_the_cached_client_keeps_it_cached() {
    with_temporary_config_dir(|| {
        let mut provider = provider(None);
        provider.client_info = Some(json!({ "client_id": "cached" }));
        provider.client_registration_source = Some(ClientRegistrationSource::CachedDynamic);
        let restamped = json!({ "client_id": "cached", "issuer": "https://auth.example.com" });

        provider.save_client_information(&restamped).unwrap();

        assert_eq!(provider.client_info, Some(restamped.clone()));
        assert_eq!(
            provider.client_registration_source,
            Some(ClientRegistrationSource::CachedDynamic)
        );
        assert_eq!(
            read_json_file::<Value>(HASH, "client_info.json"),
            Some(restamped)
        );
    });
}

#[test]
fn a_different_client_replacing_the_cached_one_is_fresh() {
    with_temporary_config_dir(|| {
        let mut provider = provider(None);
        provider.client_info = Some(json!({ "client_id": "cached" }));
        provider.client_registration_source = Some(ClientRegistrationSource::CachedDynamic);

        provider
            .save_client_information(&json!({ "client_id": "other" }))
            .unwrap();

        assert_eq!(
            provider.client_registration_source,
            Some(ClientRegistrationSource::FreshDynamic)
        );
    });
}

#[test]
fn a_client_metadata_document_id_is_not_cached() {
    with_temporary_config_dir(|| {
        let mut provider = provider(Some(METADATA_URL));

        provider
            .save_client_information(&json!({ "client_id": METADATA_URL }))
            .unwrap();

        assert!(!config_file_path(HASH, "client_info.json").exists());
        assert_eq!(provider.client_info, None);
        assert_eq!(
            provider.client_registration_source,
            Some(ClientRegistrationSource::ClientIdMetadataDocument)
        );
    });
}

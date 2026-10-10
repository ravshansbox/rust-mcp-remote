//! The sign-in setup proxy.ts and client.ts share: discovering the authorization server,
//! building the OAuth provider and the lazily coordinated auth initializer, and settling who owns
//! the sign-in before the first connection attempt.

use std::sync::{Arc, Mutex};

use serde_json::json;
use tokio::io::AsyncReadExt;

use crate::callback_server::AuthEvents;
use crate::connect::{AuthInitialization, AuthInitializer};
use crate::coordination::{
    CoordinatedAuth, create_lazy_auth_coordinator, has_usable_tokens, server_issues_auth_challenge,
};
use crate::logging::{debug_log, log};
use crate::node_oauth_client_provider::{NodeOAuthClientProvider, OAuthProviderOptions};
use crate::oauth_provider::OAuthProvider;
use crate::streamable_http::fetch_with_headers;
use crate::utils::{CommandLineArgs, discover_oauth_server_info};

/// What [`prepare_sign_in`] sets up.
pub struct SignIn {
    pub auth_provider: Arc<OAuthProvider>,
    pub auth_initializer: AuthInitializer,
    /// The device and client-credentials grants finish without a browser or a callback port.
    pub signs_in_without_a_callback_port: bool,
    /// The coordinated sign-in whose callback server has to be closed on the way out.
    owned_auth: Arc<Mutex<Option<Arc<CoordinatedAuth>>>>,
}

impl SignIn {
    /// `server.close()`: closes the callback server, if this instance started one.
    pub fn close_owned_auth(&self) {
        if let Ok(slot) = self.owned_auth.lock()
            && let Some(auth_state) = slot.as_ref()
        {
            auth_state.close();
        }
    }
}

/// The start of `runProxy` and `runClient`, up to the first connection attempt. `client_name`
/// is the name the dynamic client registration uses.
pub async fn prepare_sign_in(args: &CommandLineArgs, client_name: &str) -> Result<SignIn, String> {
    let events = AuthEvents::new();

    // A redirect_uri pinned outside this process stops being valid on another port.
    let strict_port = args.specified_port.is_some()
        || args.static_oauth_client_info.is_some()
        || args.client_metadata_url.is_some();
    let coordinator = Arc::new(create_lazy_auth_coordinator(
        &args.server_url_hash,
        &args.callback_path,
        args.callback_port,
        events,
        args.auth_timeout_ms,
        strict_port,
    ));

    log("Discovering OAuth server configuration...", &[]);
    let discovery = discover_oauth_server_info(
        &args.server_url,
        &args.headers,
        args.token_endpoint.as_deref(),
    )
    .await?;
    if let Some(metadata) = &discovery.protected_resource_metadata {
        log(
            &format!(
                "Discovered authorization server: {}",
                discovery.authorization_server_url
            ),
            &[],
        );
        if let Some(scopes) = metadata.get("scopes_supported") {
            debug_log(
                "Protected Resource Metadata scopes",
                &[json!({"scopes_supported": scopes})],
            );
        }
    } else {
        debug_log(
            "No Protected Resource Metadata found, using server URL as authorization server",
            &[],
        );
    }

    let provider = NodeOAuthClientProvider::new(OAuthProviderOptions {
        server_url: discovery.authorization_server_url.clone(),
        resource_server_url: Some(args.server_url.clone()),
        callback_path: Some(args.callback_path.clone()),
        callback_port: args.callback_port,
        host: args.host.clone(),
        client_name: Some(client_name.to_owned()),
        static_oauth_client_metadata: args.static_oauth_client_metadata.clone(),
        static_oauth_client_info: args.static_oauth_client_info.clone(),
        client_metadata_url: args.client_metadata_url.clone(),
        use_id_token: Some(args.use_id_token),
        use_device_code: Some(args.use_device_code),
        use_client_credentials: Some(args.use_client_credentials),
        token_endpoint: args.token_endpoint.clone(),
        authorize_resource: args.authorize_resource.clone(),
        skip_resource_parameter: Some(args.skip_resource_parameter),
        authorize_params: Some(args.authorize_params.clone()),
        server_url_hash: args.server_url_hash.clone(),
        authorization_server_metadata: discovery.authorization_server_metadata.clone(),
        protected_resource_metadata: discovery.protected_resource_metadata.clone(),
        www_authenticate_scope: discovery.www_authenticate_scope.clone(),
        ..OAuthProviderOptions::default()
    })?;
    let auth_provider = Arc::new(OAuthProvider::new(
        provider,
        fetch_with_headers(None, &args.headers),
    ));

    // The coordinated sign-in whose callback server has to be closed on the way out.
    let owned_auth: Arc<Mutex<Option<Arc<CoordinatedAuth>>>> = Arc::new(Mutex::new(None));
    let auth_initializer: AuthInitializer = {
        let coordinator = Arc::clone(&coordinator);
        let auth_provider = Arc::clone(&auth_provider);
        let owned_auth = Arc::clone(&owned_auth);
        let callback_port = args.callback_port;
        Arc::new(move |force_refresh| {
            let coordinator = Arc::clone(&coordinator);
            let auth_provider = Arc::clone(&auth_provider);
            let owned_auth = Arc::clone(&owned_auth);
            Box::pin(async move {
                let auth_state = coordinator
                    .initialize_auth(force_refresh)
                    .await
                    .map_err(|error| error.to_string())?;
                if let Ok(mut slot) = owned_auth.lock() {
                    *slot = Some(Arc::clone(&auth_state));
                }
                // A stranger on an earlier candidate can push this instance onto a later port.
                if auth_state.actual_port != callback_port {
                    log(
                        &format!("Using callback port {}", auth_state.actual_port),
                        &[],
                    );
                    auth_provider.set_callback_port(auth_state.actual_port);
                }
                let waiter = Arc::clone(&auth_state);
                Ok(AuthInitialization {
                    wait_for_auth_code: Box::new(move || Box::pin(waiter.wait_for_auth_code())),
                    skip_browser_auth: auth_state.skip_browser_auth,
                })
            })
        })
    };
    // Ownership is settled before the first connection attempt, so a follower never registers
    // its own client or issues its own PKCE challenge.
    let signs_in_without_a_callback_port = args.use_device_code || args.use_client_credentials;
    if !signs_in_without_a_callback_port
        && !has_usable_tokens(&args.server_url_hash)
        && server_issues_auth_challenge(&args.server_url, &args.headers).await
    {
        auth_initializer(false).await?;
    }
    Ok(SignIn {
        auth_provider,
        auth_initializer,
        signs_in_without_a_callback_port,
        owned_auth,
    })
}

/// `setupSignalHandlers`: on Ctrl+C, or when stdin reaches its end, logs the shutdown, runs
/// `cleanup` and exits with 0. Only for a process that does not read stdin itself; the proxy
/// learns of both from its stdio transport closing.
pub fn setup_signal_handlers(cleanup: impl FnOnce() + Send + 'static) {
    tokio::spawn(async move {
        let stdin_ended = async {
            let mut stdin = tokio::io::stdin();
            let mut buffer = [0u8; 4096];
            while matches!(stdin.read(&mut buffer).await, Ok(read) if read > 0) {}
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = stdin_ended => {}
        }
        log("\nShutting down...", &[]);
        cleanup();
        std::process::exit(0);
    });
}

/// The advice proxy.ts logs after a fatal error caused by an untrusted certificate, which is
/// usually a VPN or a proxy re-signing traffic. rustls reports it as an unknown issuer.
pub fn vpn_hint(error: &str) -> Option<String> {
    let untrusted = error.contains("self-signed certificate in certificate chain")
        || error.contains("UnknownIssuer");
    untrusted.then(|| {
        "You may be behind a VPN!\n\n\
         If you are behind a VPN, add its CA certificate to the system trust store, which is\n\
         where mcp-remote looks for trusted certificates."
            .to_owned()
    })
}

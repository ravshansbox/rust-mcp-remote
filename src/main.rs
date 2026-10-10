use std::sync::{Arc, Mutex};

use rust_mcp_remote::callback_server::AuthEvents;
use rust_mcp_remote::connect::{
    AuthInitialization, AuthInitializer, ConnectOptions, RemoteConnection, connect_to_remote_server,
};
use rust_mcp_remote::coordination::{
    CoordinatedAuth, create_lazy_auth_coordinator, has_usable_tokens, server_issues_auth_challenge,
};
use rust_mcp_remote::logging::{debug_log, log};
use rust_mcp_remote::node_oauth_client_provider::{NodeOAuthClientProvider, OAuthProviderOptions};
use rust_mcp_remote::oauth_provider::OAuthProvider;
use rust_mcp_remote::proxy::{ProxyOptions, mcp_proxy};
use rust_mcp_remote::stdio::StdioServerTransport;
use rust_mcp_remote::streamable_http::fetch_with_headers;
use rust_mcp_remote::utils::{
    CommandLineArgs, discover_oauth_server_info, early_exit_output, parse_command_line_args_to,
};
use serde_json::{Value, json};

const USAGE: &str = "Usage: mcp-remote <https://server-url> [callback-port] [--debug]";

/// `runProxy` from proxy.ts. Not yet ported: mid-session re-authorization and the
/// rejected-token reset from inside the proxy, keep-alive, and the `auto` protocol mode.
async fn run_proxy(args: CommandLineArgs) -> Result<(), String> {
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
        client_name: Some("MCP CLI Proxy".to_owned()),
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
    let close_owned_auth = || {
        if let Ok(slot) = owned_auth.lock()
            && let Some(auth_state) = slot.as_ref()
        {
            auth_state.close();
        }
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

    let connected = connect_to_remote_server(
        &auth_provider,
        &auth_initializer,
        &ConnectOptions {
            server_url: args.server_url.clone(),
            headers: args.headers.clone(),
            transport_strategy: args.transport_strategy,
            protocol_mode: args.protocol_mode,
            non_interactive_flow: args.non_interactive_flow,
        },
    )
    .await;
    let RemoteConnection {
        transport: remote,
        events: remote_events,
    } = match connected {
        Ok(connection) => connection,
        Err(error) => {
            close_owned_auth();
            return Err(error.to_string());
        }
    };

    let (local, local_events) = StdioServerTransport::start_stdio();
    log("Local STDIO server running", &[]);
    log(
        &format!(
            "Proxy established successfully between local STDIO and remote {}",
            remote.name()
        ),
        &[],
    );
    log("Press Ctrl+C to exit", &[]);

    let proxy = mcp_proxy(
        local.clone(),
        local_events,
        remote.clone(),
        remote_events,
        ProxyOptions {
            ignored_tools: args.ignored_tools.clone(),
            ..ProxyOptions::default()
        },
    );
    tokio::select! {
        _ = proxy => {}
        _ = tokio::signal::ctrl_c() => {}
    }
    log("\nShutting down...", &[]);
    remote.close();
    local.close();
    close_owned_auth();
    Ok(())
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some(output) = early_exit_output(&args, USAGE) {
        print!("{output}");
        std::process::exit(0);
    }
    let args = match parse_command_line_args_to(&mut std::io::stderr(), args, USAGE) {
        Ok(Some(args)) => args,
        Ok(None) => std::process::exit(1),
        Err(error) => {
            log(&format!("Fatal error: {error}"), &[]);
            std::process::exit(1);
        }
    };
    if let Err(error) = run_proxy(args).await {
        log("Fatal error:", &[Value::String(error)]);
        std::process::exit(1);
    }
    std::process::exit(0);
}

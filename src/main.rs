use std::sync::Arc;
use std::time::Duration;

use rust_mcp_remote::cli::{prepare_sign_in, vpn_hint};
use rust_mcp_remote::connect::{
    ConnectOptions, RemoteConnection, connect_to_remote_server, forget_rejected_authorization,
};
use rust_mcp_remote::logging::log;
use rust_mcp_remote::proxy::{AuthHook, ProxyOptions, mcp_proxy};
use rust_mcp_remote::stdio::StdioServerTransport;
use rust_mcp_remote::utils::{
    CommandLineArgs, early_exit_output, parse_command_line_args_to, set_cookies_enabled,
};
use serde_json::Value;

const USAGE: &str = "Usage: mcp-remote <https://server-url> [callback-port] [--debug]";

/// `runProxy` from proxy.ts.
async fn run_proxy(args: CommandLineArgs) -> Result<(), String> {
    let sign_in = prepare_sign_in(&args, "MCP CLI Proxy").await?;
    let auth_provider = Arc::clone(&sign_in.auth_provider);
    let auth_initializer = Arc::clone(&sign_in.auth_initializer);
    let signs_in_without_a_callback_port = sign_in.signs_in_without_a_callback_port;
    let close_owned_auth = || sign_in.close_owned_auth();

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
        on_stream_reconnect,
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

    // Discards a token the server refused straight after issuing it, so the next attempt is an
    // ordinary 401 that `reauthorize` can answer.
    let forget_rejected: AuthHook = {
        let auth_provider = Arc::clone(&auth_provider);
        Arc::new(move || {
            let auth_provider = Arc::clone(&auth_provider);
            Box::pin(async move {
                forget_rejected_authorization(&auth_provider).await;
                Ok(())
            })
        })
    };
    // Finishes a sign-in the remote server asked for mid-session.
    let reauthorize: AuthHook = {
        let auth_initializer = Arc::clone(&auth_initializer);
        let auth_provider = Arc::clone(&auth_provider);
        let remote = remote.clone();
        Arc::new(move || {
            let auth_initializer = Arc::clone(&auth_initializer);
            let auth_provider = Arc::clone(&auth_provider);
            let remote = remote.clone();
            Box::pin(async move {
                // A grant that needs no browser already finished inside the redirect step
                if signs_in_without_a_callback_port {
                    log(
                        "Signed in without a browser; retrying with the tokens it produced",
                        &[],
                    );
                    return Ok(());
                }
                let initialization = auth_initializer(false).await?;
                if initialization.skip_browser_auth {
                    log(
                        "Another instance is completing the sign-in; retrying with the tokens it writes",
                        &[],
                    );
                    return Ok(());
                }
                let code = (initialization.wait_for_auth_code)().await?;
                if let Some(state) = &code.state {
                    auth_provider.use_authorization_state(state);
                }
                remote
                    .finish_auth(&code.code, code.iss.as_deref())
                    .await
                    .map_err(|error| error.to_string())?;
                log("Re-authorized with the remote server", &[]);
                Ok(())
            })
        })
    };

    let proxy = mcp_proxy(
        local.clone(),
        local_events,
        remote.clone(),
        remote_events,
        ProxyOptions {
            ignored_tools: args.ignored_tools.clone(),
            keep_alive: args
                .keep_alive
                .enabled
                .then(|| Duration::from_millis(args.keep_alive.interval_ms)),
            reauthorize: Some(reauthorize),
            forget_rejected_authorization: Some(forget_rejected),
            stream_reconnect: Some(on_stream_reconnect),
            protocol_mode: args.protocol_mode,
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
    set_cookies_enabled(args.cookies_enabled);
    if let Err(error) = run_proxy(args).await {
        log("Fatal error:", &[Value::String(error.clone())]);
        if let Some(hint) = vpn_hint(&error) {
            log(&hint, &[]);
        }
        std::process::exit(1);
    }
    std::process::exit(0);
}

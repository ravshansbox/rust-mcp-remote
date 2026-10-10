//! client.ts: a command-line MCP client that signs in to a remote server, lists its tools and
//! resources, and exits.

use rust_mcp_remote::cli::{configure_network, prepare_sign_in, setup_signal_handlers};
use rust_mcp_remote::client::attach_client_diagnostics;
use rust_mcp_remote::connect::{ConnectOptions, connect_client_to_remote_server};
use rust_mcp_remote::logging::log;
use rust_mcp_remote::protocol_era::ProtocolMode;
use rust_mcp_remote::utils::{
    CommandLineArgs, MCP_REMOTE_VERSION, early_exit_output, parse_command_line_args_to,
    set_cookies_enabled,
};
use serde_json::Value;

const USAGE: &str = "Usage: mcp-remote-client <https://server-url> [callback-port] [--debug]";

fn pretty(value: &Value) -> Value {
    Value::String(serde_json::to_string_pretty(value).unwrap_or_default())
}

/// `runClient` from client.ts. Returns the exit code.
async fn run_client(args: CommandLineArgs) -> Result<i32, String> {
    let sign_in =
        std::sync::Arc::new(prepare_sign_in(&args, "MCP CLI Client", args.use_device_code).await?);

    let connected = connect_client_to_remote_server(
        &sign_in.auth_provider,
        &sign_in.auth_initializer,
        &ConnectOptions {
            server_url: args.server_url.clone(),
            headers: args.headers.clone(),
            transport_strategy: args.transport_strategy,
            protocol_mode: ProtocolMode::Legacy,
            non_interactive_flow: args.non_interactive_flow,
        },
        "mcp-remote",
        MCP_REMOTE_VERSION,
    )
    .await
    .map(|(client, _transport)| client)
    .map_err(|error| error.to_string());
    let client = match connected {
        Ok(client) => client,
        Err(error) => {
            log("Fatal error:", &[Value::String(error)]);
            sign_in.close_owned_auth();
            return Ok(1);
        }
    };

    // Log what arrives without displacing the dispatcher that settles requests.
    attach_client_diagnostics(&client, || std::process::exit(0));

    {
        let client = client.clone();
        let sign_in = std::sync::Arc::clone(&sign_in);
        setup_signal_handlers(move || {
            log("\nClosing connection...", &[]);
            client.close();
            sign_in.close_owned_auth();
        });
    }

    log("Connected successfully!", &[]);

    log("Requesting tools list...", &[]);
    match client.request("tools/list", None).await {
        Ok(tools) => log("Tools:", &[pretty(&tools)]),
        Err(error) => log(
            "Error requesting tools list:",
            &[Value::String(error.to_string())],
        ),
    }

    log("Requesting resource list...", &[]);
    match client.request("resources/list", None).await {
        Ok(resources) => log("Resources:", &[pretty(&resources)]),
        Err(error) => log(
            "Error requesting resources list:",
            &[Value::String(error.to_string())],
        ),
    }

    log("Exiting OK...", &[]);
    sign_in.close_owned_auth();
    Ok(0)
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
            eprintln!("Fatal error: {error}");
            std::process::exit(1);
        }
    };
    set_cookies_enabled(args.cookies_enabled);
    configure_network(&args);
    match run_client(args).await {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            log("Fatal error:", &[Value::String(error)]);
            std::process::exit(1);
        }
    }
}

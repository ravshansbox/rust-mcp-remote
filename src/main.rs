use rust_mcp_remote::logging::{debug_log, log};
use rust_mcp_remote::proxy::{ProxyOptions, mcp_proxy};
use rust_mcp_remote::stdio::StdioServerTransport;
use rust_mcp_remote::streamable_http::{StreamableHttpClientTransport, StreamableHttpOptions};
use rust_mcp_remote::utils::{CommandLineArgs, early_exit_output, parse_command_line_args_to};
use serde_json::Value;

const USAGE: &str = "Usage: mcp-remote <https://server-url> [callback-port] [--debug]";

/// `runProxy` from proxy.ts, so far without OAuth discovery, sign-in, the
/// connection probe or the SSE fallback: it connects over streamable HTTP only.
async fn run_proxy(args: CommandLineArgs) -> Result<(), String> {
    log(
        &format!(
            "[{}] Connecting to remote server: {}",
            std::process::id(),
            args.server_url
        ),
        &[],
    );
    let url = reqwest::Url::parse(&args.server_url).map_err(|error| error.to_string())?;
    let (remote, remote_events) = StreamableHttpClientTransport::new(
        url,
        StreamableHttpOptions {
            headers: args.headers.clone(),
            ..StreamableHttpOptions::default()
        },
    );
    debug_log("Starting transport directly", &[]);
    remote.start().map_err(|error| error.to_string())?;
    log(
        "Connected to remote server using StreamableHTTPClientTransport",
        &[],
    );

    let (local, local_events) = StdioServerTransport::start_stdio();
    log("Local STDIO server running", &[]);
    log(
        "Proxy established successfully between local STDIO and remote StreamableHTTPClientTransport",
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

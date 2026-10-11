use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rust_mcp_remote::cli::prepare_sign_in;
use rust_mcp_remote::utils::{CommandLineArgs, parse_command_line_args_to};

use crate::test_server::{RecordedRequest, reply, serve};

/// Serializes the tests: each points MCP_REMOTE_CONFIG_DIR at its own directory.
static CONFIG_DIR: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn in_config_dir<T>(test: impl AsyncFnOnce() -> T) -> T {
    let _guard = CONFIG_DIR
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "mcp-remote-prepare-sign-in-{}-{nanos}",
        std::process::id()
    ));
    unsafe { std::env::set_var("MCP_REMOTE_CONFIG_DIR", &directory) };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build runtime");
    let result = runtime.block_on(test());
    drop(runtime);
    unsafe { std::env::remove_var("MCP_REMOTE_CONFIG_DIR") };
    let _ = std::fs::remove_dir_all(&directory);
    result
}

fn command_line(values: &[&str]) -> CommandLineArgs {
    let values = values.iter().map(|value| value.to_string()).collect();
    parse_command_line_args_to(&mut Vec::new(), values, "usage")
        .unwrap()
        .unwrap()
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

fn probes(requests: &mut tokio::sync::mpsc::UnboundedReceiver<RecordedRequest>) -> usize {
    std::iter::from_fn(|| requests.try_recv().ok())
        .filter(|request| request.method == "GET" && request.path == "/mcp")
        .count()
}

#[test]
fn a_server_without_an_auth_challenge_starts_no_sign_in() {
    in_config_dir(async || {
        let (base, mut requests) = serve(Arc::new(|_: &RecordedRequest| reply(404, &[], ""))).await;
        let port = free_port();
        let args = command_line(&[&format!("{base}/mcp"), &port.to_string(), "--allow-http"]);

        let sign_in = prepare_sign_in(&args, "MCP CLI Proxy", false)
            .await
            .unwrap();

        assert!(!sign_in.signs_in_without_a_callback_port);
        assert!(probes(&mut requests) >= 1);
        assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_err());
    });
}

#[test]
fn an_auth_challenge_starts_the_callback_server_until_it_is_closed() {
    in_config_dir(async || {
        let (base, _requests) = serve(Arc::new(|request: &RecordedRequest| {
            if request.path == "/mcp" {
                reply(401, &[("www-authenticate", "Bearer")], "")
            } else {
                reply(404, &[], "")
            }
        }))
        .await;
        let port = free_port();
        let args = command_line(&[&format!("{base}/mcp"), &port.to_string(), "--allow-http"]);

        let sign_in = prepare_sign_in(&args, "MCP CLI Proxy", false)
            .await
            .unwrap();
        assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_ok());

        sign_in.close_owned_auth();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_err());
    });
}

#[test]
fn skipping_the_ownership_check_leaves_the_server_unprobed() {
    in_config_dir(async || {
        let (base, mut requests) = serve(Arc::new(|request: &RecordedRequest| {
            if request.path == "/mcp" {
                reply(401, &[("www-authenticate", "Bearer")], "")
            } else {
                reply(404, &[], "")
            }
        }))
        .await;
        let port = free_port();
        let args = command_line(&[
            &format!("{base}/mcp"),
            &port.to_string(),
            "--allow-http",
            "--device-code",
        ]);
        let discovery_probes = {
            let sign_in = prepare_sign_in(&args, "MCP CLI Proxy", true).await.unwrap();
            assert!(sign_in.signs_in_without_a_callback_port);
            probes(&mut requests)
        };

        let sign_in = prepare_sign_in(&args, "MCP CLI Proxy", false)
            .await
            .unwrap();
        sign_in.close_owned_auth();

        assert_eq!(probes(&mut requests), discovery_probes + 1);
    });
}

#[test]
fn a_discovery_failure_is_returned() {
    in_config_dir(async || {
        let mut args = command_line(&["http://127.0.0.1:9/mcp", "--allow-http"]);
        args.use_client_credentials = true;
        args.token_endpoint = Some("not a url".to_string());

        assert!(prepare_sign_in(&args, "MCP CLI Proxy", true).await.is_err());
    });
}

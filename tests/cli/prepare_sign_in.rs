use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rust_mcp_remote::auth::OAuthClientProvider;
use rust_mcp_remote::cli::prepare_sign_in;
use rust_mcp_remote::mcp_auth_config::write_json_file;
use rust_mcp_remote::utils::{CommandLineArgs, parse_command_line_args_to};
use serde_json::json;

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

#[test]
fn stored_usable_tokens_start_no_sign_in() {
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
        write_json_file(
            &args.server_url_hash,
            "tokens.json",
            &json!({"access_token": "stored", "token_type": "Bearer"}),
        )
        .unwrap();

        let sign_in = prepare_sign_in(&args, "MCP CLI Proxy", false)
            .await
            .unwrap();
        sign_in.close_owned_auth();

        assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_err());
    });
}

#[test]
fn a_stranger_on_the_callback_port_moves_the_redirect_to_the_port_in_use() {
    in_config_dir(async || {
        let (base, _requests) = serve(Arc::new(|request: &RecordedRequest| {
            if request.path == "/mcp" {
                reply(401, &[("www-authenticate", "Bearer")], "")
            } else {
                reply(404, &[], "")
            }
        }))
        .await;
        let (stranger, _stranger_requests) =
            serve(Arc::new(|_: &RecordedRequest| reply(404, &[], ""))).await;
        let stranger_port: u16 = stranger.rsplit(':').next().unwrap().parse().unwrap();
        let mut args = command_line(&[&format!("{base}/mcp"), "--allow-http"]);
        args.callback_port = stranger_port;

        let sign_in = prepare_sign_in(&args, "MCP CLI Proxy", false)
            .await
            .unwrap();
        let redirect_url = sign_in.auth_provider.redirect_url().unwrap();
        sign_in.close_owned_auth();

        let redirect_port: u16 = redirect_url
            .trim_start_matches("http://localhost:")
            .split('/')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert!(redirect_port > stranger_port, "{redirect_url}");
        assert!(redirect_url.ends_with("/oauth/callback"), "{redirect_url}");
    });
}

#[test]
fn the_provider_signs_in_at_the_discovered_authorization_server() {
    in_config_dir(async || {
        let (base, _requests) = serve(Arc::new(|request: &RecordedRequest| {
            let base = format!("http://{}", request.header("host").unwrap());
            match request.path.as_str() {
                "/mcp" => reply(401, &[("www-authenticate", "Bearer")], ""),
                "/.well-known/oauth-protected-resource/mcp" => reply(
                    200,
                    &[("content-type", "application/json")],
                    &json!({
                        "resource": format!("{base}/mcp"),
                        "authorization_servers": [format!("{base}/auth")],
                        "scopes_supported": ["files:read"],
                    })
                    .to_string(),
                ),
                "/.well-known/oauth-authorization-server/auth" => reply(
                    200,
                    &[("content-type", "application/json")],
                    &json!({
                        "issuer": format!("{base}/auth"),
                        "authorization_endpoint": format!("{base}/auth/authorize"),
                        "token_endpoint": format!("{base}/auth/token"),
                        "response_types_supported": ["code"],
                    })
                    .to_string(),
                ),
                _ => reply(404, &[], ""),
            }
        }))
        .await;
        let args = command_line(&[&format!("{base}/mcp"), "--allow-http"]);

        let sign_in = prepare_sign_in(&args, "MCP CLI Client", true)
            .await
            .unwrap();

        let metadata = sign_in.auth_provider.client_metadata();
        assert_eq!(metadata["client_name"], "MCP CLI Client");
        assert_eq!(metadata["scope"], "files:read");
        let server_metadata = sign_in
            .auth_provider
            .get_authorization_server_metadata()
            .await
            .unwrap();
        assert_eq!(server_metadata["issuer"], format!("{base}/auth"));
    });
}

#[test]
fn a_stranger_on_a_port_pinned_on_the_command_line_fails_the_sign_in() {
    in_config_dir(async || {
        let (base, _requests) = serve(Arc::new(|request: &RecordedRequest| {
            if request.path == "/mcp" {
                reply(401, &[("www-authenticate", "Bearer")], "")
            } else {
                reply(404, &[], "")
            }
        }))
        .await;
        let (stranger, _stranger_requests) =
            serve(Arc::new(|_: &RecordedRequest| reply(404, &[], ""))).await;
        let stranger_port = stranger.rsplit(':').next().unwrap();
        let args = command_line(&[&format!("{base}/mcp"), stranger_port, "--allow-http"]);

        let error = prepare_sign_in(&args, "MCP CLI Proxy", false)
            .await
            .err()
            .unwrap();

        assert!(
            error.contains(&format!("Callback port {stranger_port} is already in use")),
            "{error}"
        );
    });
}

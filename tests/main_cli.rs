use std::process::Command;

fn run(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_rust-mcp-remote"))
        .args(arguments)
        .env(
            "MCP_REMOTE_CONFIG_DIR",
            std::env::temp_dir().join("rust-mcp-remote-main-cli"),
        )
        .output()
        .unwrap()
}

const USAGE: &str = "Usage: mcp-remote <https://server-url> [callback-port] [--debug]";

#[test]
fn prints_the_usage_and_exits_with_zero_for_help() {
    let output = run(&["--help"]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!("{USAGE}\n")
    );
}

#[test]
fn prints_the_version_and_exits_with_zero_for_version() {
    let output = run(&["--version"]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(String::from_utf8_lossy(&output.stdout), "0.1.38\n");
}

#[test]
fn logs_the_usage_and_exits_with_one_without_a_server_url() {
    let output = run(&[]);

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).ends_with(&format!("] {USAGE}\n")));
    assert!(output.stdout.is_empty());
}

#[test]
fn logs_a_fatal_error_and_exits_with_one_for_an_invalid_url() {
    let output = run(&["not a url"]);

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("] Fatal error: Invalid URL"));
}

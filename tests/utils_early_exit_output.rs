use rust_mcp_remote::utils::{MCP_REMOTE_VERSION, early_exit_output};

fn arguments(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

#[test]
fn prints_the_usage_for_help() {
    let output = early_exit_output(&arguments(&["https://example.com", "--help"]), "Usage: x");

    assert_eq!(output.as_deref(), Some("Usage: x\n"));
}

#[test]
fn prints_the_usage_for_the_short_help_flag() {
    let output = early_exit_output(&arguments(&["-h"]), "Usage: x");

    assert_eq!(output.as_deref(), Some("Usage: x\n"));
}

#[test]
fn prints_the_version_for_version() {
    let output = early_exit_output(&arguments(&["--version"]), "Usage: x");

    assert_eq!(output, Some(format!("{MCP_REMOTE_VERSION}\n")));
    assert_eq!(MCP_REMOTE_VERSION, "0.1.38");
}

#[test]
fn prefers_help_over_version() {
    let output = early_exit_output(&arguments(&["--version", "--help"]), "Usage: x");

    assert_eq!(output.as_deref(), Some("Usage: x\n"));
}

#[test]
fn does_not_treat_v_as_version() {
    let output = early_exit_output(&arguments(&["https://example.com", "-v"]), "Usage: x");

    assert_eq!(output, None);
}

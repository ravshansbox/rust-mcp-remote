use crate::{arguments, console_text};
use rust_mcp_remote::utils::log_authorize_param_keys_to;

#[test]
fn lists_keys_in_the_order_they_were_first_given() {
    let mut console = Vec::new();

    log_authorize_param_keys_to(
        &mut console,
        &arguments(&[
            "https://example.com",
            "--authorize-param",
            "prompt=consent",
            "--authorize-param",
            " audience =https://api.example.com",
            "--authorize-param",
            "prompt=login",
        ]),
    );

    let pid = std::process::id();
    assert_eq!(
        console_text(console),
        format!("[{pid}] Using extra authorization parameters: prompt, audience\n")
    );
}

#[test]
fn lists_integer_keys_first_in_ascending_order() {
    let mut console = Vec::new();

    log_authorize_param_keys_to(
        &mut console,
        &arguments(&[
            "--authorize-param",
            "b=1",
            "--authorize-param",
            "10=x",
            "--authorize-param",
            "2=y",
            "--authorize-param",
            "01=z",
        ]),
    );

    let pid = std::process::id();
    assert_eq!(
        console_text(console),
        format!("[{pid}] Using extra authorization parameters: 2, 10, b, 01\n")
    );
}

#[test]
fn logs_nothing_without_authorize_params() {
    let mut console = Vec::new();

    log_authorize_param_keys_to(
        &mut console,
        &arguments(&["https://example.com", "--authorize-param"]),
    );

    assert_eq!(console_text(console), "");
}

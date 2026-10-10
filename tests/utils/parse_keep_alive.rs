use rust_mcp_remote::utils::{KeepAliveConfig, parse_keep_alive_to};

fn arguments(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

#[test]
fn keep_alive_is_disabled_by_default_with_thirty_second_interval() {
    let mut console = Vec::new();

    let keep_alive = parse_keep_alive_to(&mut console, &arguments(&["https://example.com"]));

    assert_eq!(
        keep_alive,
        KeepAliveConfig {
            enabled: false,
            interval_ms: 30_000,
        }
    );
    assert!(console.is_empty());
}

#[test]
fn keep_alive_flag_enables_default_interval() {
    let mut console = Vec::new();

    let keep_alive = parse_keep_alive_to(
        &mut console,
        &arguments(&["https://example.com", "--keep-alive"]),
    );

    assert_eq!(
        keep_alive,
        KeepAliveConfig {
            enabled: true,
            interval_ms: 30_000,
        }
    );
}

#[test]
fn ping_interval_implies_keep_alive() {
    let mut console = Vec::new();

    let keep_alive = parse_keep_alive_to(
        &mut console,
        &arguments(&["https://example.com", "--ping-interval", "2.5"]),
    );

    assert_eq!(
        keep_alive,
        KeepAliveConfig {
            enabled: true,
            interval_ms: 2_500,
        }
    );
}

#[test]
fn invalid_ping_interval_warns_and_leaves_keep_alive_off() {
    let mut console = Vec::new();

    let keep_alive = parse_keep_alive_to(
        &mut console,
        &arguments(&["https://example.com", "--ping-interval", "0"]),
    );

    assert_eq!(
        keep_alive,
        KeepAliveConfig {
            enabled: false,
            interval_ms: 30_000,
        }
    );
    let pid = std::process::id();
    assert_eq!(
        String::from_utf8(console).expect("utf8"),
        format!(
            "[{pid}] Warning: Ignoring invalid --ping-interval value: 0. Must be a positive number of seconds.\n"
        )
    );
}

use rust_mcp_remote::utils::parse_seconds_option_to;

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

#[test]
fn warns_about_an_invalid_positive_duration() {
    let mut console = Vec::new();

    let result = parse_seconds_option_to(
        &mut console,
        &args(&["--connect-timeout", "abc"]),
        "--connect-timeout",
        false,
    );

    assert_eq!(result, None);
    assert_eq!(
        String::from_utf8(console).expect("utf8"),
        format!(
            "[{}] Warning: Ignoring invalid --connect-timeout value: abc. Must be a positive number of seconds.\n",
            std::process::id()
        )
    );
}

#[test]
fn warns_about_an_invalid_non_negative_duration() {
    let mut console = Vec::new();

    let result = parse_seconds_option_to(
        &mut console,
        &args(&["--body-timeout", "-1"]),
        "--body-timeout",
        true,
    );

    assert_eq!(result, None);
    assert_eq!(
        String::from_utf8(console).expect("utf8"),
        format!(
            "[{}] Warning: Ignoring invalid --body-timeout value: -1. Must be a non-negative number of seconds.\n",
            std::process::id()
        )
    );
}

#[test]
fn logs_nothing_for_a_valid_or_absent_duration() {
    let mut console = Vec::new();

    let valid = parse_seconds_option_to(
        &mut console,
        &args(&["--connect-timeout", "2"]),
        "--connect-timeout",
        false,
    );
    let absent = parse_seconds_option_to(
        &mut console,
        &args(&["--connect-timeout"]),
        "--connect-timeout",
        false,
    );

    assert_eq!(valid, Some(2000));
    assert_eq!(absent, None);
    assert!(console.is_empty());
}

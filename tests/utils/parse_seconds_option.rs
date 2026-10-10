use rust_mcp_remote::utils::parse_seconds_option;

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

#[test]
fn reads_a_duration_in_seconds_as_milliseconds() {
    assert_eq!(
        parse_seconds_option(
            &args(&["--connect-timeout", "30"]),
            "--connect-timeout",
            false
        ),
        Some(30000)
    );
    assert_eq!(
        parse_seconds_option(
            &args(&["--connect-timeout", "2.5"]),
            "--connect-timeout",
            false
        ),
        Some(2500)
    );
}

#[test]
fn absent_flag_leaves_the_setting_alone() {
    assert_eq!(
        parse_seconds_option(
            &args(&["--transport", "sse-only"]),
            "--connect-timeout",
            false
        ),
        None
    );
    assert_eq!(
        parse_seconds_option(&args(&["--connect-timeout"]), "--connect-timeout", false),
        None
    );
}

#[test]
fn zero_is_accepted_only_where_allowed() {
    assert_eq!(
        parse_seconds_option(&args(&["--body-timeout", "0"]), "--body-timeout", true),
        Some(0)
    );
    assert_eq!(
        parse_seconds_option(
            &args(&["--connect-timeout", "0"]),
            "--connect-timeout",
            false
        ),
        None
    );
}

#[test]
fn rejects_values_that_are_not_durations() {
    assert_eq!(
        parse_seconds_option(
            &args(&["--connect-timeout", "soon"]),
            "--connect-timeout",
            false
        ),
        None
    );
    assert_eq!(
        parse_seconds_option(
            &args(&["--connect-timeout", "-5"]),
            "--connect-timeout",
            false
        ),
        None
    );
    assert_eq!(
        parse_seconds_option(
            &args(&["--body-timeout", "Infinity"]),
            "--body-timeout",
            true
        ),
        None
    );
    assert_eq!(
        parse_seconds_option(&args(&["--body-timeout", "NaN"]), "--body-timeout", true),
        None
    );
}

#[test]
fn reads_numbers_the_way_javascript_does() {
    let parse = |raw: &str| {
        parse_seconds_option(&args(&["--ping-interval", raw]), "--ping-interval", false)
    };
    assert_eq!(parse(" 3 "), Some(3000));
    assert_eq!(parse("1e1"), Some(10000));
    assert_eq!(parse(".5"), Some(500));
    assert_eq!(parse("0x10"), Some(16000));
    assert_eq!(parse("0.0015"), Some(2));
    assert_eq!(parse("inf"), None);
    assert_eq!(parse(""), None);
    assert_eq!(
        parse_seconds_option(&args(&["--body-timeout", ""]), "--body-timeout", true),
        Some(0)
    );
}

#[test]
fn uses_the_first_occurrence_of_the_flag() {
    assert_eq!(
        parse_seconds_option(
            &args(&["--ping-interval", "5", "--ping-interval", "9"]),
            "--ping-interval",
            false
        ),
        Some(5000)
    );
}

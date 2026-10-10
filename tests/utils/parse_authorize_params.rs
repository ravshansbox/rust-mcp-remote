use std::collections::BTreeMap;

use rust_mcp_remote::utils::parse_authorize_params;

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

fn params(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

#[test]
fn collects_repeated_key_value_flags() {
    let result = parse_authorize_params(&args(&[
        "https://example.com/mcp",
        "--authorize-param",
        "access_type=offline",
        "--authorize-param",
        "prompt=consent",
    ]));
    assert_eq!(
        result,
        Ok(params(&[("access_type", "offline"), ("prompt", "consent")]))
    );
}

#[test]
fn only_the_first_equals_sign_separates_key_from_value() {
    let result = parse_authorize_params(&args(&[
        "--authorize-param",
        "audience=https://api.example.com/?a=b",
    ]));
    assert_eq!(
        result,
        Ok(params(&[("audience", "https://api.example.com/?a=b")]))
    );
}

#[test]
fn refuses_parameters_the_flow_derives_per_request() {
    for reserved in [
        "client_id",
        "redirect_uri",
        "response_type",
        "state",
        "code_challenge",
        "code_challenge_method",
    ] {
        let error =
            parse_authorize_params(&args(&["--authorize-param", &format!("{reserved}=abc")]))
                .unwrap_err();
        assert_eq!(
            error,
            format!(
                "--authorize-param cannot set \"{reserved}\": it is part of the authorization flow itself and is derived per request."
            )
        );
    }
}

#[test]
fn rejects_a_value_that_is_not_key_value() {
    for raw in ["audience", "=orphaned"] {
        let error = parse_authorize_params(&args(&["--authorize-param", raw])).unwrap_err();
        assert_eq!(
            error,
            format!(
                "Invalid --authorize-param value: \"{raw}\". Expected key=value, e.g. --authorize-param audience=https://api.example.com"
            )
        );
    }
}

#[test]
fn no_flags_means_no_parameters() {
    assert_eq!(
        parse_authorize_params(&args(&["https://example.com/mcp"])),
        Ok(BTreeMap::new())
    );
}

#[test]
fn trims_the_key_keeps_the_value_and_lets_a_later_flag_win() {
    let result = parse_authorize_params(&args(&[
        "--authorize-param",
        " audience = first ",
        "--authorize-param",
        "prompt=",
        "--authorize-param",
        "audience=second",
        "--authorize-param",
    ]));
    assert_eq!(
        result,
        Ok(params(&[("audience", "second"), ("prompt", "")]))
    );
}

#[test]
fn the_resource_parameter_is_accepted() {
    let result = parse_authorize_params(&args(&[
        "--authorize-param",
        "resource=https://api.example.com",
    ]));
    assert_eq!(
        result,
        Ok(params(&[("resource", "https://api.example.com")]))
    );
}

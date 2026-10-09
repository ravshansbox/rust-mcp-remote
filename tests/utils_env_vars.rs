use rust_mcp_remote::utils::{parse_json_with_env_vars, substitute_env_vars};
use serde_json::json;

fn set_env(name: &str, value: &str) {
    unsafe { std::env::set_var(name, value) }
}

#[test]
fn takes_a_client_secret_from_the_environment() {
    set_env("RMR_TEST_SECRET", "s3cr3t");

    let parsed = parse_json_with_env_vars(
        r#"{"client_id":"c1","client_secret":"${RMR_TEST_SECRET}"}"#,
        "static OAuth client info",
    );

    assert_eq!(
        parsed,
        Ok(json!({ "client_id": "c1", "client_secret": "s3cr3t" }))
    );
}

#[test]
fn replaces_every_placeholder() {
    set_env("RMR_TEST_FIRST", "one");
    set_env("RMR_TEST_SECOND", "two");

    assert_eq!(
        substitute_env_vars(
            "${RMR_TEST_FIRST}-${RMR_TEST_SECOND}-${RMR_TEST_FIRST}",
            "test"
        ),
        "one-two-one"
    );
}

#[test]
fn leaves_a_missing_variable_as_it_is() {
    assert_eq!(
        substitute_env_vars("Bearer ${RMR_TEST_NOT_SET}", "test"),
        "Bearer ${RMR_TEST_NOT_SET}"
    );
}

#[test]
fn does_not_expand_inherited_object_properties() {
    assert_eq!(substitute_env_vars("${toString}", "test"), "${toString}");
}

#[test]
fn leaves_names_the_environment_cannot_hold() {
    assert_eq!(substitute_env_vars("${A=B}", "test"), "${A=B}");
    assert_eq!(substitute_env_vars("${A\0B}", "test"), "${A\0B}");
}

#[test]
fn matches_placeholders_as_the_typescript_pattern_does() {
    set_env("RMR_TEST_NESTED", "x");
    set_env("${RMR_TEST_NESTED", "inner");

    assert_eq!(substitute_env_vars("${}", "test"), "${}");
    assert_eq!(
        substitute_env_vars("${RMR_TEST_NESTED", "test"),
        "${RMR_TEST_NESTED"
    );
    assert_eq!(substitute_env_vars("$${RMR_TEST_NESTED}}", "test"), "$x}");
    assert_eq!(substitute_env_vars("${}${RMR_TEST_NESTED}", "test"), "${}x");
    assert_eq!(
        substitute_env_vars("${${RMR_TEST_NESTED}}", "test"),
        "inner}"
    );
}

#[test]
fn does_not_touch_text_without_placeholders() {
    assert_eq!(
        parse_json_with_env_vars(r#"{"token":"$abc{"}"#, "headers"),
        Ok(json!({ "token": "$abc{" }))
    );
}

#[test]
fn hides_the_parse_error_text() {
    set_env("RMR_TEST_BROKEN", "secret-not-json");

    assert_eq!(
        parse_json_with_env_vars("${RMR_TEST_BROKEN}", "static OAuth client info"),
        Err(
            "Could not parse the static OAuth client info as JSON after expanding its ${...} placeholders"
                .to_string()
        )
    );
    assert_eq!(
        parse_json_with_env_vars("{oops", "static OAuth client metadata"),
        Err("Could not parse the static OAuth client metadata as JSON".to_string())
    );
}

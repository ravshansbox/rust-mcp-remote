use rust_mcp_remote::utils::substitute_env_vars_to;

#[test]
fn logs_each_replaced_placeholder() {
    unsafe { std::env::set_var("RMR_LOG_TEST_TOKEN", "abc") };
    let mut console = Vec::new();

    let result = substitute_env_vars_to(&mut console, "Bearer ${RMR_LOG_TEST_TOKEN}", "headers");

    assert_eq!(result, "Bearer abc");
    assert_eq!(
        String::from_utf8(console).expect("utf8"),
        format!(
            "[{}] Replacing ${{RMR_LOG_TEST_TOKEN}} with environment value in headers\n",
            std::process::id()
        )
    );
}

#[test]
fn warns_about_a_missing_variable() {
    let mut console = Vec::new();

    let result = substitute_env_vars_to(
        &mut console,
        "${RMR_LOG_TEST_MISSING}",
        "static OAuth client info",
    );

    assert_eq!(result, "${RMR_LOG_TEST_MISSING}");
    assert_eq!(
        String::from_utf8(console).expect("utf8"),
        format!(
            "[{}] Warning: Environment variable 'RMR_LOG_TEST_MISSING' not found for static OAuth client info; leaving ${{RMR_LOG_TEST_MISSING}} as it is.\n",
            std::process::id()
        )
    );
}

#[test]
fn logs_nothing_without_placeholders() {
    let mut console = Vec::new();

    let result = substitute_env_vars_to(&mut console, "${} plain", "headers");

    assert_eq!(result, "${} plain");
    assert!(console.is_empty());
}

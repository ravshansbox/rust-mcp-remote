use rust_mcp_remote::utils::extract_header_args_to;

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

fn pairs(values: &[(&str, &str)]) -> Vec<(String, String)> {
    values
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect()
}

#[test]
fn removes_header_flags_and_collects_their_values() {
    let mut args = strings(&[
        "https://example.com/mcp",
        "--header",
        "Authorization: Bearer one",
        "8080",
        "--header",
        "X-Tenant:acme",
        "--header",
        "Authorization:Bearer two",
    ]);
    let mut console = Vec::new();

    let headers = extract_header_args_to(&mut console, &mut args).expect("headers");

    assert_eq!(
        headers,
        pairs(&[("Authorization", "Bearer two"), ("X-Tenant", "acme")])
    );
    assert_eq!(args, strings(&["https://example.com/mcp", "8080"]));
    assert!(console.is_empty());
}

#[test]
fn warns_about_a_malformed_header_without_echoing_it() {
    let mut args = strings(&["https://example.com/mcp", "--header", "secret-token"]);
    let mut console = Vec::new();

    let headers = extract_header_args_to(&mut console, &mut args).expect("headers");

    assert!(headers.is_empty());
    assert_eq!(args, strings(&["https://example.com/mcp"]));
    assert_eq!(
        String::from_utf8(console).expect("utf8"),
        format!(
            "[{}] Warning: ignoring a --header argument that is not in Name:Value form\n",
            std::process::id()
        )
    );
}

#[test]
fn merges_header_file_values_in_argument_order() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mcp-remote-header-args-{}-{nanos}.txt",
        std::process::id()
    ));
    std::fs::write(&path, "Authorization: Bearer file\nX-File: yes\n").expect("write");
    let path_text = path.to_str().expect("path").to_string();
    let mut args = vec![
        "https://example.com/mcp".to_string(),
        "--header".to_string(),
        "Authorization: Bearer flag".to_string(),
        "--header-file".to_string(),
        path_text.clone(),
        "--header".to_string(),
        "X-Last: 1".to_string(),
    ];
    let mut console = Vec::new();

    let headers = extract_header_args_to(&mut console, &mut args).expect("headers");

    assert_eq!(
        headers,
        pairs(&[
            ("Authorization", "Bearer file"),
            ("X-File", "yes"),
            ("X-Last", "1")
        ])
    );
    assert_eq!(args, strings(&["https://example.com/mcp"]));
    assert_eq!(
        String::from_utf8(console).expect("utf8"),
        format!(
            "[{}] Loaded 2 header(s) from {path_text}\n",
            std::process::id()
        )
    );
}

#[test]
fn leaves_a_trailing_flag_without_a_value_in_place() {
    let mut args = strings(&["https://example.com/mcp", "--header"]);
    let mut console = Vec::new();

    let headers = extract_header_args_to(&mut console, &mut args).expect("headers");

    assert!(headers.is_empty());
    assert_eq!(args, strings(&["https://example.com/mcp", "--header"]));
}

#[test]
fn fails_when_a_header_file_cannot_be_read() {
    let mut args = strings(&["--header-file", "/nonexistent/mcp-remote-headers.txt"]);
    let mut console = Vec::new();

    let error = extract_header_args_to(&mut console, &mut args).expect_err("error");

    assert!(
        error.starts_with("Could not read the header file /nonexistent/mcp-remote-headers.txt: ")
    );
}

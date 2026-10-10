use rust_mcp_remote::open_browser::linux_browser_fallbacks;

#[test]
fn lists_the_linux_helpers_in_the_order_they_are_tried() {
    let fallbacks = linux_browser_fallbacks("https://auth.example.com/authorize");

    let commands: Vec<&str> = fallbacks
        .iter()
        .map(|fallback| fallback.command.as_str())
        .collect();
    assert_eq!(
        commands,
        [
            "/usr/bin/xdg-open",
            "gio",
            "x-www-browser",
            "sensible-browser"
        ]
    );
}

#[test]
fn passes_the_url_to_each_helper() {
    let url = "https://auth.example.com/authorize";
    let fallbacks = linux_browser_fallbacks(url);

    let arguments: Vec<Vec<String>> = fallbacks
        .into_iter()
        .map(|fallback| fallback.args)
        .collect();
    assert_eq!(
        arguments,
        [
            vec![url.to_string()],
            vec!["open".to_string(), url.to_string()],
            vec![url.to_string()],
            vec![url.to_string()],
        ]
    );
}

use rust_mcp_remote::open_browser::{BrowserFallback, bundled_opener, open_browser_with};

const URL: &str = "https://example.com/authorize";

fn recording_launcher(
    results: Vec<bool>,
    calls: &mut Vec<(String, Vec<String>)>,
) -> impl FnMut(&str, &[String]) -> bool + '_ {
    let mut results = results.into_iter();
    move |command, args| {
        calls.push((command.to_string(), args.to_vec()));
        results.next().unwrap_or(false)
    }
}

#[test]
fn uses_open_on_macos() {
    assert_eq!(
        bundled_opener(URL, "macos"),
        BrowserFallback {
            command: "open".to_string(),
            args: vec![URL.to_string()],
        }
    );
}

#[test]
fn uses_cmd_start_on_windows() {
    assert_eq!(
        bundled_opener(URL, "windows"),
        BrowserFallback {
            command: "cmd".to_string(),
            args: vec![
                "/c".to_string(),
                "start".to_string(),
                "\"\"".to_string(),
                URL.to_string()
            ],
        }
    );
}

#[test]
fn uses_xdg_open_on_linux() {
    assert_eq!(
        bundled_opener(URL, "linux"),
        BrowserFallback {
            command: "xdg-open".to_string(),
            args: vec![URL.to_string()],
        }
    );
}

#[test]
fn stops_after_the_bundled_opener_launches() {
    let mut calls = Vec::new();
    assert!(open_browser_with(
        URL,
        "linux",
        recording_launcher(vec![true], &mut calls)
    ));
    assert_eq!(calls, vec![("xdg-open".to_string(), vec![URL.to_string()])]);
}

#[test]
fn does_not_try_fallbacks_outside_linux() {
    let mut calls = Vec::new();
    assert!(!open_browser_with(
        URL,
        "macos",
        recording_launcher(vec![false], &mut calls)
    ));
    assert_eq!(calls, vec![("open".to_string(), vec![URL.to_string()])]);
}

#[test]
fn tries_linux_fallbacks_in_order_until_one_launches() {
    let mut calls = Vec::new();
    assert!(open_browser_with(
        URL,
        "linux",
        recording_launcher(vec![false, false, true], &mut calls)
    ));
    let commands: Vec<&str> = calls.iter().map(|(command, _)| command.as_str()).collect();
    assert_eq!(commands, vec!["xdg-open", "/usr/bin/xdg-open", "gio"]);
    assert_eq!(calls[2].1, vec!["open".to_string(), URL.to_string()]);
}

#[test]
fn reports_failure_when_every_linux_helper_fails() {
    let mut calls = Vec::new();
    assert!(!open_browser_with(
        URL,
        "linux",
        recording_launcher(vec![], &mut calls)
    ));
    let commands: Vec<&str> = calls.iter().map(|(command, _)| command.as_str()).collect();
    assert_eq!(
        commands,
        vec![
            "xdg-open",
            "/usr/bin/xdg-open",
            "gio",
            "x-www-browser",
            "sensible-browser"
        ]
    );
}

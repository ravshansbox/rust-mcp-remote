use serde_json::{Map, Value};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserFallback {
    pub command: String,
    pub args: Vec<String>,
}

pub fn linux_browser_fallbacks(url: &str) -> Vec<BrowserFallback> {
    let fallback = |command: &str, args: &[&str]| BrowserFallback {
        command: command.to_string(),
        args: args.iter().map(|argument| argument.to_string()).collect(),
    };
    vec![
        fallback("/usr/bin/xdg-open", &[url]),
        fallback("gio", &["open", url]),
        fallback("x-www-browser", &[url]),
        fallback("sensible-browser", &[url]),
    ]
}

pub fn browser_launch_environment_details(lookup: impl Fn(&str) -> Option<String>) -> Value {
    let mut details = Map::new();
    if let Some(display) = lookup("DISPLAY") {
        details.insert("DISPLAY".to_string(), Value::from(display));
    }
    if let Some(wayland_display) = lookup("WAYLAND_DISPLAY") {
        details.insert("WAYLAND_DISPLAY".to_string(), Value::from(wayland_display));
    }
    if lookup("DBUS_SESSION_BUS_ADDRESS").is_some_and(|address| !address.is_empty()) {
        details.insert("DBUS_SESSION_BUS_ADDRESS".to_string(), Value::from("set"));
    }
    if let Some(browser) = lookup("BROWSER") {
        details.insert("BROWSER".to_string(), Value::from(browser));
    }
    Value::Object(details)
}

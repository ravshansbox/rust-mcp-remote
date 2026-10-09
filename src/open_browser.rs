use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};

use crate::logging::{debug_log, log};

pub const HELPER_SETTLE_MS: u64 = 500;

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

pub fn launch_helper(command: &str, args: &[String]) -> bool {
    let mut child = match Command::new(command)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            debug_log(
                &format!("Browser helper {command} failed to start"),
                &[Value::from(error.to_string())],
            );
            return false;
        }
    };
    let deadline = Instant::now() + Duration::from_millis(HELPER_SETTLE_MS);
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(status)) => {
                debug_log(
                    &format!("Browser helper {command} exited"),
                    &[json!({ "code": status.code() })],
                );
                return status.success();
            }
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(error) => {
                debug_log(
                    &format!("Browser helper {command} failed to start"),
                    &[Value::from(error.to_string())],
                );
                return false;
            }
        }
    }
    debug_log(
        &format!("Browser helper {command} is still running, treating it as the browser"),
        &[],
    );
    true
}

pub fn bundled_opener(url: &str, os: &str) -> BrowserFallback {
    let (command, args): (&str, Vec<&str>) = match os {
        "macos" => ("open", vec![url]),
        "windows" => ("cmd", vec!["/c", "start", "\"\"", url]),
        _ => ("xdg-open", vec![url]),
    };
    BrowserFallback {
        command: command.to_string(),
        args: args.iter().map(|argument| argument.to_string()).collect(),
    }
}

pub fn open_browser_with(
    url: &str,
    os: &str,
    mut launch: impl FnMut(&str, &[String]) -> bool,
) -> bool {
    debug_log(
        "Browser launch environment",
        &[browser_launch_environment_details(|name| {
            std::env::var(name).ok()
        })],
    );
    let opener = bundled_opener(url, os);
    if launch(&opener.command, &opener.args) {
        return true;
    }
    if os != "linux" {
        return false;
    }
    for fallback in linux_browser_fallbacks(url) {
        log(
            &format!("Trying {} to open the browser...", fallback.command),
            &[],
        );
        if launch(&fallback.command, &fallback.args) {
            return true;
        }
    }
    false
}

pub fn open_browser(url: &str) -> bool {
    open_browser_with(url, std::env::consts::OS, launch_helper)
}

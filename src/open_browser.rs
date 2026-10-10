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
    if os == "windows" {
        return powershell_start(url);
    }
    let (command, args): (&str, Vec<&str>) = match os {
        "macos" => ("open", vec![url]),
        _ => ("xdg-open", vec![url]),
    };
    BrowserFallback {
        command: command.to_string(),
        args: args.iter().map(|argument| argument.to_string()).collect(),
    }
}

/// What the `open` package runs on Windows: PowerShell's `Start`, handed over as an encoded
/// command so that `&` and the rest of a query string reach it intact.
fn powershell_start(url: &str) -> BrowserFallback {
    use base64::Engine;

    let system_root = std::env::var("SYSTEMROOT")
        .or_else(|_| std::env::var("windir"))
        .unwrap_or_else(|_| r"C:\Windows".to_string());
    let command: Vec<u8> = format!("Start \"{url}\"")
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    BrowserFallback {
        command: format!(r"{system_root}\System32\WindowsPowerShell\v1.0\powershell.exe"),
        args: [
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
        ]
        .iter()
        .map(|argument| argument.to_string())
        .chain([base64::engine::general_purpose::STANDARD.encode(command)])
        .collect(),
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

/// JavaScript's encodeURIComponent.
pub fn encode_uri_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&byte) {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

/// strict-url-sanitise's sanitizeUrl: only http(s) URLs with a plain hostname get through, and
/// every other component is re-encoded so nothing in it can reach the opener as syntax.
pub fn sanitize_url(raw: &str) -> Result<String, String> {
    let invalid = || format!("Invalid url to pass to open(): {raw}");
    let mut url = url::Url::parse(raw).map_err(|_| invalid())?;
    if url.scheme() != "https" && url.scheme() != "http" {
        return Err(invalid());
    }
    let hostname = url.host_str().unwrap_or_default().to_owned();
    if hostname != encode_uri_component(&hostname) {
        return Err(invalid());
    }
    if !url.username().is_empty() {
        let username = encode_uri_component(url.username());
        url.set_username(&username).map_err(|_| invalid())?;
    }
    if let Some(password) = url.password().filter(|password| !password.is_empty()) {
        let password = encode_uri_component(password);
        url.set_password(Some(&password)).map_err(|_| invalid())?;
    }
    let path = url.path().to_owned();
    let (first, rest) = path.split_at(path.len().min(1));
    let path = format!(
        "{first}{}",
        encode_uri_component(rest)
            .replace("%2F", "/")
            .replace("%2f", "/")
    );
    url.set_path(&path);
    if url.query().is_some_and(|query| !query.is_empty()) {
        let query = url
            .query_pairs()
            .map(|(key, value)| {
                if value.is_empty() {
                    encode_uri_component(&key)
                } else {
                    format!(
                        "{}={}",
                        encode_uri_component(&key),
                        encode_uri_component(&value)
                    )
                }
            })
            .collect::<Vec<_>>()
            .join("&");
        url.set_query(Some(&query));
    } else {
        url.set_query(None);
    }
    match url.fragment().map(str::to_owned) {
        Some(fragment) if !fragment.is_empty() => {
            url.set_fragment(Some(&encode_uri_component(&fragment)))
        }
        _ => url.set_fragment(None),
    }
    Ok(url.to_string())
}

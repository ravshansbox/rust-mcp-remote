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

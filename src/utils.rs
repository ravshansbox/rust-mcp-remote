use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::logging::log_to;

pub const DEFAULT_CALLBACK_PATH: &str = "/oauth/callback";
pub const MCP_REMOTE_ID_PATH: &str = "/.mcp-remote/id";
pub const MCP_REMOTE_VERSION: &str = "0.1.38";
const LONG_POLL_PATH: &str = "/wait-for-auth";

const BASE64_SENTINEL_PREFIX: &str = "=?base64?";
const BASE64_SENTINEL_SUFFIX: &str = "?=";
const RESERVED_AUTHORIZE_PARAMS: [&str; 6] = [
    "client_id",
    "redirect_uri",
    "response_type",
    "state",
    "code_challenge",
    "code_challenge_method",
];

#[derive(Debug, PartialEq, Eq)]
pub struct MirroredMcpHeaders {
    pub method: String,
    pub name: Option<String>,
}

fn mcp_name_source(method: &str) -> Option<&'static str> {
    match method {
        "tools/call" | "prompts/get" => Some("name"),
        "resources/read" => Some("uri"),
        _ => None,
    }
}

pub fn mcp_headers_from_body(body: &str) -> Option<MirroredMcpHeaders> {
    let message: serde_json::Value = serde_json::from_str(body).ok()?;
    let method = message.as_object()?.get("method")?.as_str()?;
    if method.is_empty() {
        return None;
    }

    let name = mcp_name_source(method)
        .and_then(|source| message.get("params")?.as_object()?.get(source)?.as_str())
        .filter(|name| !name.is_empty())
        .map(str::to_string);

    Some(MirroredMcpHeaders {
        method: method.to_string(),
        name,
    })
}

pub fn encode_mcp_header_value(value: &str) -> String {
    let visible = |byte: &u8| (0x21..=0x7e).contains(byte);
    let bytes = value.as_bytes();
    let header_safe = bytes.first().is_some_and(visible)
        && bytes.last().is_some_and(visible)
        && bytes
            .iter()
            .all(|byte| (0x20..=0x7e).contains(byte) || *byte == b'\t');
    let looks_encoded =
        value.starts_with(BASE64_SENTINEL_PREFIX) && value.ends_with(BASE64_SENTINEL_SUFFIX);

    if header_safe && !looks_encoded {
        value.to_string()
    } else {
        format!(
            "{BASE64_SENTINEL_PREFIX}{}{BASE64_SENTINEL_SUFFIX}",
            STANDARD.encode(value)
        )
    }
}

pub fn calculate_default_port(server_url_hash: &str) -> Option<u16> {
    let hex_prefix: String = server_url_hash
        .chars()
        .take(4)
        .take_while(char::is_ascii_hexdigit)
        .collect();
    let offset = u16::from_str_radix(&hex_prefix, 16).ok()?;
    Some(3335 + offset % 45816)
}

pub fn select_callback_port_to(
    console: &mut impl std::io::Write,
    specified_port: Option<u16>,
    default_port: u16,
) -> u16 {
    match specified_port.filter(|port| *port != 0) {
        Some(port) => {
            log_to(
                console,
                &format!("Using specified callback port: {port}"),
                &[],
            );
            port
        }
        None => {
            log_to(
                console,
                &format!("Using callback port derived from the server URL: {default_port}"),
                &[],
            );
            default_port
        }
    }
}

pub fn build_redirect_url(host: &str, port: u16, callback_path: &str) -> String {
    format!("http://{host}:{port}{callback_path}")
}

#[derive(serde::Deserialize)]
struct ClientRegistration {
    #[allow(dead_code)]
    client_id: String,
    redirect_uris: Vec<String>,
}

pub fn invalidate_mismatched_client_registration(server_url_hash: &str, redirect_url: &str) {
    invalidate_mismatched_client_registration_to(
        &mut std::io::stderr(),
        server_url_hash,
        redirect_url,
    )
}

pub fn invalidate_mismatched_client_registration_to(
    console: &mut impl std::io::Write,
    server_url_hash: &str,
    redirect_url: &str,
) {
    let Some(client_info) = crate::mcp_auth_config::read_json_file::<ClientRegistration>(
        server_url_hash,
        "client_info.json",
    ) else {
        return;
    };
    if client_info
        .redirect_uris
        .iter()
        .any(|uri| uri == redirect_url)
    {
        return;
    }
    log_to(
        console,
        &format!(
            "Cached client registration is for {} but this session will use {redirect_url}. Deleting it so the client re-registers.",
            client_info.redirect_uris.join(", ")
        ),
        &[],
    );
    crate::mcp_auth_config::delete_config_file(server_url_hash, "client_info.json");
}

pub fn parse_authorize_params(args: &[String]) -> Result<BTreeMap<String, String>, String> {
    parse_authorize_params_to(&mut std::io::stderr(), args)
}

pub fn parse_authorize_params_to(
    console: &mut impl std::io::Write,
    args: &[String],
) -> Result<BTreeMap<String, String>, String> {
    let mut params = BTreeMap::new();
    for pair in args.windows(2) {
        if pair[0] != "--authorize-param" {
            continue;
        }
        let raw = &pair[1];
        let (key, value) = match raw.split_once('=') {
            Some((key, value)) if !key.is_empty() => (key.trim(), value),
            _ => {
                return Err(format!(
                    "Invalid --authorize-param value: \"{raw}\". Expected key=value, e.g. --authorize-param audience=https://api.example.com"
                ));
            }
        };
        if RESERVED_AUTHORIZE_PARAMS.contains(&key) {
            return Err(format!(
                "--authorize-param cannot set \"{key}\": it is part of the authorization flow itself and is derived per request."
            ));
        }
        if key == "resource" {
            log_to(
                console,
                "Warning: --authorize-param resource=... only applies to the authorization request. Use --resource so the token request agrees.",
                &[],
            );
        }
        params.insert(key.to_string(), value.to_string());
    }
    Ok(params)
}

pub fn log_authorize_param_keys_to(console: &mut impl std::io::Write, args: &[String]) {
    let mut keys: Vec<&str> = Vec::new();
    for pair in args.windows(2) {
        if pair[0] != "--authorize-param" {
            continue;
        }
        if let Some((key, _)) = pair[1].split_once('=') {
            let key = key.trim();
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
    }
    if keys.is_empty() {
        return;
    }
    let array_index = |key: &str| {
        key.parse::<u32>()
            .ok()
            .filter(|index| *index != u32::MAX && index.to_string() == key)
    };
    let (mut integer_keys, string_keys): (Vec<&str>, Vec<&str>) =
        keys.into_iter().partition(|key| array_index(key).is_some());
    integer_keys.sort_by_key(|key| array_index(key));
    integer_keys.extend(string_keys);
    log_to(
        console,
        &format!(
            "Using extra authorization parameters: {}",
            integer_keys.join(", ")
        ),
        &[],
    );
}

pub fn parse_seconds_option(args: &[String], flag: &str, allow_zero: bool) -> Option<u64> {
    parse_seconds_option_to(&mut std::io::stderr(), args, flag, allow_zero)
}

pub fn parse_seconds_option_to(
    console: &mut impl std::io::Write,
    args: &[String],
    flag: &str,
    allow_zero: bool,
) -> Option<u64> {
    let index = args.iter().position(|arg| arg == flag)?;
    let raw = args.get(index + 1)?;
    let seconds = javascript_number(raw);
    if !seconds.is_finite() || seconds < 0.0 || (seconds == 0.0 && !allow_zero) {
        let expected = if allow_zero {
            "non-negative"
        } else {
            "positive"
        };
        log_to(
            console,
            &format!(
                "Warning: Ignoring invalid {flag} value: {raw}. Must be a {expected} number of seconds."
            ),
            &[],
        );
        return None;
    }
    Some((seconds * 1000.0).round() as u64)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkOptions {
    pub connect_timeout_ms: Option<u64>,
    pub body_timeout_ms: Option<u64>,
    pub headers_timeout_ms: Option<u64>,
    pub force_ipv4: bool,
}

pub fn parse_network_options_to(
    console: &mut impl std::io::Write,
    args: &[String],
) -> NetworkOptions {
    let options = NetworkOptions {
        connect_timeout_ms: parse_seconds_option_to(console, args, "--connect-timeout", false),
        body_timeout_ms: parse_seconds_option_to(console, args, "--body-timeout", true),
        headers_timeout_ms: parse_seconds_option_to(console, args, "--headers-timeout", true),
        force_ipv4: args.iter().any(|arg| arg == "--ipv4"),
    };
    let describe = |milliseconds: u64| match milliseconds {
        0 => "disabled".to_string(),
        _ => format!("{} seconds", milliseconds as f64 / 1000.0),
    };
    if options.force_ipv4 {
        log_to(console, "Restricting connections to IPv4", &[]);
    }
    if let Some(milliseconds) = options.connect_timeout_ms {
        log_to(
            console,
            &format!(
                "Using connect timeout: {} seconds",
                milliseconds as f64 / 1000.0
            ),
            &[],
        );
    }
    if let Some(milliseconds) = options.body_timeout_ms {
        log_to(
            console,
            &format!("Using body timeout: {}", describe(milliseconds)),
            &[],
        );
    }
    if let Some(milliseconds) = options.headers_timeout_ms {
        log_to(
            console,
            &format!("Using headers timeout: {}", describe(milliseconds)),
            &[],
        );
    }
    options
}

pub fn parse_enable_proxy_to(console: &mut impl std::io::Write, args: &[String]) -> bool {
    let enable_proxy = args.iter().any(|arg| arg == "--enable-proxy");
    if enable_proxy {
        log_to(
            console,
            "HTTP proxy support enabled - using system HTTP_PROXY/HTTPS_PROXY environment variables",
            &[],
        );
    }
    enable_proxy
}

const DEFAULT_KEEP_ALIVE_INTERVAL_MS: u64 = 30_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeepAliveConfig {
    pub enabled: bool,
    pub interval_ms: u64,
}

pub fn parse_keep_alive_to(console: &mut impl std::io::Write, args: &[String]) -> KeepAliveConfig {
    let ping_interval_ms = parse_seconds_option_to(console, args, "--ping-interval", false);
    KeepAliveConfig {
        enabled: args.iter().any(|arg| arg == "--keep-alive") || ping_interval_ms.is_some(),
        interval_ms: ping_interval_ms.unwrap_or(DEFAULT_KEEP_ALIVE_INTERVAL_MS),
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TransportStrategy {
    SseOnly,
    HttpOnly,
    SseFirst,
    #[default]
    HttpFirst,
}

impl TransportStrategy {
    pub fn as_str(self) -> &'static str {
        match self {
            TransportStrategy::SseOnly => "sse-only",
            TransportStrategy::HttpOnly => "http-only",
            TransportStrategy::SseFirst => "sse-first",
            TransportStrategy::HttpFirst => "http-first",
        }
    }
}

pub fn parse_transport_strategy_to(
    console: &mut impl std::io::Write,
    args: &[String],
) -> TransportStrategy {
    let Some(raw) = args
        .iter()
        .position(|arg| arg == "--transport")
        .and_then(|index| args.get(index + 1))
    else {
        return TransportStrategy::default();
    };
    let strategy = [
        TransportStrategy::SseOnly,
        TransportStrategy::HttpOnly,
        TransportStrategy::SseFirst,
        TransportStrategy::HttpFirst,
    ]
    .into_iter()
    .find(|strategy| strategy.as_str() == raw);
    match strategy {
        Some(strategy) => {
            log_to(
                console,
                &format!("Using transport strategy: {}", strategy.as_str()),
                &[],
            );
            strategy
        }
        None => {
            log_to(
                console,
                &format!(
                    "Warning: Ignoring invalid transport strategy: {raw}. Valid values are: sse-only, http-only, sse-first, http-first"
                ),
                &[],
            );
            TransportStrategy::default()
        }
    }
}

pub fn parse_protocol_mode_to(
    console: &mut impl std::io::Write,
    args: &[String],
) -> crate::protocol_era::ProtocolMode {
    use crate::protocol_era::ProtocolMode;
    let Some(raw) = args
        .iter()
        .position(|arg| arg == "--protocol")
        .and_then(|index| args.get(index + 1))
    else {
        return ProtocolMode::default();
    };
    match [ProtocolMode::Legacy, ProtocolMode::Auto]
        .into_iter()
        .find(|mode| mode.as_str() == raw)
    {
        Some(mode) => {
            log_to(
                console,
                &format!("Using protocol mode: {}", mode.as_str()),
                &[],
            );
            mode
        }
        None => {
            log_to(
                console,
                &format!(
                    "Warning: Ignoring invalid protocol mode: {raw}. Valid values are: legacy, auto"
                ),
                &[],
            );
            ProtocolMode::default()
        }
    }
}

pub fn parse_callback_host_to(console: &mut impl std::io::Write, args: &[String]) -> String {
    match args
        .iter()
        .position(|arg| arg == "--host")
        .and_then(|index| args.get(index + 1))
    {
        Some(host) => {
            log_to(console, &format!("Using callback hostname: {host}"), &[]);
            host.clone()
        }
        None if cfg!(windows) => "127.0.0.1".to_string(),
        None => "localhost".to_string(),
    }
}

pub fn parse_callback_path_to(console: &mut impl std::io::Write, args: &[String]) -> String {
    let Some(value) = args
        .iter()
        .position(|arg| arg == "--callback-path")
        .and_then(|index| args.get(index + 1))
    else {
        return DEFAULT_CALLBACK_PATH.to_string();
    };
    if !value.starts_with('/') {
        log_to(
            console,
            &format!("Warning: Ignoring invalid callback path: {value}. It must start with '/'."),
            &[],
        );
        DEFAULT_CALLBACK_PATH.to_string()
    } else if value == LONG_POLL_PATH || value == MCP_REMOTE_ID_PATH {
        log_to(
            console,
            &format!(
                "Warning: Ignoring reserved callback path: {value}. It is used to coordinate concurrent instances."
            ),
            &[],
        );
        DEFAULT_CALLBACK_PATH.to_string()
    } else {
        log_to(console, &format!("Using callback path: {value}"), &[]);
        value.clone()
    }
}

pub fn parse_static_oauth_client_metadata_to(
    console: &mut impl std::io::Write,
    args: &[String],
) -> Result<Option<serde_json::Value>, String> {
    let Some(value) = args
        .iter()
        .position(|arg| arg == "--static-oauth-client-metadata")
        .and_then(|index| args.get(index + 1))
    else {
        return Ok(None);
    };
    if let Some(file_path) = value.strip_prefix('@') {
        let contents = std::fs::read_to_string(file_path).map_err(|error| error.to_string())?;
        let metadata = serde_json::from_str(&contents).map_err(|error| error.to_string())?;
        log_to(
            console,
            &format!("Using static OAuth client metadata from file: {file_path}"),
            &[],
        );
        Ok(Some(metadata))
    } else {
        let metadata = serde_json::from_str(value).map_err(|error| error.to_string())?;
        log_to(
            console,
            "Using static OAuth client metadata from string",
            &[],
        );
        Ok(Some(metadata))
    }
}

pub fn parse_static_oauth_client_info_to(
    console: &mut impl std::io::Write,
    args: &[String],
) -> Result<Option<serde_json::Value>, String> {
    let Some(value) = args
        .iter()
        .position(|arg| arg == "--static-oauth-client-info")
        .and_then(|index| args.get(index + 1))
    else {
        return Ok(None);
    };
    let context = "static OAuth client information";
    if let Some(file_path) = value.strip_prefix('@') {
        let contents = std::fs::read_to_string(file_path).map_err(|error| error.to_string())?;
        let information = parse_json_with_env_vars(&contents, context)?;
        log_to(
            console,
            &format!("Using static OAuth client information from file: {file_path}"),
            &[],
        );
        Ok(Some(information))
    } else {
        let information = parse_json_with_env_vars(value, context)?;
        log_to(
            console,
            "Using static OAuth client information from string",
            &[],
        );
        Ok(Some(information))
    }
}

fn javascript_number(raw: &str) -> f64 {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return 0.0;
    }
    let radix_digits = [
        ("0x", 16),
        ("0X", 16),
        ("0o", 8),
        ("0O", 8),
        ("0b", 2),
        ("0B", 2),
    ]
    .into_iter()
    .find_map(|(prefix, radix)| trimmed.strip_prefix(prefix).map(|digits| (digits, radix)));
    if let Some((digits, radix)) = radix_digits {
        return u64::from_str_radix(digits, radix).map_or(f64::NAN, |value| value as f64);
    }
    trimmed.parse().unwrap_or(f64::NAN)
}

pub fn parse_header_line(line: &str) -> Option<(String, String)> {
    let (name, rest) = line.split_once(':')?;
    let valid_name = !name.is_empty()
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'));
    let value = rest.trim_start_matches(is_javascript_whitespace);
    if !valid_name || value.contains(is_line_terminator) {
        return None;
    }
    Some((name.to_string(), value.to_string()))
}

pub fn read_header_file(file_path: &str) -> Result<Vec<(String, String)>, String> {
    read_header_file_to(&mut std::io::stderr(), file_path)
}

pub fn read_header_file_to(
    console: &mut impl std::io::Write,
    file_path: &str,
) -> Result<Vec<(String, String)>, String> {
    let contents = std::fs::read_to_string(file_path)
        .map_err(|error| format!("Could not read the header file {file_path}: {error}"))?;
    let mut headers: Vec<(String, String)> = Vec::new();
    for (index, line) in contents.split('\n').enumerate() {
        let trimmed = line.trim_matches(is_javascript_whitespace);
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((name, value)) = parse_header_line(trimmed) else {
            log_to(
                console,
                &format!(
                    "Warning: ignoring line {} of {file_path}, which is not in Name:Value form",
                    index + 1
                ),
                &[],
            );
            continue;
        };
        insert_header(&mut headers, name, value);
    }
    log_to(
        console,
        &format!("Loaded {} header(s) from {file_path}", headers.len()),
        &[],
    );
    Ok(headers)
}

fn insert_header(headers: &mut Vec<(String, String)>, name: String, value: String) {
    match headers.iter_mut().find(|(existing, _)| *existing == name) {
        Some(entry) => entry.1 = value,
        None => headers.push((name, value)),
    }
}

pub fn extract_header_args_to(
    console: &mut impl std::io::Write,
    args: &mut Vec<String>,
) -> Result<Vec<(String, String)>, String> {
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut index = 0;
    while index < args.len() {
        if args[index] == "--header" && index + 1 < args.len() {
            match parse_header_line(&args[index + 1]) {
                Some((name, value)) => insert_header(&mut headers, name, value),
                None => log_to(
                    console,
                    "Warning: ignoring a --header argument that is not in Name:Value form",
                    &[],
                ),
            }
            args.drain(index..index + 2);
            continue;
        }
        if args[index] == "--header-file" && index + 1 < args.len() {
            for (name, value) in read_header_file_to(console, &args[index + 1])? {
                insert_header(&mut headers, name, value);
            }
            args.drain(index..index + 2);
            continue;
        }
        index += 1;
    }
    Ok(headers)
}

pub fn finalise_headers_to(
    console: &mut impl std::io::Write,
    headers: Vec<(String, String)>,
) -> Vec<(String, String)> {
    if !headers.is_empty() {
        let names: Vec<&str> = headers.iter().map(|(name, _)| name.as_str()).collect();
        log_to(
            console,
            &format!("Using custom headers: {}", names.join(", ")),
            &[],
        );
    }
    headers
        .into_iter()
        .map(|(name, value)| {
            let value = substitute_env_vars_to(console, &value, &format!("header '{name}'"));
            (name, value)
        })
        .collect()
}

fn is_javascript_whitespace(character: char) -> bool {
    matches!(
        character,
        '\t' | '\u{b}' | '\u{c}' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}'
    ) || is_line_terminator(character)
}

pub fn should_include_tool(ignore_patterns: &[String], tool_name: &str) -> bool {
    !ignore_patterns
        .iter()
        .any(|pattern| glob_matches(pattern, tool_name))
}

fn glob_matches(pattern: &str, text: &str) -> bool {
    let pattern: Vec<Option<char>> = pattern
        .chars()
        .map(|character| (character != '*').then(|| javascript_canonical_case(character)))
        .collect();
    let text: Vec<char> = text.chars().map(javascript_canonical_case).collect();
    let mut matched = vec![false; text.len() + 1];
    matched[0] = true;
    for token in pattern {
        let mut next = vec![false; text.len() + 1];
        match token {
            None => {
                next[0] = matched[0];
                for index in 0..text.len() {
                    next[index + 1] =
                        matched[index + 1] || (next[index] && !is_line_terminator(text[index]));
                }
            }
            Some(expected) => {
                for index in 0..text.len() {
                    next[index + 1] = matched[index] && text[index] == expected;
                }
            }
        }
        matched = next;
    }
    matched[text.len()]
}

fn is_line_terminator(character: char) -> bool {
    matches!(character, '\n' | '\r' | '\u{2028}' | '\u{2029}')
}

fn javascript_canonical_case(character: char) -> char {
    let mut upper = character.to_uppercase();
    match (upper.next(), upper.next()) {
        (Some(single), None) if character.is_ascii() || !single.is_ascii() => single,
        _ => character,
    }
}

pub fn merge_headers(sources: &[&[(&str, &str)]]) -> Vec<(String, String)> {
    let mut merged: Vec<(String, (String, String))> = Vec::new();
    for (name, value) in sources.iter().flat_map(|source| source.iter()) {
        let key = name.to_lowercase();
        let entry = (name.to_string(), value.to_string());
        match merged.iter_mut().find(|(existing, _)| *existing == key) {
            Some((_, slot)) => *slot = entry,
            None => merged.push((key, entry)),
        }
    }
    merged.into_iter().map(|(_, entry)| entry).collect()
}

pub fn is_client_metadata_url(value: &str) -> bool {
    url::Url::parse(value).is_ok_and(|url| url.scheme() == "https" && url.path() != "/")
}

pub fn parse_client_metadata_url_to(
    console: &mut impl std::io::Write,
    args: &[String],
) -> Option<String> {
    let value = args
        .iter()
        .position(|arg| arg == "--client-metadata-url")
        .and_then(|index| args.get(index + 1))?
        .trim();
    if is_client_metadata_url(value) {
        log_to(
            console,
            &format!("Using client metadata document: {value}"),
            &[],
        );
        Some(value.to_string())
    } else {
        log_to(
            console,
            &format!(
                "Warning: Ignoring invalid client metadata URL: {value}. It must be an HTTPS URL with a path."
            ),
            &[],
        );
        None
    }
}

fn parse_flag_to(
    console: &mut impl std::io::Write,
    args: &[String],
    flag: &str,
    message: &str,
) -> bool {
    let present = args.iter().any(|arg| arg == flag);
    if present {
        log_to(console, message, &[]);
    }
    present
}

pub fn parse_cookies_enabled_to(console: &mut impl std::io::Write, args: &[String]) -> bool {
    !parse_flag_to(
        console,
        args,
        "--disable-cookies",
        "Cookies disabled; requests will not carry session stickiness",
    )
}

pub fn parse_device_code_to(console: &mut impl std::io::Write, args: &[String]) -> bool {
    parse_flag_to(
        console,
        args,
        "--device-code",
        "Using the OAuth device grant; no browser will be opened on this machine",
    )
}

pub fn parse_client_credentials_to(console: &mut impl std::io::Write, args: &[String]) -> bool {
    parse_flag_to(
        console,
        args,
        "--client-credentials",
        "Using the OAuth client_credentials grant; no browser will be opened and no user will be asked",
    )
}

pub fn parse_token_endpoint_to(
    console: &mut impl std::io::Write,
    args: &[String],
    use_client_credentials: bool,
) -> Result<Option<String>, String> {
    let Some(index) = args.iter().position(|arg| arg == "--token-endpoint") else {
        return Ok(None);
    };
    let value = match args.get(index + 1) {
        Some(value) if !value.starts_with("--") => value.trim(),
        _ => return Err("--token-endpoint requires an HTTPS URL".to_string()),
    };
    if !use_client_credentials {
        return Err("--token-endpoint can only be used with --client-credentials".to_string());
    }
    let endpoint = url::Url::parse(value)
        .map_err(|_| "Invalid --token-endpoint value. Expected an HTTPS URL.".to_string())?;
    let is_loopback = endpoint.scheme() == "http"
        && matches!(
            endpoint.host_str(),
            Some("localhost" | "127.0.0.1" | "[::1]")
        );
    if endpoint.scheme() != "https" && !is_loopback {
        return Err(
            "--token-endpoint must use HTTPS, except for an HTTP loopback endpoint".to_string(),
        );
    }
    if !endpoint.username().is_empty()
        || endpoint
            .password()
            .is_some_and(|password| !password.is_empty())
        || endpoint
            .fragment()
            .is_some_and(|fragment| !fragment.is_empty())
    {
        return Err("--token-endpoint must not contain credentials or a URL fragment".to_string());
    }
    log_to(
        console,
        &format!(
            "Using an explicit OAuth token endpoint at {}",
            endpoint.origin().ascii_serialization()
        ),
        &[],
    );
    Ok(Some(endpoint.to_string()))
}

pub fn parse_use_id_token_to(console: &mut impl std::io::Write, args: &[String]) -> bool {
    parse_flag_to(
        console,
        args,
        "--use-id-token",
        "Using the ID token as the bearer credential",
    )
}

pub fn parse_resource_to(
    console: &mut impl std::io::Write,
    args: &[String],
) -> Result<(Option<String>, bool), String> {
    let mut authorize_resource = None;
    let mut skip_resource_parameter = args.iter().any(|arg| arg == "--disable-resource-parameter");
    if let Some(index) = args.iter().position(|arg| arg == "--resource")
        && let Some(value) = args.get(index + 1).map(|value| value.trim())
    {
        if value.is_empty() {
            skip_resource_parameter = true;
        } else {
            authorize_resource = Some(value.to_string());
        }
    }
    if skip_resource_parameter {
        if let Some(resource) = authorize_resource.take() {
            log_to(
                console,
                &format!(
                    "Warning: --disable-resource-parameter overrides --resource {resource}; the resource parameter will be omitted."
                ),
                &[],
            );
        }
        log_to(
            console,
            "Resource parameter disabled - it will be omitted from authorization and token requests",
            &[],
        );
    } else if let Some(resource) = &authorize_resource {
        if url::Url::parse(resource).is_err() {
            return Err(format!(
                "Invalid --resource value: \"{resource}\". RFC 8707 requires an absolute URI, e.g. https://example.com/mcp"
            ));
        }
        log_to(
            console,
            &format!("Using authorize resource: {resource}"),
            &[],
        );
    }
    Ok((authorize_resource, skip_resource_parameter))
}

pub fn parse_ignored_tools_to(
    console: &mut impl std::io::Write,
    args: &mut Vec<String>,
) -> Vec<String> {
    let mut ignored_tools = Vec::new();
    let mut index = 0;
    while index < args.len() {
        if args[index] == "--ignore-tool" && index + 1 < args.len() {
            let tool_name = args.remove(index + 1);
            args.remove(index);
            log_to(console, &format!("Ignoring tool: {tool_name}"), &[]);
            ignored_tools.push(tool_name);
            continue;
        }
        index += 1;
    }
    ignored_tools
}

pub fn parse_auth_timeout_to(console: &mut impl std::io::Write, args: &[String]) -> u64 {
    let Some(raw) = args
        .iter()
        .position(|arg| arg == "--auth-timeout")
        .and_then(|index| args.get(index + 1))
    else {
        return 30_000;
    };
    let trimmed = raw.trim_start();
    let (negative, unsigned) = match trimmed.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, trimmed.strip_prefix('+').unwrap_or(trimmed)),
    };
    let digits: String = unsigned
        .chars()
        .take_while(|character| character.is_ascii_digit())
        .collect();
    match digits.parse::<u64>() {
        Ok(timeout_seconds) if !negative && timeout_seconds > 0 => {
            log_to(
                console,
                &format!("Using auth callback timeout: {timeout_seconds} seconds"),
                &[],
            );
            timeout_seconds.saturating_mul(1000)
        }
        _ => {
            log_to(
                console,
                &format!(
                    "Warning: Ignoring invalid auth timeout value: {raw}. Must be a positive number."
                ),
                &[],
            );
            30_000
        }
    }
}

pub fn validate_server_url_to(
    console: &mut impl std::io::Write,
    server_url: Option<&str>,
    allow_http: bool,
    usage: &str,
) -> Result<bool, String> {
    let Some(server_url) = server_url.filter(|server_url| !server_url.is_empty()) else {
        log_to(console, usage, &[]);
        return Ok(false);
    };
    let url = url::Url::parse(server_url).map_err(|_| "Invalid URL".to_string())?;
    let is_localhost =
        matches!(url.host_str(), Some("localhost" | "127.0.0.1")) && url.scheme() == "http";
    if !(url.scheme() == "https" || is_localhost || allow_http) {
        log_to(
            console,
            "Error: Non-HTTPS URLs are only allowed for localhost or when --allow-http flag is provided",
            &[],
        );
        log_to(console, usage, &[]);
        return Ok(false);
    }
    Ok(true)
}

pub fn early_exit_output(args: &[String], usage: &str) -> Option<String> {
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        return Some(format!("{usage}\n"));
    }
    if args.iter().any(|arg| arg == "--version") {
        return Some(format!("{MCP_REMOTE_VERSION}\n"));
    }
    None
}

pub fn parse_debug_and_silent_flags_to(console: &mut impl std::io::Write, args: &[String]) -> bool {
    let debug = args.iter().any(|arg| arg == "--debug");
    if debug {
        crate::logging::set_debug(true);
        log_to(
            console,
            "Debug mode enabled - detailed logs will be written to ~/.mcp-auth/",
            &[],
        );
    }
    if args.iter().any(|arg| arg == "--silent") {
        crate::logging::set_silent(true);
        log_to(
            console,
            "Silent mode enabled - stderr output will be suppressed, except when --debug is also enabled",
            &[],
        );
    }
    debug
}

pub fn announce_server_url_to(
    console: &mut impl std::io::Write,
    server_url: &str,
    server_url_hash: &str,
) {
    crate::logging::set_current_server_url_hash(Some(server_url_hash.to_string()));
    crate::logging::debug_log_to(
        console,
        &format!("Starting mcp-remote with server URL: {server_url}"),
        &[],
    );
}

pub fn get_server_url_hash(
    server_url: &str,
    authorize_resource: Option<&str>,
    headers: &BTreeMap<String, String>,
    authorize_params: &BTreeMap<String, String>,
    client_metadata_url: Option<&str>,
    token_endpoint: Option<&str>,
) -> String {
    let mut parts = vec![server_url.to_string()];
    parts.extend(
        authorize_resource
            .filter(|value| !value.is_empty())
            .map(String::from),
    );
    for record in [authorize_params, headers] {
        if !record.is_empty() {
            parts.push(json_with_utf16_sorted_keys(record));
        }
    }
    parts.extend(
        client_metadata_url
            .filter(|value| !value.is_empty())
            .map(String::from),
    );
    parts.extend(
        token_endpoint
            .filter(|value| !value.is_empty())
            .map(String::from),
    );
    format!("{:x}", md5::compute(parts.join("|")))
}

fn json_with_utf16_sorted_keys(record: &BTreeMap<String, String>) -> String {
    let mut entries: Vec<_> = record.iter().collect();
    entries.sort_by(|(left, _), (right, _)| left.encode_utf16().cmp(right.encode_utf16()));
    let fields: Vec<String> = entries
        .into_iter()
        .map(|(key, value)| {
            format!(
                "{}:{}",
                serde_json::Value::from(key.as_str()),
                serde_json::Value::from(value.as_str())
            )
        })
        .collect();
    format!("{{{}}}", fields.join(","))
}

pub fn substitute_env_vars(value: &str, context: &str) -> String {
    substitute_env_vars_to(&mut std::io::stderr(), value, context)
}

pub fn substitute_env_vars_to(
    console: &mut impl std::io::Write,
    value: &str,
    context: &str,
) -> String {
    let mut result = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(start) = rest.find("${") {
        let Some(length) = rest[start + 2..].find('}') else {
            break;
        };
        if length == 0 {
            result.push_str(&rest[..start + 1]);
            rest = &rest[start + 1..];
            continue;
        }
        let name = &rest[start + 2..start + 2 + length];
        let end = start + 3 + length;
        let placeholder = &rest[start..end];
        result.push_str(&rest[..start]);
        let environment_value = (!name.contains(['=', '\0']))
            .then(|| std::env::var_os(name))
            .flatten();
        match environment_value {
            Some(environment_value) => {
                log_to(
                    console,
                    &format!("Replacing {placeholder} with environment value in {context}"),
                    &[],
                );
                result.push_str(&environment_value.to_string_lossy())
            }
            None => {
                log_to(
                    console,
                    &format!(
                        "Warning: Environment variable '{name}' not found for {context}; leaving {placeholder} as it is."
                    ),
                    &[],
                );
                result.push_str(placeholder)
            }
        }
        rest = &rest[end..];
    }
    result.push_str(rest);
    result
}

pub fn parse_json_with_env_vars(raw: &str, context: &str) -> Result<serde_json::Value, String> {
    let has_placeholder = raw.contains("${");
    let expanded = if has_placeholder {
        substitute_env_vars(raw, context)
    } else {
        raw.to_string()
    };
    serde_json::from_str(&expanded).map_err(|_| {
        let suffix = if has_placeholder {
            " after expanding its ${...} placeholders"
        } else {
            ""
        };
        format!("Could not parse the {context} as JSON{suffix}")
    })
}

#[derive(Debug, Clone, PartialEq)]
pub struct CommandLineArgs {
    pub server_url: String,
    pub callback_path: String,
    pub callback_port: u16,
    pub specified_port: Option<u16>,
    pub headers: Vec<(String, String)>,
    pub transport_strategy: TransportStrategy,
    pub host: String,
    pub debug: bool,
    pub static_oauth_client_metadata: Option<serde_json::Value>,
    pub static_oauth_client_info: Option<serde_json::Value>,
    pub client_metadata_url: Option<String>,
    pub use_id_token: bool,
    pub use_device_code: bool,
    pub use_client_credentials: bool,
    pub token_endpoint: Option<String>,
    pub authorize_resource: Option<String>,
    pub skip_resource_parameter: bool,
    pub authorize_params: BTreeMap<String, String>,
    pub ignored_tools: Vec<String>,
    pub auth_timeout_ms: u64,
    pub server_url_hash: String,
    pub keep_alive: KeepAliveConfig,
    pub protocol_mode: crate::protocol_era::ProtocolMode,
    pub network_options: NetworkOptions,
    pub enable_proxy: bool,
    pub cookies_enabled: bool,
    pub non_interactive_flow: bool,
}

fn parse_specified_port(value: &str) -> Option<u16> {
    let trimmed = value.trim_start_matches(is_javascript_whitespace);
    let digits: String = trimmed
        .strip_prefix('+')
        .unwrap_or(trimmed)
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

pub fn parse_command_line_args_to(
    console: &mut impl std::io::Write,
    mut args: Vec<String>,
    usage: &str,
) -> Result<Option<CommandLineArgs>, String> {
    let headers = extract_header_args_to(console, &mut args)?;
    let server_url = args.first().cloned();
    let specified_port = args.get(1).and_then(|value| parse_specified_port(value));
    let allow_http = args.iter().any(|arg| arg == "--allow-http");
    let debug = parse_debug_and_silent_flags_to(console, &args);
    let network_options = parse_network_options_to(console, &args);
    let enable_proxy = parse_enable_proxy_to(console, &args);
    let keep_alive = parse_keep_alive_to(console, &args);
    let transport_strategy = parse_transport_strategy_to(console, &args);
    let protocol_mode = parse_protocol_mode_to(console, &args);
    let host = parse_callback_host_to(console, &args);
    let callback_path = parse_callback_path_to(console, &args);
    let static_oauth_client_metadata = parse_static_oauth_client_metadata_to(console, &args)?;
    let static_oauth_client_info = parse_static_oauth_client_info_to(console, &args)?;
    let client_metadata_url = parse_client_metadata_url_to(console, &args);
    let cookies_enabled = parse_cookies_enabled_to(console, &args);
    let use_device_code = parse_device_code_to(console, &args);
    let use_client_credentials = parse_client_credentials_to(console, &args);
    let token_endpoint = parse_token_endpoint_to(console, &args, use_client_credentials)?;
    let non_interactive_flow = use_device_code || use_client_credentials;
    let use_id_token = parse_use_id_token_to(console, &args);
    let (authorize_resource, skip_resource_parameter) = parse_resource_to(console, &args)?;
    let authorize_params = parse_authorize_params_to(console, &args)?;
    log_authorize_param_keys_to(console, &args);
    let ignored_tools = parse_ignored_tools_to(console, &mut args);
    let auth_timeout_ms = parse_auth_timeout_to(console, &args);
    if !validate_server_url_to(console, server_url.as_deref(), allow_http, usage)? {
        return Ok(None);
    }
    let server_url = server_url.unwrap_or_default();
    let server_url_hash = get_server_url_hash(
        &server_url,
        authorize_resource.as_deref(),
        &headers.iter().cloned().collect(),
        &authorize_params,
        client_metadata_url.as_deref(),
        token_endpoint.as_deref(),
    );
    announce_server_url_to(console, &server_url, &server_url_hash);
    let default_port = calculate_default_port(&server_url_hash).unwrap_or_default();
    let callback_port = select_callback_port_to(console, specified_port, default_port);
    if static_oauth_client_info.is_none() {
        invalidate_mismatched_client_registration_to(
            console,
            &server_url_hash,
            &build_redirect_url(&host, callback_port, &callback_path),
        );
    }
    let headers = finalise_headers_to(console, headers);
    Ok(Some(CommandLineArgs {
        server_url,
        callback_path,
        callback_port,
        specified_port,
        headers,
        transport_strategy,
        host,
        debug,
        static_oauth_client_metadata,
        static_oauth_client_info,
        client_metadata_url,
        use_id_token,
        use_device_code,
        use_client_credentials,
        token_endpoint,
        authorize_resource,
        skip_resource_parameter,
        authorize_params,
        ignored_tools,
        auth_timeout_ms,
        server_url_hash,
        keep_alive,
        protocol_mode,
        network_options,
        enable_proxy,
        cookies_enabled,
        non_interactive_flow,
    }))
}

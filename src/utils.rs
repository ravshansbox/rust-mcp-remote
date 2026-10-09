use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

pub const DEFAULT_CALLBACK_PATH: &str = "/oauth/callback";

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

pub fn build_redirect_url(host: &str, port: u16, callback_path: &str) -> String {
    format!("http://{host}:{port}{callback_path}")
}

pub fn parse_authorize_params(args: &[String]) -> Result<BTreeMap<String, String>, String> {
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
        params.insert(key.to_string(), value.to_string());
    }
    Ok(params)
}

pub fn parse_seconds_option(args: &[String], flag: &str, allow_zero: bool) -> Option<u64> {
    let index = args.iter().position(|arg| arg == flag)?;
    let raw = args.get(index + 1)?;
    let seconds = javascript_number(raw);
    if !seconds.is_finite() || seconds < 0.0 || (seconds == 0.0 && !allow_zero) {
        return None;
    }
    Some((seconds * 1000.0).round() as u64)
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

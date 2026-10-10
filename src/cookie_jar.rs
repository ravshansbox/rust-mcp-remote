use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use url::Url;

struct StoredCookie {
    name: String,
    value: String,
    path: String,
    expires_at: Option<SystemTime>,
}

pub struct CookieJar {
    by_origin: HashMap<String, Vec<StoredCookie>>,
    clock: Box<dyn Fn() -> SystemTime + Send>,
}

impl Default for CookieJar {
    fn default() -> Self {
        Self::new()
    }
}

impl CookieJar {
    pub fn new() -> Self {
        Self::with_clock(SystemTime::now)
    }

    pub fn with_clock(clock: impl Fn() -> SystemTime + Send + 'static) -> Self {
        Self {
            by_origin: HashMap::new(),
            clock: Box::new(clock),
        }
    }

    pub fn capture(&mut self, url: &str, set_cookies: &[&str]) {
        if set_cookies.is_empty() {
            return;
        }
        let Ok(target) = Url::parse(url) else {
            return;
        };
        let now = (self.clock)();
        let jar = self
            .by_origin
            .entry(target.origin().ascii_serialization())
            .or_default();

        for header in set_cookies {
            let Some(cookie) = parse_set_cookie(header, &target, now) else {
                continue;
            };
            let existing = jar.iter().position(|stored| stored.name == cookie.name);

            if cookie
                .expires_at
                .is_some_and(|expires_at| expires_at <= now)
            {
                if let Some(index) = existing {
                    jar.remove(index);
                }
                continue;
            }

            match existing {
                Some(index) => jar[index] = cookie,
                None => jar.push(cookie),
            }
        }
    }

    pub fn header(&mut self, url: &str) -> Option<String> {
        let target = Url::parse(url).ok()?;
        let jar = self
            .by_origin
            .get_mut(&target.origin().ascii_serialization())?;
        let now = (self.clock)();

        jar.retain(|cookie| cookie.expires_at.is_none_or(|expires_at| expires_at > now));

        let pairs: Vec<String> = jar
            .iter()
            .filter(|cookie| path_matches(target.path(), &cookie.path))
            .map(|cookie| format!("{}={}", cookie.name, cookie.value))
            .collect();

        (!pairs.is_empty()).then(|| pairs.join("; "))
    }
}

fn parse_set_cookie(header: &str, target: &Url, now: SystemTime) -> Option<StoredCookie> {
    let mut parts = header.split(';');
    let pair = parts.next()?;
    let separator = pair.find('=')?;
    if separator < 1 {
        return None;
    }

    let name = pair[..separator].trim();
    let value = pair[separator + 1..].trim();
    if name.is_empty() {
        return None;
    }

    let mut path = default_path(target.path());
    let mut expires = None;
    let mut max_age = None;

    for attribute in parts {
        let (key, attribute_value) = match attribute.find('=') {
            Some(index) => (&attribute[..index], attribute[index + 1..].trim()),
            None => (attribute, ""),
        };
        let key = key.trim().to_ascii_lowercase();

        if key == "path" && attribute_value.starts_with('/') {
            path = attribute_value.to_string();
        } else if key == "expires" {
            if let Ok(parsed) = httpdate::parse_http_date(attribute_value) {
                expires = Some(parsed);
            }
        } else if key == "max-age"
            && let Ok(seconds) = attribute_value.parse::<f64>()
            && seconds.is_finite()
        {
            max_age = Some(seconds);
        }
    }

    let expires_at = match max_age {
        Some(seconds) => offset(now, seconds),
        None => expires,
    };

    Some(StoredCookie {
        name: name.to_string(),
        value: value.to_string(),
        path,
        expires_at,
    })
}

fn offset(now: SystemTime, seconds: f64) -> Option<SystemTime> {
    let span = Duration::try_from_secs_f64(seconds.abs()).unwrap_or(Duration::MAX);
    if seconds >= 0.0 {
        now.checked_add(span)
    } else {
        Some(now.checked_sub(span).unwrap_or(SystemTime::UNIX_EPOCH))
    }
}

fn default_path(pathname: &str) -> String {
    if !pathname.starts_with('/') {
        return "/".to_string();
    }
    match pathname.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(last_slash) => pathname[..last_slash].to_string(),
    }
}

fn path_matches(request_path: &str, cookie_path: &str) -> bool {
    if request_path == cookie_path {
        return true;
    }
    if !request_path.starts_with(cookie_path) {
        return false;
    }
    cookie_path.ends_with('/') || request_path.as_bytes().get(cookie_path.len()) == Some(&b'/')
}

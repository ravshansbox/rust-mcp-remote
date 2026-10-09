use std::io::Write;

use serde_json::Value;

use crate::mcp_auth_config::{config_dir, config_file_path};

pub fn format_debug_log_entry(formatted_message: &str, args: &[Value]) -> String {
    let rendered_args: Vec<String> = args
        .iter()
        .map(|arg| match arg {
            Value::String(text) => text.clone(),
            other => other.to_string(),
        })
        .collect();
    format!("{formatted_message} {}\n", rendered_args.join(" "))
}

pub fn append_debug_log(server_url_hash: &str, entry: &str) -> std::io::Result<()> {
    let mut directory_builder = std::fs::DirBuilder::new();
    directory_builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut directory_builder, 0o700);
    directory_builder.create(config_dir())?;

    let mut options = std::fs::OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options
        .open(config_file_path(server_url_hash, "debug.log"))?
        .write_all(entry.as_bytes())
}

pub fn iso_timestamp(time: std::time::SystemTime) -> String {
    let milliseconds_since_epoch: i64 = match time.duration_since(std::time::UNIX_EPOCH) {
        Ok(after) => after.as_millis() as i64,
        Err(before) => -(before.duration().as_nanos().div_ceil(1_000_000) as i64),
    };
    let days_since_epoch = milliseconds_since_epoch.div_euclid(86_400_000);
    let millisecond_of_day = milliseconds_since_epoch.rem_euclid(86_400_000);

    let shifted_days = days_since_epoch + 719_468;
    let era = shifted_days.div_euclid(146_097);
    let day_of_era = shifted_days.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);

    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        millisecond_of_day / 3_600_000,
        millisecond_of_day / 60_000 % 60,
        millisecond_of_day / 1_000 % 60,
        millisecond_of_day % 1_000
    )
}

pub fn format_debug_message(timestamp: &str, pid: u32, message: &str) -> String {
    format!("[{timestamp}][{pid}] {message}")
}

pub fn format_log_line(pid: u32, message: &str) -> String {
    format!("[{pid}] {message}")
}

pub fn write_debug_log(
    console: &mut impl Write,
    server_url_hash: Option<&str>,
    formatted_message: &str,
    args: &[Value],
) {
    let Some(server_url_hash) = server_url_hash else {
        let _ = writeln!(
            console,
            "[DEBUG LOG ERROR] global.currentServerUrlHash is not set. Cannot write debug log."
        );
        return;
    };

    let entry = format_debug_log_entry(formatted_message, args);
    let console_line = if args.is_empty() {
        format!("{formatted_message}\n")
    } else {
        entry.clone()
    };
    let _ = console.write_all(console_line.as_bytes());

    if let Err(error) = append_debug_log(server_url_hash, &entry) {
        let _ = writeln!(console, "[DEBUG LOG ERROR] {error}");
    }
}

static DEBUG: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static SILENT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static CURRENT_SERVER_URL_HASH: std::sync::RwLock<Option<String>> = std::sync::RwLock::new(None);

pub fn set_debug(enabled: bool) {
    DEBUG.store(enabled, std::sync::atomic::Ordering::Relaxed);
}

pub fn set_silent(enabled: bool) {
    SILENT.store(enabled, std::sync::atomic::Ordering::Relaxed);
}

pub fn set_current_server_url_hash(server_url_hash: Option<String>) {
    *CURRENT_SERVER_URL_HASH
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = server_url_hash;
}

pub fn debug_log_to(console: &mut impl Write, message: &str, args: &[Value]) {
    if !DEBUG.load(std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    let server_url_hash = CURRENT_SERVER_URL_HASH
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    let formatted_message = format_debug_message(
        &iso_timestamp(std::time::SystemTime::now()),
        std::process::id(),
        message,
    );
    write_debug_log(
        console,
        server_url_hash.as_deref(),
        &formatted_message,
        args,
    );
}

pub fn debug_log(message: &str, args: &[Value]) {
    debug_log_to(&mut std::io::stderr(), message, args);
}

pub fn log_to(console: &mut impl Write, message: &str, rest: &[Value]) {
    if !SILENT.load(std::sync::atomic::Ordering::Relaxed) {
        write_log_line(console, message, rest);
    }
    debug_log_to(console, message, rest);
}

fn write_log_line(console: &mut impl Write, message: &str, rest: &[Value]) {
    let mut line = format_log_line(std::process::id(), message);
    for value in rest {
        line.push(' ');
        match value {
            Value::String(text) => line.push_str(text),
            other => line.push_str(&other.to_string()),
        }
    }
    line.push('\n');
    let _ = console.write_all(line.as_bytes());
}

pub fn log(message: &str, rest: &[Value]) {
    log_to(&mut std::io::stderr(), message, rest);
}

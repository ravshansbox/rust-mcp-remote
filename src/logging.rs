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

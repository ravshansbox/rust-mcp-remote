use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::de::DeserializeOwned;
use serde_json::Value;

const CONFIG_STORE_VERSION: u32 = 1;

pub fn config_dir() -> PathBuf {
    let base_config_dir = std::env::var_os("MCP_REMOTE_CONFIG_DIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::home_dir().unwrap_or_default().join(".mcp-auth"));
    base_config_dir.join(format!("mcp-remote-v{CONFIG_STORE_VERSION}"))
}

pub fn config_file_path(server_url_hash: &str, filename: &str) -> PathBuf {
    config_dir().join(format!("{server_url_hash}_{filename}"))
}

fn ensure_config_dir() -> std::io::Result<()> {
    std::fs::create_dir_all(config_dir())
}

fn write_owner_only(path: &Path, contents: &str) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)?.write_all(contents.as_bytes())
}

pub fn read_json_file<T: DeserializeOwned>(server_url_hash: &str, filename: &str) -> Option<T> {
    ensure_config_dir().ok()?;
    let content = std::fs::read_to_string(config_file_path(server_url_hash, filename)).ok()?;
    serde_json::from_str(&content).ok()
}

pub fn write_json_file(server_url_hash: &str, filename: &str, data: &Value) -> std::io::Result<()> {
    ensure_config_dir()?;
    let file_path = config_file_path(server_url_hash, filename);
    let serialized = serde_json::to_string_pretty(data)?;
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let mut temp_path = file_path.clone().into_os_string();
    temp_path.push(format!(".{}.{millis}.tmp", std::process::id()));
    let temp_path = PathBuf::from(temp_path);

    let rename_result = write_owner_only(&temp_path, &serialized)
        .and_then(|()| std::fs::rename(&temp_path, &file_path));
    if let Err(rename_error) = rename_result {
        let _ = std::fs::remove_file(&temp_path);
        if cfg!(windows) {
            return write_owner_only(&file_path, &serialized);
        }
        return Err(rename_error);
    }
    Ok(())
}

#[derive(Debug)]
struct ReadTextFileError {
    message: String,
    cause: std::io::Error,
}

impl std::fmt::Display for ReadTextFileError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ReadTextFileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}

pub fn read_text_file(
    server_url_hash: &str,
    filename: &str,
    error_message: Option<&str>,
) -> std::io::Result<String> {
    ensure_config_dir()
        .and_then(|()| std::fs::read_to_string(config_file_path(server_url_hash, filename)))
        .map_err(|cause| {
            let message = error_message
                .filter(|message| !message.is_empty())
                .map(str::to_owned)
                .unwrap_or_else(|| format!("Error reading {filename}"));
            std::io::Error::new(cause.kind(), ReadTextFileError { message, cause })
        })
}

pub fn write_text_file(server_url_hash: &str, filename: &str, text: &str) -> std::io::Result<()> {
    ensure_config_dir()?;
    write_owner_only(&config_file_path(server_url_hash, filename), text)
}

pub fn delete_config_file(server_url_hash: &str, filename: &str) {
    let _ = std::fs::remove_file(config_file_path(server_url_hash, filename));
}

pub fn delete_stale_config_files(server_url_hash: &str, prefix: &str, max_age: Duration) {
    let config_dir = config_dir();
    let Ok(entries) = std::fs::read_dir(&config_dir) else {
        return;
    };
    let cutoff = SystemTime::now().checked_sub(max_age).unwrap_or(UNIX_EPOCH);
    let filename_prefix = format!("{server_url_hash}_{prefix}");
    for entry in entries.flatten() {
        if !entry
            .file_name()
            .to_string_lossy()
            .starts_with(&filename_prefix)
        {
            continue;
        }
        let is_stale = entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .is_ok_and(|modified| modified <= cutoff);
        if is_stale {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

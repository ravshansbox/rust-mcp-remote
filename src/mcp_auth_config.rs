use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

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

use std::path::PathBuf;

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

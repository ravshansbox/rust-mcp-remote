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

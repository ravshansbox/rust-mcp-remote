//! Tests for the `logging` module, gathered into one test binary.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Serializes tests that change process-wide state (environment variables, logging flags).
pub static GLOBAL_STATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Runs `action` with `MCP_REMOTE_CONFIG_DIR` pointing at a fresh, not yet created temporary
/// directory, passing that directory in, and removes it afterwards.
pub fn with_temporary_config_dir<T>(action: impl FnOnce(&Path) -> T) -> T {
    let _guard = GLOBAL_STATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let directory: PathBuf =
        std::env::temp_dir().join(format!("mcp-remote-logging-{}-{nanos}", std::process::id()));
    unsafe { std::env::set_var("MCP_REMOTE_CONFIG_DIR", &directory) };
    let result = action(&directory);
    unsafe { std::env::remove_var("MCP_REMOTE_CONFIG_DIR") };
    let _ = std::fs::remove_dir_all(&directory);
    result
}

mod debug_log;
mod prefixes;
mod write_debug_log;

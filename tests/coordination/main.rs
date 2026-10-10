//! Tests for the `coordination` module, gathered into one test binary.

use std::future::Future;
use std::time::{SystemTime, UNIX_EPOCH};

/// Serializes tests that change process-wide state (environment variables, logging flags).
pub static GLOBAL_STATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Runs an async test on its own runtime with MCP_REMOTE_CONFIG_DIR pointing at a fresh
/// directory, holding GLOBAL_STATE throughout.
pub fn run_in_config_dir<F: Future>(prefix: &str, test: impl FnOnce() -> F) -> F::Output {
    let _guard = GLOBAL_STATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let directory = std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&directory).expect("create temporary directory");
    unsafe { std::env::set_var("MCP_REMOTE_CONFIG_DIR", &directory) };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build runtime");
    let result = runtime.block_on(test());
    drop(runtime);
    unsafe { std::env::remove_var("MCP_REMOTE_CONFIG_DIR") };
    std::fs::remove_dir_all(&directory).expect("remove temporary directory");
    result
}

mod callback_port_candidates;
mod coordinate_auth;
mod has_usable_tokens;
mod lazy_auth_coordinator;

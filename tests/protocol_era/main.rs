//! Tests for the `protocol_era` module, gathered into one test binary.

/// Serializes tests that change process-wide state (environment variables, logging flags).
pub static GLOBAL_STATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

mod discover;
mod initialize;
mod meta;
mod predicates;
mod protocol_era;
mod subscriptions;
mod verdict;

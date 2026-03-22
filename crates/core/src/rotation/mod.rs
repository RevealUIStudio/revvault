//! Secret rotation engine.
//!
//! Provides a generic HTTP-based rotation provider and an executor that
//! orchestrates vault I/O around provider dispatch.
//!
//! # Supported providers
//!
//! - `GenericHttpProvider` — any API key lifecycle driven by two HTTP endpoints
//!   (create + optional revoke). Configured via `<store>/.revvault/rotation.toml`.

pub mod config;
pub mod executor;
pub mod provider;
pub mod providers;

pub use config::RotationConfig;
pub use provider::RotationProvider;

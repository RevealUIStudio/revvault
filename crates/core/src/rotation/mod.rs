//! Secret rotation engine.
//!
//! Provides rotation providers and an executor that orchestrates vault I/O
//! around provider dispatch, post-rotate hooks, and verification.
//!
//! # Supported providers
//!
//! - `GenericHttpProvider` — any API key lifecycle driven by two HTTP endpoints
//!   (create + optional revoke). Configured via `<store>/.revvault/rotation.toml`.
//! - `LocalGeneratorProvider` — cryptographically random values (hex32, hex64, uuid)
//!   without network calls. Triggered by `generator_type` in provider settings.

pub mod config;
pub mod executor;
pub mod provider;
pub mod providers;

pub use config::RotationConfig;
pub use provider::RotationProvider;

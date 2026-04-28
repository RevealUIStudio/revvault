//! Secret rotation engine.
//!
//! Provides rotation providers and an executor that orchestrates vault
//! I/O around provider dispatch (factory in `providers::build_provider`).
//!
//! # Supported providers
//!
//! - `GenericHttpProvider` — any API key lifecycle driven by two HTTP
//!   endpoints (create + optional revoke). Default when `settings["type"]`
//!   is unset; works for stripe / vercel / github tokens whose auth is
//!   the value being rotated. Configured via
//!   `<store>/.revvault/rotation.toml`.
//! - `NeonProvider` — Neon Postgres password reset. Selected by
//!   `settings["type"] = "neon"`. Reads its API key from a separate vault
//!   path (`settings["api_key_path"]`) because the rotated value (the
//!   connection URI) is distinct from the auth token.

pub mod config;
pub mod executor;
pub mod provider;
pub mod providers;

pub use config::RotationConfig;
pub use provider::RotationProvider;

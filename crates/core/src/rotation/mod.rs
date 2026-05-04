//! Secret rotation engine.
//!
//! Provides rotation providers and an executor that orchestrates vault
//! I/O around provider dispatch (factory in `providers::build_provider`),
//! the post-rotation Vercel sync hook (`sync_hook`), user-configurable
//! `post_rotate` shell hooks, and a strict `verify` gate.
//!
//! # Supported providers
//!
//! - `GenericHttpProvider` — any API key lifecycle driven by two HTTP
//!   endpoints (create + optional revoke). Default when `settings["type"]`
//!   is unset; works for stripe / vercel / github tokens whose auth is
//!   the value being rotated.
//! - `NeonProvider` — Neon Postgres password reset. Selected by
//!   `settings["type"] = "neon"`. Reads its API key from a separate vault
//!   path (`settings["api_key_path"]`) because the rotated value (the
//!   connection URI) is distinct from the auth token.
//! - `LocalGeneratorProvider` — cryptographically random values
//!   (hex32 / hex64 / uuid) without network calls. Selected by
//!   `settings["type"] = "local"` with `settings["generator_type"]`.
//!
//! All providers configured via `<store>/.revvault/rotation.toml`.

pub mod config;
pub mod executor;
pub mod provider;
pub mod providers;
pub mod sync_hook;

pub use config::RotationConfig;
pub use provider::RotationProvider;

//! Outbound sync to external secret stores.
//!
//! Sync is a generic capability — `revvault sync vercel` runs it
//! standalone (whole-project push/pull from a `revvault-vercel.toml`
//! manifest), and `revvault rotate <provider>` runs it chained (per-secret
//! push driven by a `[providers.<name>.sync.vercel]` block in
//! `rotation.toml`). Both flows share the [`vercel::VercelClient`]
//! transport in this module.

pub mod vercel;

pub use vercel::{VercelClient, VercelEnvVar};

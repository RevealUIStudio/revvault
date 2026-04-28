//! Rotation provider implementations + factory dispatch.
//!
//! Providers all implement `RotationProvider` (see `super::provider`). The
//! `build_provider` factory below picks the right implementation based on
//! `settings["type"]` so the executor doesn't need to know which kind of
//! provider it's running.
//!
//! - `type` absent or any value other than `"neon"` → [`GenericHttpProvider`]
//!   (HTTP create + optional revoke pattern; works for stripe / vercel /
//!   github tokens whose auth is the value being rotated).
//! - `type = "neon"` → [`NeonProvider`] (Neon Postgres password reset; the
//!   auth token is a separate vault secret read from `api_key_path`).

pub mod http;
pub mod neon;

pub use http::GenericHttpProvider;
pub use neon::NeonProvider;

use std::collections::HashMap;

use secrecy::{ExposeSecret as _, SecretString};

use crate::error::{Result, RevvaultError};
use crate::rotation::provider::RotationProvider;
use crate::store::PassageStore;

/// Build a `RotationProvider` for the given config.
///
/// Dispatches by `settings["type"]`:
/// - `"neon"` — constructs a `NeonProvider`. Reads the Neon API key from
///   the vault path in `settings["api_key_path"]` so the rotated value
///   (the connection URI at `secret_path`) and the auth token can live in
///   different vault locations.
/// - anything else (or absent) — constructs a `GenericHttpProvider` using
///   `current_key` as the auth token and the existing create/revoke URL
///   pattern.
pub fn build_provider(
    store: &PassageStore,
    name: String,
    current_key: SecretString,
    old_key_id: Option<String>,
    settings: &HashMap<String, String>,
) -> Result<Box<dyn RotationProvider>> {
    match settings.get("type").map(String::as_str) {
        Some("neon") => {
            let api_key_path = settings.get("api_key_path").ok_or_else(|| {
                RevvaultError::Other(anyhow::anyhow!(
                    "provider '{}': type=neon requires 'api_key_path' setting (path to the Neon API key in the vault)",
                    name
                ))
            })?;
            let api_key = store.get(api_key_path).map_err(|e| {
                RevvaultError::Other(anyhow::anyhow!(
                    "provider '{}': cannot read api_key_path '{}': {e}",
                    name,
                    api_key_path
                ))
            })?;
            // Re-wrap so the new SecretString owns its bytes (PassageStore
            // returns a fresh SecretString already, but explicit copy keeps
            // the lifetime story obvious).
            let api_key_owned = SecretString::from(api_key.expose_secret().to_string());
            Ok(Box::new(NeonProvider::from_config(
                name,
                api_key_owned,
                settings,
            )?))
        }
        _ => Ok(Box::new(GenericHttpProvider::from_config(
            name,
            current_key,
            old_key_id,
            settings,
        )?)),
    }
}

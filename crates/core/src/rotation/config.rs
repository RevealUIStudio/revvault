use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Result, RevvaultError};
use crate::rotation::sync_hook::SyncConfig;

/// Rotation configuration loaded from `<store>/.revvault/rotation.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationConfig {
    #[serde(default)]
    pub providers: HashMap<String, ProviderConfig>,
}

/// Configuration for a single rotation provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    /// Secret path in the store containing the current API key.
    pub secret_path: String,
    /// Provider-specific settings.
    #[serde(default)]
    pub settings: HashMap<String, String>,
    /// Optional post-rotation sync block. When present, the
    /// executor pushes the new value to the configured external
    /// secret stores (today: Vercel) after the vault write
    /// succeeds. See [`crate::rotation::sync_hook`] for shape +
    /// failure semantics.
    #[serde(default)]
    pub sync: Option<SyncConfig>,
    /// User-configurable shell commands to run after the vault
    /// write + sync hook complete. Executed sequentially with
    /// `sh -c`. Failure is **warn-only** — the rotation is not
    /// aborted because the new key is already live in the vault.
    /// Use `verify` for a strict gate.
    #[serde(default)]
    pub post_rotate: Vec<String>,
    /// Optional strict verification command. When set, runs after
    /// the `post_rotate` hooks. Exit-zero records `verified: true`
    /// in the rotation log; **non-zero records `verified: false`
    /// AND causes the executor to return Err** (cli exits non-zero).
    /// Vault state is unchanged either way — the rotation already
    /// landed.
    #[serde(default)]
    pub verify: Option<String>,
}

impl RotationConfig {
    /// Load rotation config from the store's `.revvault/rotation.toml`.
    pub fn load(store_dir: &Path) -> Result<Self> {
        let config_path = store_dir.join(".revvault/rotation.toml");

        if !config_path.exists() {
            return Ok(Self {
                providers: HashMap::new(),
            });
        }

        let contents = std::fs::read_to_string(&config_path)?;
        toml::from_str(&contents)
            .map_err(|e| RevvaultError::Other(anyhow::anyhow!("invalid rotation.toml: {e}")))
    }
}

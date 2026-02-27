use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Result, RevaultError};

/// Rotation configuration loaded from `<store>/.revault/rotation.toml`.
#[derive(Debug, Serialize, Deserialize)]
pub struct RotationConfig {
    #[serde(default)]
    pub providers: HashMap<String, ProviderConfig>,
}

/// Configuration for a single rotation provider.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProviderConfig {
    /// Secret path in the store containing the current API key.
    pub secret_path: String,
    /// Provider-specific settings.
    #[serde(default)]
    pub settings: HashMap<String, String>,
}

impl RotationConfig {
    /// Load rotation config from the store's `.revault/rotation.toml`.
    pub fn load(store_dir: &Path) -> Result<Self> {
        let config_path = store_dir.join(".revault/rotation.toml");

        if !config_path.exists() {
            return Ok(Self {
                providers: HashMap::new(),
            });
        }

        let contents = std::fs::read_to_string(&config_path)?;
        toml::from_str(&contents).map_err(|e| {
            RevaultError::Other(anyhow::anyhow!("invalid rotation.toml: {e}"))
        })
    }
}

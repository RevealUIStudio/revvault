use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Result, RevvaultError};

/// Rotation configuration loaded from `<store>/.revvault/rotation.toml`.
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

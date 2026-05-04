//! Local secret generator — produces cryptographically random values without
//! any network calls. Used for internal secrets like REVEALUI_SECRET.

use std::str::FromStr;

use async_trait::async_trait;
use rand::RngCore;
use secrecy::SecretString;

use crate::error::{Result, RevvaultError};
use crate::rotation::provider::{RotationOutcome, RotationProvider};

/// The type of value to generate.
#[derive(Debug)]
pub enum GeneratorType {
    /// 32-byte hex string (64 hex chars).
    Hex32,
    /// 64-byte hex string (128 hex chars).
    Hex64,
    /// UUID v4 string.
    Uuid,
}

impl FromStr for GeneratorType {
    type Err = RevvaultError;

    /// Parse a generator type from a string (as used in `rotation.toml` settings).
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "hex32" => Ok(Self::Hex32),
            "hex64" => Ok(Self::Hex64),
            "uuid" => Ok(Self::Uuid),
            other => Err(RevvaultError::Other(anyhow::anyhow!(
                "unknown generator_type: '{other}' (expected hex32, hex64, or uuid)"
            ))),
        }
    }
}

impl GeneratorType {
    /// Generate a random value of this type.
    fn generate(&self) -> String {
        match self {
            Self::Hex32 => {
                let mut bytes = [0u8; 32];
                rand::rng().fill_bytes(&mut bytes);
                hex::encode(bytes)
            }
            Self::Hex64 => {
                let mut bytes = [0u8; 64];
                rand::rng().fill_bytes(&mut bytes);
                hex::encode(bytes)
            }
            Self::Uuid => uuid::Uuid::new_v4().to_string(),
        }
    }
}

/// Local secret generator provider — no network, no API keys.
#[derive(Debug)]
pub struct LocalGeneratorProvider {
    name: String,
    generator_type: GeneratorType,
}

impl LocalGeneratorProvider {
    /// Create a new local generator provider.
    ///
    /// `generator_type_str` must be one of `"hex32"`, `"hex64"`, or `"uuid"`.
    pub fn new(name: String, generator_type_str: &str) -> Result<Self> {
        Ok(Self {
            name,
            generator_type: GeneratorType::from_str(generator_type_str)?,
        })
    }
}

#[async_trait]
impl RotationProvider for LocalGeneratorProvider {
    fn name(&self) -> &str {
        &self.name
    }

    async fn preflight(&self) -> Result<()> {
        Ok(())
    }

    async fn rotate(&self) -> Result<RotationOutcome> {
        let value = self.generator_type.generate();
        Ok(RotationOutcome {
            new_value: SecretString::from(value),
            new_key_id: None,
        })
    }

    async fn dry_run(&self) -> Result<String> {
        Ok(format!(
            "Provider '{}': generate {:?} value (no network call)",
            self.name, self.generator_type
        ))
    }
}

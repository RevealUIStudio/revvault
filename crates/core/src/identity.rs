use std::fs;
use std::path::Path;

use age::x25519;

use crate::error::{Result, RevaultError};

/// Loaded age identity (private key) used for decryption.
pub struct Identity {
    identities: Vec<x25519::Identity>,
}

impl Identity {
    /// Load age identities from a key file.
    ///
    /// The file can contain multiple identity lines (one per line),
    /// plus comment lines starting with `#`.
    pub fn from_file(path: &Path) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .map_err(|_| RevaultError::IdentityNotFound(path.to_path_buf()))?;

        let identities: Vec<x25519::Identity> = contents
            .lines()
            .filter(|line| {
                let trimmed = line.trim();
                !trimmed.is_empty() && !trimmed.starts_with('#')
            })
            .filter_map(|line| line.trim().parse::<x25519::Identity>().ok())
            .collect();

        if identities.is_empty() {
            return Err(RevaultError::DecryptionFailed(
                "no valid age identities found in key file".into(),
            ));
        }

        Ok(Self { identities })
    }

    /// Get a reference to the loaded identities for decryption.
    pub fn as_identities(&self) -> &[x25519::Identity] {
        &self.identities
    }

    /// Get the public key (recipient) for the first identity.
    pub fn default_recipient(&self) -> x25519::Recipient {
        self.identities[0].to_public()
    }

    /// Create an identity from pre-generated keys (for testing).
    #[cfg(test)]
    pub fn from_generated(identities: Vec<x25519::Identity>) -> Self {
        Self { identities }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_identity_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("keys.txt");

        // Generate a test identity
        let identity = x25519::Identity::generate();
        let secret_key = identity.to_string();

        fs::write(
            &key_file,
            format!(
                "# created: 2024-01-01\n# public key: {}\n{}\n",
                identity.to_public(),
                secret_key
            ),
        )
        .unwrap();

        let loaded = Identity::from_file(&key_file).unwrap();
        assert_eq!(loaded.as_identities().len(), 1);
    }
}

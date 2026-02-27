use std::path::{Path, PathBuf};

use fuzzy_matcher::skim::SkimMatcherV2;
use fuzzy_matcher::FuzzyMatcher;
use secrecy::SecretString;
use walkdir::WalkDir;

use crate::config::Config;
use crate::crypto;
use crate::error::{Result, RevaultError};
use crate::identity::Identity;
use crate::namespace::Namespace;

/// Entry in the secret store.
#[derive(Debug, Clone)]
pub struct SecretEntry {
    /// Relative path from store root (e.g., "revealui/stripe/secret-key")
    pub path: String,
    /// Parsed namespace from the first path segment
    pub namespace: Namespace,
    /// Full filesystem path to the .age file
    pub file_path: PathBuf,
}

/// The main passage-compatible secret store.
pub struct PassageStore {
    config: Config,
    identity: Identity,
    recipients: Vec<age::x25519::Recipient>,
}

impl PassageStore {
    /// Open an existing store using resolved configuration.
    pub fn open(config: Config) -> Result<Self> {
        let identity = Identity::from_file(&config.identity_file)?;
        let recipients = crypto::load_recipients(&config.recipients_file)?;

        Ok(Self {
            config,
            identity,
            recipients,
        })
    }

    /// Get (decrypt) a secret by its path.
    pub fn get(&self, path: &str) -> Result<SecretString> {
        let file_path = self.resolve_path(path)?;
        let ciphertext = std::fs::read(&file_path)
            .map_err(|_| RevaultError::SecretNotFound(path.to_string()))?;
        crypto::decrypt(&ciphertext, &self.identity)
    }

    /// Set (encrypt and write) a secret at the given path.
    pub fn set(&self, path: &str, plaintext: &[u8]) -> Result<()> {
        let file_path = self.secret_file_path(path);

        if file_path.exists() {
            return Err(RevaultError::SecretAlreadyExists(path.to_string()));
        }

        // Ensure parent directories exist
        if let Some(parent) = file_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let ciphertext = crypto::encrypt(plaintext, &self.recipients)?;
        std::fs::write(&file_path, ciphertext)?;
        Ok(())
    }

    /// Overwrite an existing secret (or create if missing).
    pub fn upsert(&self, path: &str, plaintext: &[u8]) -> Result<()> {
        let file_path = self.secret_file_path(path);

        if let Some(parent) = file_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let ciphertext = crypto::encrypt(plaintext, &self.recipients)?;
        std::fs::write(&file_path, ciphertext)?;
        Ok(())
    }

    /// List all secret entries, optionally filtered by a path prefix.
    pub fn list(&self, prefix: Option<&str>) -> Result<Vec<SecretEntry>> {
        let mut entries = Vec::new();

        for entry in WalkDir::new(&self.config.store_dir)
            .min_depth(1)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();

            if !path.is_file() {
                continue;
            }

            // Skip non-.age files and hidden files
            let ext = path.extension().and_then(|e| e.to_str());
            if ext != Some("age") {
                continue;
            }

            let file_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            if file_name.starts_with('.') {
                continue;
            }

            let relative = path
                .strip_prefix(&self.config.store_dir)
                .unwrap_or(path);

            // Remove .age extension from the logical path
            let logical_path = relative
                .with_extension("")
                .to_string_lossy()
                .replace('\\', "/");

            if let Some(prefix) = prefix {
                if !logical_path.starts_with(prefix) {
                    continue;
                }
            }

            let namespace = logical_path
                .split('/')
                .next()
                .map(Namespace::from_path_segment)
                .unwrap_or(Namespace::Misc);

            entries.push(SecretEntry {
                path: logical_path,
                namespace,
                file_path: path.to_path_buf(),
            });
        }

        entries.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(entries)
    }

    /// Fuzzy search for secrets by path.
    pub fn search(&self, query: &str) -> Result<Vec<SecretEntry>> {
        let matcher = SkimMatcherV2::default();
        let mut entries = self.list(None)?;

        let mut scored: Vec<(i64, SecretEntry)> = entries
            .drain(..)
            .filter_map(|entry| {
                matcher
                    .fuzzy_match(&entry.path, query)
                    .map(|score| (score, entry))
            })
            .collect();

        scored.sort_by(|a, b| b.0.cmp(&a.0));
        Ok(scored.into_iter().map(|(_, entry)| entry).collect())
    }

    /// Delete a secret by its path.
    pub fn delete(&self, path: &str) -> Result<()> {
        let file_path = self.resolve_path(path)?;
        std::fs::remove_file(&file_path)?;

        // Clean up empty parent directories
        if let Some(parent) = file_path.parent() {
            Self::cleanup_empty_dirs(parent, &self.config.store_dir);
        }

        Ok(())
    }

    /// Get the store root directory.
    pub fn store_dir(&self) -> &Path {
        &self.config.store_dir
    }

    fn resolve_path(&self, path: &str) -> Result<PathBuf> {
        let file_path = self.secret_file_path(path);
        if file_path.exists() {
            Ok(file_path)
        } else {
            Err(RevaultError::SecretNotFound(path.to_string()))
        }
    }

    fn secret_file_path(&self, path: &str) -> PathBuf {
        self.config.store_dir.join(format!("{path}.age"))
    }

    fn cleanup_empty_dirs(dir: &Path, stop_at: &Path) {
        let mut current = dir.to_path_buf();
        while current != stop_at {
            if std::fs::read_dir(&current)
                .map(|mut d| d.next().is_none())
                .unwrap_or(false)
            {
                let _ = std::fs::remove_dir(&current);
            } else {
                break;
            }
            if let Some(parent) = current.parent() {
                current = parent.to_path_buf();
            } else {
                break;
            }
        }
    }
}

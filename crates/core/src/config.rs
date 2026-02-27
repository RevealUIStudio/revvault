use std::env;
use std::path::PathBuf;

use crate::error::{Result, RevaultError};

/// Cross-platform configuration for store and identity paths.
pub struct Config {
    pub store_dir: PathBuf,
    pub identity_file: PathBuf,
    pub recipients_file: PathBuf,
}

impl Config {
    /// Resolve configuration from environment and platform defaults.
    ///
    /// Store resolution order:
    ///   1. `REVAULT_STORE` env var
    ///   2. `PASSAGE_DIR` env var (backwards compat)
    ///   3. `~/.revealui/passage-store`
    ///
    /// Identity resolution order:
    ///   1. `REVAULT_IDENTITY` env var
    ///   2. `~/.age-identity/keys.txt`
    pub fn resolve() -> Result<Self> {
        let store_dir = Self::resolve_store_dir()?;
        let identity_file = Self::resolve_identity_file()?;
        let recipients_file = store_dir.join(".age-recipients");

        Ok(Self {
            store_dir,
            identity_file,
            recipients_file,
        })
    }

    fn resolve_store_dir() -> Result<PathBuf> {
        if let Ok(path) = env::var("REVAULT_STORE") {
            let p = PathBuf::from(path);
            if p.is_dir() {
                return Ok(p);
            }
        }

        if let Ok(path) = env::var("PASSAGE_DIR") {
            let p = PathBuf::from(path);
            if p.is_dir() {
                return Ok(p);
            }
        }

        // Platform-aware default
        let home = home_dir()?;

        // On WSL, check /mnt/c path if we're under Linux
        let candidates = if cfg!(target_os = "linux") {
            vec![
                home.join(".revealui/passage-store"),
                PathBuf::from("/mnt/c/Users/joshu/.revealui/passage-store"),
            ]
        } else {
            vec![home.join(".revealui/passage-store")]
        };

        for candidate in &candidates {
            if candidate.is_dir() {
                return Ok(candidate.clone());
            }
        }

        Err(RevaultError::StoreNotFound(
            candidates
                .first()
                .cloned()
                .unwrap_or_else(|| PathBuf::from("~/.revealui/passage-store")),
        ))
    }

    fn resolve_identity_file() -> Result<PathBuf> {
        if let Ok(path) = env::var("REVAULT_IDENTITY") {
            let p = PathBuf::from(path);
            if p.is_file() {
                return Ok(p);
            }
        }

        let home = home_dir()?;

        let candidates = if cfg!(target_os = "linux") {
            vec![
                home.join(".age-identity/keys.txt"),
                PathBuf::from("/mnt/c/Users/joshu/.age-identity/keys.txt"),
            ]
        } else {
            vec![home.join(".age-identity/keys.txt")]
        };

        for candidate in &candidates {
            if candidate.is_file() {
                return Ok(candidate.clone());
            }
        }

        Err(RevaultError::IdentityNotFound(
            candidates
                .first()
                .cloned()
                .unwrap_or_else(|| PathBuf::from("~/.age-identity/keys.txt")),
        ))
    }
}

fn home_dir() -> Result<PathBuf> {
    dirs::home_dir().ok_or_else(|| {
        RevaultError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "could not determine home directory",
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_respects_env_vars() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("store");
        std::fs::create_dir_all(&store).unwrap();

        let id_file = dir.path().join("keys.txt");
        std::fs::write(&id_file, "# fake identity\n").unwrap();

        let recip_file = store.join(".age-recipients");
        std::fs::write(&recip_file, "age1fake\n").unwrap();

        unsafe {
            env::set_var("REVAULT_STORE", &store);
            env::set_var("REVAULT_IDENTITY", &id_file);
        }

        let config = Config::resolve().unwrap();
        assert_eq!(config.store_dir, store);
        assert_eq!(config.identity_file, id_file);

        unsafe {
            env::remove_var("REVAULT_STORE");
            env::remove_var("REVAULT_IDENTITY");
        }
    }
}

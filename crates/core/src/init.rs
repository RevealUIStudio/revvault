//! Vault initialization — create store directory, generate age identity.

use std::path::{Path, PathBuf};

use age::x25519;
use chrono::Utc;
use secrecy::ExposeSecret as _;

use crate::error::{Result, RevvaultError};

/// Summary returned after a successful `init_vault` call.
#[derive(Debug, Clone)]
pub struct InitSummary {
    /// Path to the created store directory.
    pub store_dir: PathBuf,
    /// Path to the identity (private key) file.
    pub identity_file: PathBuf,
    /// Age public key written to `.age-recipients`.
    pub public_key: String,
    /// True if the store directory already existed before this call.
    pub store_existed: bool,
    /// True if the identity file already existed before this call.
    pub identity_existed: bool,
}

/// Options for `init_vault`.
#[derive(Debug, Default)]
pub struct InitOptions {
    /// Override the default store location (`~/.revealui/passage-store`).
    pub store_dir: Option<PathBuf>,
    /// Override the default identity location (`~/.config/age/keys.txt`).
    pub identity_file: Option<PathBuf>,
}

/// Initialize a new vault.
///
/// - Creates the store directory if it does not exist.
/// - Generates a new age X25519 identity and writes it to `identity_file`
///   **only if the file does not already exist** (never overwrites).
/// - Writes the identity's public key to `<store_dir>/.age-recipients`
///   if the file does not already exist.
///
/// Safe to call on an already-initialized vault — it will not overwrite
/// existing keys.
pub fn init_vault(options: InitOptions) -> Result<InitSummary> {
    let store_dir = options.store_dir.unwrap_or_else(default_store_dir);

    let identity_file = options.identity_file.unwrap_or_else(default_identity_file);

    // --- Store directory ---
    let store_existed = store_dir.exists();
    if !store_existed {
        std::fs::create_dir_all(&store_dir)?;
        // Create the .revvault metadata directory too
        std::fs::create_dir_all(store_dir.join(".revvault"))?;
    }

    // --- Identity file ---
    let identity_existed = identity_file.exists();
    let public_key = if identity_existed {
        // Read the existing public key from the recipients file if available,
        // otherwise re-derive it from the identity file.
        read_existing_public_key(&store_dir, &identity_file)?
    } else {
        generate_and_write_identity(&identity_file)?
    };

    // --- Recipients file ---
    let recipients_file = store_dir.join(".age-recipients");
    if !recipients_file.exists() {
        std::fs::write(&recipients_file, format!("{}\n", public_key))?;
    }

    Ok(InitSummary {
        store_dir,
        identity_file,
        public_key,
        store_existed,
        identity_existed,
    })
}

/// Generate a fresh X25519 identity, write it to disk, return the public key.
fn generate_and_write_identity(path: &Path) -> Result<String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let identity = x25519::Identity::generate();
    let public_key = identity.to_public().to_string();
    let created_at = Utc::now().to_rfc3339();

    let contents = format!(
        "# created: {created_at}\n# public key: {public_key}\n{}\n",
        identity.to_string().expose_secret(),
    );

    std::fs::write(path, &contents)?;

    // Restrict permissions to owner-read-only on Unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(public_key)
}

/// Extract the public key from an existing setup.
/// Prefers the `.age-recipients` file; falls back to parsing the identity file.
fn read_existing_public_key(store_dir: &Path, identity_file: &Path) -> Result<String> {
    let recipients_file = store_dir.join(".age-recipients");

    // Try the recipients file first — it's already the public key.
    if recipients_file.exists() {
        let contents = std::fs::read_to_string(&recipients_file)?;
        if let Some(key) = contents
            .lines()
            .find(|l| !l.starts_with('#') && !l.trim().is_empty())
        {
            return Ok(key.trim().to_string());
        }
    }

    // Fall back to parsing the identity file.
    let contents = std::fs::read_to_string(identity_file)?;

    // Try the `# public key:` comment first (written by revvault init).
    for line in contents.lines() {
        if let Some(key) = line.strip_prefix("# public key: ") {
            return Ok(key.trim().to_string());
        }
    }

    // Last resort: parse a secret key line and re-derive the public key.
    if let Some(identity) = contents
        .lines()
        .find(|l| !l.starts_with('#') && !l.trim().is_empty())
        .and_then(|l| l.trim().parse::<x25519::Identity>().ok())
    {
        return Ok(identity.to_public().to_string());
    }

    Err(RevvaultError::Other(anyhow::anyhow!(
        "cannot determine public key from existing identity file — \
         file may be corrupt or use an unsupported format"
    )))
}

fn default_store_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".revealui/passage-store")
}

fn default_identity_file() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".config/age/keys.txt")
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret as _;

    fn opts(dir: &tempfile::TempDir) -> InitOptions {
        InitOptions {
            store_dir: Some(dir.path().join("store")),
            identity_file: Some(dir.path().join("keys.txt")),
        }
    }

    // ── fresh init ────────────────────────────────────────────────────────────

    #[test]
    fn fresh_init_creates_store_and_identity() {
        let tmp = tempfile::tempdir().unwrap();
        let summary = init_vault(opts(&tmp)).unwrap();

        assert!(!summary.store_existed);
        assert!(!summary.identity_existed);
        assert!(summary.store_dir.is_dir());
        assert!(summary.identity_file.is_file());
        assert!(summary.store_dir.join(".revvault").is_dir());
        assert!(summary.store_dir.join(".age-recipients").is_file());
        assert!(summary.public_key.starts_with("age1"));
    }

    #[test]
    fn fresh_init_recipients_file_contains_public_key() {
        let tmp = tempfile::tempdir().unwrap();
        let summary = init_vault(opts(&tmp)).unwrap();

        let recipients =
            std::fs::read_to_string(summary.store_dir.join(".age-recipients")).unwrap();
        assert!(recipients.contains(&summary.public_key));
    }

    #[test]
    fn fresh_init_identity_file_has_correct_permissions() {
        let tmp = tempfile::tempdir().unwrap();
        let summary = init_vault(opts(&tmp)).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&summary.identity_file)
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "identity file must be owner-read-only");
        }
    }

    // ── idempotency ───────────────────────────────────────────────────────────

    #[test]
    fn second_init_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let first = init_vault(opts(&tmp)).unwrap();
        let second = init_vault(opts(&tmp)).unwrap();

        assert!(second.store_existed);
        assert!(second.identity_existed);
        // Public key must be stable across calls.
        assert_eq!(first.public_key, second.public_key);
    }

    #[test]
    fn second_init_does_not_overwrite_identity_file() {
        let tmp = tempfile::tempdir().unwrap();
        init_vault(opts(&tmp)).unwrap();

        let identity_path = tmp.path().join("keys.txt");
        let before = std::fs::read_to_string(&identity_path).unwrap();
        init_vault(opts(&tmp)).unwrap();
        let after = std::fs::read_to_string(&identity_path).unwrap();

        assert_eq!(before, after);
    }

    // ── partial state: identity exists, store does not ────────────────────────

    #[test]
    fn init_with_existing_identity_no_store_reads_pubkey_from_comment() {
        let tmp = tempfile::tempdir().unwrap();

        // Pre-write an identity file with the `# public key:` comment.
        let identity = x25519::Identity::generate();
        let pubkey = identity.to_public().to_string();
        std::fs::write(
            tmp.path().join("keys.txt"),
            format!(
                "# public key: {pubkey}\n{}\n",
                identity.to_string().expose_secret()
            ),
        )
        .unwrap();

        let summary = init_vault(opts(&tmp)).unwrap();

        assert!(!summary.store_existed);
        assert!(summary.identity_existed);
        assert_eq!(summary.public_key, pubkey);
    }

    #[test]
    fn init_with_identity_missing_comment_derives_pubkey_from_secret_key() {
        let tmp = tempfile::tempdir().unwrap();

        // Write an identity file without the `# public key:` comment line.
        let identity = x25519::Identity::generate();
        let expected_pubkey = identity.to_public().to_string();
        std::fs::write(
            tmp.path().join("keys.txt"),
            format!(
                "# created: 2024-01-01\n{}\n",
                identity.to_string().expose_secret()
            ),
        )
        .unwrap();

        let summary = init_vault(opts(&tmp)).unwrap();

        assert_eq!(summary.public_key, expected_pubkey);
    }

    // ── partial state: store exists with recipients, identity exists ──────────

    #[test]
    fn init_with_existing_recipients_file_reads_pubkey_from_it() {
        let tmp = tempfile::tempdir().unwrap();

        // Create a store with a recipients file but no identity comment.
        let store = tmp.path().join("store");
        std::fs::create_dir_all(&store).unwrap();
        let identity = x25519::Identity::generate();
        let pubkey = identity.to_public().to_string();
        std::fs::write(store.join(".age-recipients"), format!("{pubkey}\n")).unwrap();

        // Write identity without the public key comment.
        std::fs::write(
            tmp.path().join("keys.txt"),
            format!("{}\n", identity.to_string().expose_secret()),
        )
        .unwrap();

        let summary = init_vault(opts(&tmp)).unwrap();

        assert_eq!(summary.public_key, pubkey);
    }
}

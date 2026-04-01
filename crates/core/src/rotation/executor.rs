//! Rotation executor — vault I/O + provider dispatch + log writing.
//!
//! The executor is the glue between the vault and rotation providers.
//! It reads the current key from the vault, builds the provider, runs
//! the rotation, writes the new key back, and appends a log entry.

use std::io::Write as _;

use chrono::Utc;
use secrecy::{ExposeSecret as _, SecretString};

use crate::error::Result;
use crate::rotation::config::ProviderConfig;
use crate::rotation::provider::RotationLogEntry;
use crate::rotation::providers::GenericHttpProvider;
use crate::rotation::RotationProvider;
use crate::store::PassageStore;

/// Vault path where a provider's key ID is stored between rotations.
/// e.g. `credentials/vercel/token` → `credentials/vercel/token-id`
fn key_id_path(secret_path: &str) -> String {
    format!("{secret_path}-id")
}

/// Run a full rotation for one provider.
///
/// Steps:
/// 1. Read current key from vault
/// 2. Read previous key ID from vault (if stored)
/// 3. Build and preflight the provider
/// 4. Execute rotation (create new key, revoke old key)
/// 5. Write new key to vault
/// 6. Write new key ID to vault (if provider returned one)
/// 7. Append log entry
pub async fn execute(
    store: &PassageStore,
    provider_name: &str,
    provider_config: &ProviderConfig,
) -> anyhow::Result<()> {
    // 1. Read current key
    let current_key = store
        .get(&provider_config.secret_path)
        .map_err(|e| anyhow::anyhow!("cannot read '{}': {e}", provider_config.secret_path))?;

    // 2. Read stored key ID from the previous rotation (optional)
    let id_path = key_id_path(&provider_config.secret_path);
    let old_key_id = store
        .get(&id_path)
        .ok()
        .map(|s| s.expose_secret().to_string());

    // 3. Build provider
    let provider = GenericHttpProvider::from_config(
        provider_name.to_string(),
        SecretString::from(current_key.expose_secret().to_string()),
        old_key_id,
        &provider_config.settings,
    )?;

    provider.preflight().await?;

    // 4. Rotate
    let outcome = provider.rotate().await?;

    // 5. Write new key
    store
        .upsert(
            &provider_config.secret_path,
            outcome.new_value.expose_secret().as_bytes(),
        )
        .map_err(|e| anyhow::anyhow!("cannot write new key to vault: {e}"))?;

    // 6. Write new key ID (enables revocation in the next rotation)
    if let Some(ref id) = outcome.new_key_id {
        store
            .upsert(&id_path, id.as_bytes())
            .map_err(|e| anyhow::anyhow!("cannot write key ID to vault: {e}"))?;
    }

    // 7. Append log entry
    append_log(store, provider_name, &provider_config.secret_path, &outcome.new_key_id)?;

    eprintln!(
        "✓ Rotated '{}' for provider '{}'",
        provider_config.secret_path, provider_name
    );
    if outcome.new_key_id.is_some() {
        eprintln!(
            "  Key ID stored at '{}' for next rotation",
            id_path
        );
    }

    Ok(())
}

/// Print a dry-run plan without touching the vault or any API.
pub async fn dry_run(
    store: &PassageStore,
    provider_name: &str,
    provider_config: &ProviderConfig,
) -> anyhow::Result<()> {
    let current_key = store
        .get(&provider_config.secret_path)
        .map_err(|e| anyhow::anyhow!("cannot read '{}': {e}", provider_config.secret_path))?;

    let id_path = key_id_path(&provider_config.secret_path);
    let old_key_id = store
        .get(&id_path)
        .ok()
        .map(|s| s.expose_secret().to_string());

    let provider = GenericHttpProvider::from_config(
        provider_name.to_string(),
        SecretString::from(current_key.expose_secret().to_string()),
        old_key_id,
        &provider_config.settings,
    )?;

    provider.preflight().await?;

    let plan = provider.dry_run().await?;
    eprintln!("[dry run] Rotation plan for provider '{provider_name}':\n{plan}");

    Ok(())
}

fn append_log(
    store: &PassageStore,
    provider: &str,
    secret_path: &str,
    new_key_id: &Option<String>,
) -> anyhow::Result<()> {
    let log_dir = store.store_dir().join(".revvault");
    std::fs::create_dir_all(&log_dir)?;

    let log_path = log_dir.join("rotation-log.jsonl");
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;

    let entry = RotationLogEntry {
        timestamp: Utc::now().to_rfc3339(),
        provider: provider.to_string(),
        secret_path: secret_path.to_string(),
        new_key_id: new_key_id.clone(),
        status: "success".into(),
    };

    let line = serde_json::to_string(&entry)?;
    writeln!(file, "{line}")?;

    Ok(())
}

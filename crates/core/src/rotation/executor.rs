//! Rotation executor — vault I/O + provider dispatch + log writing.
//!
//! The executor is the glue between the vault and rotation providers.
//! It reads the current key from the vault, builds the provider, runs
//! the rotation, writes the new key back, runs post-rotate hooks and
//! verification, and appends a log entry.

use std::io::Write as _;

use chrono::Utc;
use secrecy::{ExposeSecret as _, SecretString};

use crate::rotation::config::ProviderConfig;
use crate::rotation::provider::{RotationLogEntry, RotationOutcome};
use crate::rotation::providers::{GenericHttpProvider, LocalGeneratorProvider};
use crate::rotation::RotationProvider;
use crate::store::PassageStore;

/// Vault path where a provider's key ID is stored between rotations.
/// e.g. `credentials/vercel/token` → `credentials/vercel/token-id`
fn key_id_path(secret_path: &str) -> String {
    format!("{secret_path}-id")
}

/// Shared post-rotation logic: write outcome to vault, run hooks, verify, log.
///
/// Steps performed:
/// 1. Write new key to vault
/// 2. Write new key ID to vault (if present)
/// 3. Execute `post_rotate` shell commands (warn on failure, don't abort)
/// 4. Run `verify` command if configured (warn on failure, don't abort)
/// 5. Append rotation log entry
async fn finish_rotation(
    store: &PassageStore,
    provider_name: &str,
    provider_config: &ProviderConfig,
    outcome: &RotationOutcome,
) -> anyhow::Result<()> {
    let id_path = key_id_path(&provider_config.secret_path);

    // Step 5: Write new key
    store
        .upsert(
            &provider_config.secret_path,
            outcome.new_value.expose_secret().as_bytes(),
        )
        .map_err(|e| anyhow::anyhow!("cannot write new key to vault: {e}"))?;

    // Step 6: Write new key ID (enables revocation in the next rotation)
    if let Some(ref id) = outcome.new_key_id {
        store
            .upsert(&id_path, id.as_bytes())
            .map_err(|e| anyhow::anyhow!("cannot write key ID to vault: {e}"))?;
    }

    // Step 7: Execute post_rotate hooks
    for cmd in &provider_config.post_rotate {
        eprintln!("  Running post_rotate: {cmd}");
        match tokio::process::Command::new("sh")
            .args(["-c", cmd])
            .output()
            .await
        {
            Ok(output) if output.status.success() => {
                eprintln!("  ✓ post_rotate succeeded: {cmd}");
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                eprintln!(
                    "  ⚠ post_rotate command failed (exit {}): {cmd}\n    {stderr}",
                    output.status.code().unwrap_or(-1)
                );
            }
            Err(e) => {
                eprintln!("  ⚠ post_rotate command could not be executed: {cmd}\n    {e}");
            }
        }
    }

    // Step 8: Verify
    let verified = if let Some(ref verify_cmd) = provider_config.verify {
        eprintln!("  Running verify: {verify_cmd}");
        match tokio::process::Command::new("sh")
            .args(["-c", verify_cmd])
            .output()
            .await
        {
            Ok(output) if output.status.success() => {
                eprintln!("  ✓ Verification passed for '{provider_name}'");
                Some(true)
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                eprintln!(
                    "  ⚠ Verification failed for '{provider_name}' — new key is active but may need manual verification\n    exit {}: {stderr}",
                    output.status.code().unwrap_or(-1)
                );
                Some(false)
            }
            Err(e) => {
                eprintln!(
                    "  ⚠ Verification failed for '{provider_name}' — new key is active but may need manual verification\n    {e}"
                );
                Some(false)
            }
        }
    } else {
        None
    };

    // Step 9: Append log entry
    append_log(
        store,
        provider_name,
        &provider_config.secret_path,
        &outcome.new_key_id,
        verified,
    )?;

    eprintln!(
        "✓ Rotated '{}' for provider '{}'",
        provider_config.secret_path, provider_name
    );
    if outcome.new_key_id.is_some() {
        eprintln!("  Key ID stored at '{}' for next rotation", id_path);
    }

    Ok(())
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
/// 7. Execute post_rotate hooks
/// 8. Run verify command
/// 9. Append log entry
pub async fn execute(
    store: &PassageStore,
    provider_name: &str,
    provider_config: &ProviderConfig,
) -> anyhow::Result<()> {
    // Dispatch: local generator vs HTTP provider
    if let Some(gen_type) = provider_config.settings.get("generator_type") {
        let provider = LocalGeneratorProvider::new(provider_name.to_string(), gen_type)?;
        provider.preflight().await?;
        let outcome = provider.rotate().await?;
        finish_rotation(store, provider_name, provider_config, &outcome).await?;
    } else {
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

        // 5-9. Vault write + hooks + verify + log
        finish_rotation(store, provider_name, provider_config, &outcome).await?;
    }

    Ok(())
}

/// Print a dry-run plan without touching the vault or any API.
pub async fn dry_run(
    store: &PassageStore,
    provider_name: &str,
    provider_config: &ProviderConfig,
) -> anyhow::Result<()> {
    if let Some(gen_type) = provider_config.settings.get("generator_type") {
        let provider = LocalGeneratorProvider::new(provider_name.to_string(), gen_type)?;
        provider.preflight().await?;
        let plan = provider.dry_run().await?;
        eprintln!("[dry run] Rotation plan for provider '{provider_name}':\n{plan}");
    } else {
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
    }

    if !provider_config.post_rotate.is_empty() {
        eprintln!(
            "[dry run] post_rotate hooks ({} command{}):",
            provider_config.post_rotate.len(),
            if provider_config.post_rotate.len() == 1 { "" } else { "s" }
        );
        for cmd in &provider_config.post_rotate {
            eprintln!("  - {cmd}");
        }
    }

    if let Some(ref verify_cmd) = provider_config.verify {
        eprintln!("[dry run] verify: {verify_cmd}");
    }

    Ok(())
}

fn append_log(
    store: &PassageStore,
    provider: &str,
    secret_path: &str,
    new_key_id: &Option<String>,
    verified: Option<bool>,
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
        verified,
    };

    let line = serde_json::to_string(&entry)?;
    writeln!(file, "{line}")?;

    Ok(())
}

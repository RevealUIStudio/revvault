//! Rotation executor — vault I/O + provider dispatch + log writing.
//!
//! The executor is the glue between the vault and rotation providers.
//! It reads the current key from the vault, builds the provider, runs
//! the rotation, writes the new key back, runs the sync hook, the
//! `post_rotate` user hooks, the `verify` gate, and finally appends a
//! log entry.
//!
//! # Failure semantics
//!
//! - The `apply_sync_after_rotation` step is infallible at the function
//!   level — sync target failures land as log rows + stderr warnings.
//! - `post_rotate` hooks are warn-on-failure — a failing hook does not
//!   abort the rotation (the new key is already in the vault).
//! - The `verify` step is **strict** — a failing verify writes a log
//!   entry with `verified: false` and then the executor returns Err so
//!   the cli exits non-zero. Vault state is unchanged.

use std::io::Write as _;

use chrono::Utc;
use secrecy::{ExposeSecret as _, SecretString};

use crate::rotation::config::ProviderConfig;
use crate::rotation::provider::RotationLogEntry;
use crate::rotation::providers::build_provider;
use crate::rotation::sync_hook::{self, SyncLogEntry};
use crate::store::PassageStore;
use crate::sync::shape::{self, Shape};

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
/// 3. Build and preflight the provider (factory in `providers::build_provider`)
/// 4. Execute rotation (create new key, revoke old key)
/// 5. Write new key to vault
/// 6. Write new key ID to vault (if provider returned one)
/// 7. Apply post-rotation sync hook (if `[sync.*]` configured)
/// 8. Run `post_rotate` user hooks (warn-on-failure)
/// 9. Run `verify` gate (strict — Err on failure)
/// 10. Append log entry
pub async fn execute(
    store: &PassageStore,
    provider_name: &str,
    provider_config: &ProviderConfig,
) -> anyhow::Result<()> {
    let id_path = key_id_path(&provider_config.secret_path);
    let is_local = provider_config.settings.get("type").map(String::as_str) == Some("local");

    // 1-2. Read current key + previous key ID (skipped for `type=local`,
    //      whose generator doesn't depend on prior state — first-rotation
    //      cases would otherwise fail when the path is empty).
    let (current_key_for_provider, old_key_id) = if is_local {
        (SecretString::from(String::new()), None)
    } else {
        let current = store
            .get(&provider_config.secret_path)
            .map_err(|e| anyhow::anyhow!("cannot read '{}': {e}", provider_config.secret_path))?;
        let id = store
            .get(&id_path)
            .ok()
            .map(|s| s.expose_secret().to_string());
        (SecretString::from(current.expose_secret().to_string()), id)
    };

    // 3. Build provider via factory dispatch on settings["type"].
    let provider = build_provider(
        store,
        provider_name.to_string(),
        current_key_for_provider,
        old_key_id,
        &provider_config.settings,
    )?;

    provider.preflight().await?;

    // 4. Rotate
    let outcome = provider.rotate().await?;

    // 5. Validate output shape before writing to vault.
    //    Universal structural checks (empty / null / envelope) always run.
    //    Per-shape check runs when `output_shape` is declared.
    //    On mismatch the rotation ABORTS — old key remains in vault.
    {
        let declared = provider_config.output_shape.unwrap_or(Shape::Any);
        let raw = outcome.new_value.expose_secret();
        if let Err(violation) = shape::check(raw, declared) {
            return Err(anyhow::anyhow!(
                "rotation provider '{}' returned a value that failed shape validation \
                 ({}); rotation aborted — old key is unchanged. \
                 Shape category: {}",
                provider_name,
                violation,
                shape::classify(raw),
            ));
        }
    }

    // 5b. Write new key
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

    // 7. Post-rotation sync hook. The vault is already on the
    // new value at this point; sync is best-effort and infallible
    // at the function level (failures land as log entries). We
    // surface partial failures to stderr so the operator knows to
    // run `revvault sync vercel --apply` to retry.
    let sync_log: Option<Vec<SyncLogEntry>> = if let Some(sync_cfg) = &provider_config.sync {
        let entries =
            sync_hook::apply_sync_after_rotation(store, sync_cfg, &outcome.new_value).await;
        for row in &entries {
            if row.status != "success" {
                eprintln!(
                    "  ⚠ Sync to {} failed for {}/{}: {}",
                    row.target,
                    row.env_var,
                    row.vercel_target,
                    row.error.as_deref().unwrap_or("(no error message)"),
                );
            }
        }
        if entries.iter().any(|r| r.status != "success") {
            eprintln!("  Vault is correct but at least one sync target lagged. Retry with:");
            eprintln!("    revvault sync vercel --apply --manifest <path>");
        }
        Some(entries)
    } else {
        None
    };

    // 8. post_rotate user hooks (warn-on-failure)
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
                    "  ⚠ post_rotate command failed (exit {}): {cmd}\n    {}",
                    output.status.code().unwrap_or(-1),
                    stderr.trim()
                );
            }
            Err(e) => {
                eprintln!("  ⚠ post_rotate command could not be executed: {cmd}\n    {e}");
            }
        }
    }

    // 9. verify gate (STRICT — Err on failure)
    let verified: Option<bool> = match &provider_config.verify {
        None => None,
        Some(verify_cmd) => {
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
                    let exit_code = output.status.code().unwrap_or(-1);
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    let stderr_trim = stderr.trim();

                    // Write log entry with verified=Some(false) BEFORE returning Err
                    // so the audit trail records the failed verification.
                    append_log(
                        store,
                        provider_name,
                        &provider_config.secret_path,
                        &outcome.new_key_id,
                        sync_log,
                        Some(false),
                    )?;

                    eprintln!(
                        "  ✗ Verification FAILED for '{provider_name}' (exit {exit_code}): {stderr_trim}"
                    );
                    return Err(anyhow::anyhow!(
                        "verify command exited non-zero (code {exit_code}): {verify_cmd}"
                    ));
                }
                Err(e) => {
                    // Spawn / I/O failure — also strict.
                    append_log(
                        store,
                        provider_name,
                        &provider_config.secret_path,
                        &outcome.new_key_id,
                        sync_log,
                        Some(false),
                    )?;

                    eprintln!(
                        "  ✗ Verify command could not be executed for '{provider_name}': {e}"
                    );
                    return Err(anyhow::anyhow!(
                        "verify command could not be executed: {verify_cmd}: {e}"
                    ));
                }
            }
        }
    };

    // 10. Append log entry (success path)
    append_log(
        store,
        provider_name,
        &provider_config.secret_path,
        &outcome.new_key_id,
        sync_log,
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

/// Print a dry-run plan without touching the vault or any API.
pub async fn dry_run(
    store: &PassageStore,
    provider_name: &str,
    provider_config: &ProviderConfig,
) -> anyhow::Result<()> {
    let id_path = key_id_path(&provider_config.secret_path);
    let is_local = provider_config.settings.get("type").map(String::as_str) == Some("local");

    let (current_key_for_provider, old_key_id) = if is_local {
        (SecretString::from(String::new()), None)
    } else {
        let current = store
            .get(&provider_config.secret_path)
            .map_err(|e| anyhow::anyhow!("cannot read '{}': {e}", provider_config.secret_path))?;
        let id = store
            .get(&id_path)
            .ok()
            .map(|s| s.expose_secret().to_string());
        (SecretString::from(current.expose_secret().to_string()), id)
    };

    let provider = build_provider(
        store,
        provider_name.to_string(),
        current_key_for_provider,
        old_key_id,
        &provider_config.settings,
    )?;

    provider.preflight().await?;

    let plan = provider.dry_run().await?;
    eprintln!("[dry run] Rotation plan for provider '{provider_name}':\n{plan}");

    if !provider_config.post_rotate.is_empty() {
        eprintln!(
            "[dry run] post_rotate hooks ({} command{}):",
            provider_config.post_rotate.len(),
            if provider_config.post_rotate.len() == 1 {
                ""
            } else {
                "s"
            }
        );
        for cmd in &provider_config.post_rotate {
            eprintln!("  - {cmd}");
        }
    }

    if let Some(ref verify_cmd) = provider_config.verify {
        eprintln!("[dry run] verify (strict): {verify_cmd}");
    }

    Ok(())
}

fn append_log(
    store: &PassageStore,
    provider: &str,
    secret_path: &str,
    new_key_id: &Option<String>,
    sync: Option<Vec<SyncLogEntry>>,
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
        sync,
        verified,
    };

    let line = serde_json::to_string(&entry)?;
    writeln!(file, "{line}")?;

    Ok(())
}

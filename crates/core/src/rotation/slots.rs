//! Dual-slot path helpers and promote (GAP-261 residual).
//!
//! Convention (design §3.1 / §3.6):
//! - live:      `secret_path` (+ optional companion `public_key_path`)
//! - next:      `{path}-next`   — written by dual-slot rotate
//! - previous:  `{path}-previous` — outgoing live snapshot before promote

use secrecy::{ExposeSecret as _, SecretString};

use crate::store::PassageStore;

/// Suffixes for dual-slot leaves.
pub const NEXT_SUFFIX: &str = "-next";
pub const PREVIOUS_SUFFIX: &str = "-previous";

/// `{base}-next`
pub fn next_path(base: &str) -> String {
    format!("{base}{NEXT_SUFFIX}")
}

/// `{base}-previous`
pub fn previous_path(base: &str) -> String {
    format!("{base}{PREVIOUS_SUFFIX}")
}

/// Copy vault leaf `from` → `to` when `from` exists. No-op if missing.
fn copy_if_present(store: &PassageStore, from: &str, to: &str) -> anyhow::Result<()> {
    match store.get(from) {
        Ok(val) => {
            store
                .upsert(to, val.expose_secret().as_bytes())
                .map_err(|e| anyhow::anyhow!("cannot write '{to}': {e}"))?;
            Ok(())
        }
        Err(_) => Ok(()),
    }
}

/// Dual-slot rotate write: live → previous (if present), new value → next.
/// Live is never overwritten.
pub fn write_dual_slot_primary(
    store: &PassageStore,
    secret_path: &str,
    new_value: &SecretString,
) -> anyhow::Result<String> {
    let next = next_path(secret_path);
    let prev = previous_path(secret_path);
    copy_if_present(store, secret_path, &prev)?;
    store
        .upsert(&next, new_value.expose_secret().as_bytes())
        .map_err(|e| anyhow::anyhow!("cannot write dual-slot next '{next}': {e}"))?;
    Ok(next)
}

/// Dual-slot companion write (e.g. public SPKI): same live→previous, new→next.
pub fn write_dual_slot_companion(
    store: &PassageStore,
    companion_path: &str,
    new_value: &SecretString,
) -> anyhow::Result<()> {
    let next = next_path(companion_path);
    let prev = previous_path(companion_path);
    copy_if_present(store, companion_path, &prev)?;
    store
        .upsert(&next, new_value.expose_secret().as_bytes())
        .map_err(|e| anyhow::anyhow!("cannot write dual-slot companion next '{next}': {e}"))?;
    Ok(())
}

/// Promote: next → live, old live → previous, clear next.
/// Returns the promoted primary value (for legacy path mirrors).
pub fn promote_leaf(store: &PassageStore, base: &str) -> anyhow::Result<SecretString> {
    let next = next_path(base);
    let prev = previous_path(base);
    let next_val = store.get(&next).map_err(|e| {
        anyhow::anyhow!("promote requires '{next}' (run dual-slot rotate first): {e}")
    })?;

    // Snapshot current live into previous (if any).
    copy_if_present(store, base, &prev)?;

    store
        .upsert(base, next_val.expose_secret().as_bytes())
        .map_err(|e| anyhow::anyhow!("cannot write promoted live '{base}': {e}"))?;

    // Clear next so a second promote fails closed until another rotate.
    let _ = store.delete(&next);

    Ok(next_val)
}

/// Mirror a live leaf onto additional vault paths (legacy revforge paths).
pub fn mirror_live_to_paths(
    store: &PassageStore,
    live: &SecretString,
    paths: &[String],
) -> anyhow::Result<()> {
    for path in paths {
        let p = path.trim();
        if p.is_empty() {
            continue;
        }
        store
            .upsert(p, live.expose_secret().as_bytes())
            .map_err(|e| anyhow::anyhow!("cannot mirror to legacy path '{p}': {e}"))?;
    }
    Ok(())
}

/// Parse comma-separated path list from settings.
pub fn parse_path_list(raw: Option<&String>) -> Vec<String> {
    raw.map(|s| {
        s.split(',')
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect()
    })
    .unwrap_or_default()
}

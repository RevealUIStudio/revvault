use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use anyhow::{bail, Context};
use chrono::Utc;
use clap::Args;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

use revvault_core::sync::fly::FlyClient;
use revvault_core::sync::shape::{self, Shape};
use revvault_core::sync::vercel::{VercelClient, VercelEnvVar};
use revvault_core::{Config, PassageStore};

// ── CLI args ────────────────────────────────────────────────────────────────

#[derive(Args)]
pub struct SyncArgs {
    /// Target to sync with: "vercel" or "fly"
    pub target: String,

    /// Path to the sync manifest (default: revvault-vercel.toml)
    #[arg(long, default_value = "revvault-vercel.toml")]
    pub manifest: PathBuf,

    /// Apply changes (default is dry-run)
    #[arg(long)]
    pub apply: bool,

    /// API token for the target (or set VERCEL_TOKEN / FLY_API_TOKEN env var)
    #[arg(long)]
    pub token: Option<String>,
}

// ── TOML manifest schema ────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct SyncManifest {
    /// Vercel team ID or slug (optional for personal accounts)
    team_id: Option<String>,
    /// Map of project slug → project sync config
    #[serde(default)]
    projects: HashMap<String, ProjectSync>,
}

#[derive(Debug, Deserialize)]
struct ProjectSync {
    /// Vercel project ID
    project_id: String,
    /// Vault path prefix for this project's secrets (e.g., "revealui/vercel/admin")
    vault_prefix: String,
    /// Environment targets: production, preview, development
    #[serde(default = "default_targets")]
    targets: Vec<String>,
    /// Skip these env var names (integration-managed, etc.)
    #[serde(default)]
    skip: Vec<String>,
    /// Per-var path + optional shape overrides.
    ///
    /// Supports two TOML forms for backwards compatibility:
    ///
    /// Bare string (path only, shape defaults to `any`):
    /// ```toml
    /// [projects.api.vars]
    /// POSTGRES_URL = "revealui/prod/db/postgres-url"
    /// ```
    ///
    /// Inline table (path + explicit shape):
    /// ```toml
    /// [projects.api.vars]
    /// POSTGRES_URL = { path = "revealui/prod/db/postgres-url", shape = "postgres-url" }
    /// ```
    #[serde(default)]
    vars: HashMap<String, VarEntry>,
}

/// A per-var entry in `[projects.<slug>.vars]`.
///
/// `#[serde(untagged)]` makes TOML bare strings parse as `Path(String)`
/// while inline tables parse as `Object { path, shape }`. Existing manifests
/// that use bare strings keep working unchanged.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum VarEntry {
    /// Bare string — path only; shape defaults to `Shape::Any`.
    Path(String),
    /// Inline table — path + explicit shape constraint.
    Object { path: String, shape: Shape },
}

impl VarEntry {
    fn path(&self) -> &str {
        match self {
            Self::Path(p) => p,
            Self::Object { path, .. } => path,
        }
    }

    fn shape(&self) -> Shape {
        match self {
            Self::Path(_) => Shape::Any,
            Self::Object { shape, .. } => *shape,
        }
    }
}

impl ProjectSync {
    /// Resolve the vault path + declared shape for a given Vercel var name.
    /// Returns the override if one is set in `vars`, otherwise the
    /// prefix-derived default with `Shape::Any`.
    fn vault_path_for(&self, var_name: &str) -> (String, Shape) {
        match self.vars.get(var_name) {
            Some(entry) => (entry.path().to_string(), entry.shape()),
            None => (format!("{}/{}", self.vault_prefix, var_name), Shape::Any),
        }
    }
}

fn default_targets() -> Vec<String> {
    vec![
        "production".to_string(),
        "preview".to_string(),
        "development".to_string(),
    ]
}

// ── Fly manifest schema ───────────────────────────────────────────────────────
//
// Fly secrets are app-scoped (no per-environment "targets") and the API never
// returns secret *values* — only names + an opaque digest. So the Fly manifest
// is app-centric and lists an explicit curated set of secrets (no prefix-scan:
// we never want to push every secret under a prefix onto a worker app).

#[derive(Debug, Deserialize)]
struct FlyManifest {
    /// Map of logical name → Fly app sync config (TOML `[fly-apps.<name>]`).
    #[serde(default, rename = "fly-apps")]
    fly_apps: HashMap<String, FlyAppSync>,
}

#[derive(Debug, Deserialize)]
struct FlyAppSync {
    /// Fly app name (used as the GraphQL `appId`).
    app: String,
    /// Secret names this sync intentionally never touches.
    #[serde(default)]
    skip: Vec<String>,
    /// Secret name → vault path (+ optional shape), reusing [`VarEntry`].
    /// Every managed secret must be listed — there is no prefix fallback.
    #[serde(default)]
    vars: HashMap<String, VarEntry>,
}

impl FlyAppSync {
    /// Resolve the vault path + declared shape for a Fly secret name, or
    /// `None` when the name is not declared in `vars`.
    fn vault_path_for(&self, var_name: &str) -> Option<(String, Shape)> {
        self.vars
            .get(var_name)
            .map(|entry| (entry.path().to_string(), entry.shape()))
    }
}

// ── Diff engine ─────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
enum DiffAction {
    Add,
    Update,
    Match,
    Orphan,
    Skip,
    DropShape,
}

#[derive(Debug, Serialize)]
struct DiffEntry {
    key: String,
    action: DiffAction,
    reason: Option<String>,
}

// ── Audit log ───────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct AuditEntry {
    timestamp: String,
    /// One of: "create", "update", "match", "drop-shape", "skip"
    action: String,
    project: String,
    key: String,
    /// Shape category of the vault value (e.g. "postgres-url", "stripe-key",
    /// "vercel-envelope", "empty"). Never the value itself.
    value_shape: String,
    /// "ok" | "failed"
    result: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn append_audit_log(entry: &AuditEntry) -> anyhow::Result<()> {
    let config = Config::resolve()?;
    let log_path = PathBuf::from(&config.store_dir).join(".revvault/rotation-log.jsonl");
    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;
    writeln!(file, "{}", serde_json::to_string(entry)?)?;
    Ok(())
}

// ── Main runner ─────────────────────────────────────────────────────────────

pub async fn run(args: SyncArgs, json_output: bool) -> anyhow::Result<()> {
    match args.target.as_str() {
        "vercel" => run_vercel(args, json_output).await,
        "fly" => run_fly(args, json_output).await,
        other => bail!("Unknown sync target '{}'. Supported: vercel, fly", other),
    }
}

async fn run_vercel(args: SyncArgs, json_output: bool) -> anyhow::Result<()> {
    let token = args
        .token
        .or_else(|| std::env::var("VERCEL_TOKEN").ok())
        .ok_or_else(|| {
            anyhow::anyhow!("VERCEL_TOKEN not set. Pass --token or set VERCEL_TOKEN env var")
        })?;

    let manifest_content = fs::read_to_string(&args.manifest)
        .with_context(|| format!("Cannot read manifest: {}", args.manifest.display()))?;
    let manifest: SyncManifest =
        toml::from_str(&manifest_content).context("Invalid manifest TOML")?;

    let config = Config::resolve()?;
    let store = PassageStore::open(config)?;
    let client = VercelClient::new(token, manifest.team_id.clone());

    push_mode(&store, &client, &manifest, args.apply, json_output).await
}

async fn run_fly(args: SyncArgs, json_output: bool) -> anyhow::Result<()> {
    let token = args
        .token
        .or_else(|| std::env::var("FLY_API_TOKEN").ok())
        .ok_or_else(|| {
            anyhow::anyhow!("FLY_API_TOKEN not set. Pass --token or set FLY_API_TOKEN env var")
        })?;

    let manifest_content = fs::read_to_string(&args.manifest)
        .with_context(|| format!("Cannot read manifest: {}", args.manifest.display()))?;
    let manifest: FlyManifest =
        toml::from_str(&manifest_content).context("Invalid Fly manifest TOML")?;
    validate_fly_manifest(&manifest, &args.manifest)?;

    let config = Config::resolve()?;
    let store = PassageStore::open(config)?;
    let client = FlyClient::new(token);

    push_mode_fly(&store, &client, &manifest, args.apply, json_output).await
}

/// Reject a Fly manifest that declares no `[fly-apps.<name>]` entries.
///
/// `FlyManifest` ignores unknown fields and `fly_apps` defaults to empty, so
/// pointing `sync fly` at a non-Fly manifest — e.g. the default Vercel manifest
/// (`revvault-vercel.toml`) — would otherwise deserialize cleanly and sync
/// nothing, silently skipping expected rotation under `--apply`. Surface that
/// mis-targeting as a loud error instead.
fn validate_fly_manifest(manifest: &FlyManifest, path: &std::path::Path) -> anyhow::Result<()> {
    if manifest.fly_apps.is_empty() {
        anyhow::bail!(
            "No [fly-apps.<name>] entries found in {}. `sync fly` requires a Fly manifest; the default manifest is the Vercel manifest (revvault-vercel.toml). Pass --manifest <fly-manifest> or add a [fly-apps.<name>] section.",
            path.display()
        );
    }
    Ok(())
}

// ── Push mode: sync vault to Vercel ─────────────────────────────────────────

async fn push_mode(
    store: &PassageStore,
    client: &VercelClient,
    manifest: &SyncManifest,
    apply: bool,
    json_output: bool,
) -> anyhow::Result<()> {
    for (project_name, project_cfg) in &manifest.projects {
        let remote_vars = client.list_env_vars(&project_cfg.project_id).await?;

        // Attempt to fetch decrypted values for MATCH detection. Falls back
        // to None when the token lacks `env:read:decrypted` scope (403),
        // which causes all existing vars to be treated as needing an update.
        //
        // Filter by the configured targets before collapsing by key — same
        // as `remote_map` below. Without this, a row for a non-synced target
        // (e.g. preview) could win the per-key collapse and a stale value on
        // our actual target (e.g. production) would be falsely classified as
        // a MATCH and skipped, leaving the synced target outdated.
        let remote_decrypted_map: Option<HashMap<String, String>> = match client
            .list_env_vars_with_values(&project_cfg.project_id)
            .await
        {
            Ok(Some(vars)) => Some(
                vars.into_iter()
                    .filter(|v| project_cfg.targets.iter().any(|t| v.target.contains(t)))
                    .filter_map(|v| v.value.map(|val| (v.key, val)))
                    .collect(),
            ),
            Ok(None) => None,
            Err(_) => None,
        };

        let remote_map: HashMap<String, &VercelEnvVar> = remote_vars
            .iter()
            .filter(|v| project_cfg.targets.iter().any(|t| v.target.contains(t)))
            .map(|v| (v.key.clone(), v))
            .collect();

        // Build the union of vars to sync: explicit overrides + everything
        // under the project's vault_prefix.
        let mut vault_var_names: Vec<String> = Vec::new();
        for var_name in project_cfg.vars.keys() {
            vault_var_names.push(var_name.clone());
        }
        let prefix_secrets = store.list(Some(&project_cfg.vault_prefix))?;
        for entry in &prefix_secrets {
            let var_name = entry
                .path
                .strip_prefix(&format!("{}/", project_cfg.vault_prefix))
                .unwrap_or(&entry.path)
                .to_string();
            if !project_cfg.vars.contains_key(&var_name) {
                vault_var_names.push(var_name);
            }
        }

        let mut diff: Vec<DiffEntry> = Vec::new();

        // Compare vault → remote
        for var_name in &vault_var_names {
            if project_cfg.skip.contains(var_name) {
                diff.push(DiffEntry {
                    key: var_name.clone(),
                    action: DiffAction::Skip,
                    reason: Some("in skip list".to_string()),
                });
                continue;
            }

            let (vault_path, declared_shape) = project_cfg.vault_path_for(var_name);

            // Read and validate the vault value before deciding the diff action.
            let secret_result = store.get(&vault_path);
            let vault_value = match secret_result {
                Ok(s) => s,
                Err(e) => {
                    if !json_output {
                        eprintln!(
                            "  \x1b[31m✗\x1b[0m {} — cannot read vault path {}: {}",
                            var_name, vault_path, e
                        );
                    }
                    continue;
                }
            };

            let raw_value = vault_value.expose_secret();
            let violation = shape::check(raw_value, declared_shape).err();

            if let Some(ref v) = violation {
                diff.push(DiffEntry {
                    key: var_name.clone(),
                    action: DiffAction::DropShape,
                    reason: Some(format!("shape violation: {v}")),
                });
                continue;
            }

            if remote_map.contains_key(var_name) {
                // Check for MATCH: if decrypted remote value equals vault value, skip the write.
                let is_match = remote_decrypted_map
                    .as_ref()
                    .and_then(|m| m.get(var_name))
                    .map(|remote_val| remote_val == raw_value)
                    .unwrap_or(false);

                if is_match {
                    diff.push(DiffEntry {
                        key: var_name.clone(),
                        action: DiffAction::Match,
                        reason: None,
                    });
                } else {
                    diff.push(DiffEntry {
                        key: var_name.clone(),
                        action: DiffAction::Update,
                        reason: None,
                    });
                }
            } else {
                diff.push(DiffEntry {
                    key: var_name.clone(),
                    action: DiffAction::Add,
                    reason: None,
                });
            }
        }

        // Detect orphans (in Vercel but not in vault).
        let mut seen_orphans: std::collections::HashSet<String> = std::collections::HashSet::new();
        for remote_var in remote_map.values() {
            if project_cfg.skip.contains(&remote_var.key) {
                continue;
            }
            if remote_var.configuration_id.is_some() {
                continue;
            }
            if !vault_var_names.contains(&remote_var.key) && !seen_orphans.contains(&remote_var.key)
            {
                seen_orphans.insert(remote_var.key.clone());
                diff.push(DiffEntry {
                    key: remote_var.key.clone(),
                    action: DiffAction::Orphan,
                    reason: Some("in Vercel but not in vault".to_string()),
                });
            }
        }

        // Output diff
        if json_output {
            println!(
                "{}",
                serde_json::json!({
                    "project": project_name,
                    "mode": "push",
                    "dry_run": !apply,
                    "diff": diff,
                })
            );
        } else {
            println!(
                "\n\x1b[1m{}\x1b[0m (push{})",
                project_name,
                if apply { "" } else { " — dry-run" }
            );
            for entry in &diff {
                let (symbol, color) = match entry.action {
                    DiffAction::Add => ("+", "\x1b[32m"),
                    DiffAction::Update => ("~", "\x1b[33m"),
                    DiffAction::Match => ("=", "\x1b[90m"),
                    DiffAction::Orphan => ("!", "\x1b[31m"),
                    DiffAction::Skip => ("-", "\x1b[90m"),
                    DiffAction::DropShape => ("✗", "\x1b[31m"),
                };
                let reason = entry
                    .reason
                    .as_deref()
                    .map(|r| format!(" ({})", r))
                    .unwrap_or_default();
                println!("  {}{}\x1b[0m {}{}", color, symbol, entry.key, reason);
            }
        }

        // Apply changes
        if apply {
            for entry in &diff {
                let (vault_path, declared_shape) = project_cfg.vault_path_for(&entry.key);
                match entry.action {
                    DiffAction::Add => {
                        let secret = store.get(&vault_path)?;
                        let raw = secret.expose_secret();

                        // Shape guard (should already be DROP'd in diff, but be defensive)
                        if let Err(v) = shape::check(raw, declared_shape) {
                            let _ = append_audit_log(&AuditEntry {
                                timestamp: Utc::now().to_rfc3339(),
                                action: "drop-shape".to_string(),
                                project: project_name.clone(),
                                key: entry.key.clone(),
                                value_shape: shape::classify(raw),
                                result: "failed".to_string(),
                                error: Some(v.to_string()),
                            });
                            continue;
                        }

                        client
                            .create_env_var(
                                &project_cfg.project_id,
                                &entry.key,
                                raw,
                                &project_cfg.targets,
                            )
                            .await?;
                        let _ = append_audit_log(&AuditEntry {
                            timestamp: Utc::now().to_rfc3339(),
                            action: "create".to_string(),
                            project: project_name.clone(),
                            key: entry.key.clone(),
                            value_shape: shape::classify(raw),
                            result: "ok".to_string(),
                            error: None,
                        });
                    }
                    DiffAction::Update => {
                        let secret = store.get(&vault_path)?;
                        let raw = secret.expose_secret();

                        if let Err(v) = shape::check(raw, declared_shape) {
                            let _ = append_audit_log(&AuditEntry {
                                timestamp: Utc::now().to_rfc3339(),
                                action: "drop-shape".to_string(),
                                project: project_name.clone(),
                                key: entry.key.clone(),
                                value_shape: shape::classify(raw),
                                result: "failed".to_string(),
                                error: Some(v.to_string()),
                            });
                            continue;
                        }

                        if let Some(remote) = remote_map.get(&entry.key) {
                            if let Some(ref id) = remote.id {
                                client
                                    .update_env_var(
                                        &project_cfg.project_id,
                                        id,
                                        raw,
                                        &project_cfg.targets,
                                    )
                                    .await?;
                                let _ = append_audit_log(&AuditEntry {
                                    timestamp: Utc::now().to_rfc3339(),
                                    action: "update".to_string(),
                                    project: project_name.clone(),
                                    key: entry.key.clone(),
                                    value_shape: shape::classify(raw),
                                    result: "ok".to_string(),
                                    error: None,
                                });
                            }
                        }
                    }
                    DiffAction::Match => {
                        let secret = store.get(&vault_path)?;
                        let raw = secret.expose_secret();
                        let _ = append_audit_log(&AuditEntry {
                            timestamp: Utc::now().to_rfc3339(),
                            action: "match".to_string(),
                            project: project_name.clone(),
                            key: entry.key.clone(),
                            value_shape: shape::classify(raw),
                            result: "ok".to_string(),
                            error: None,
                        });
                    }
                    DiffAction::DropShape => {
                        if !json_output {
                            eprintln!(
                                "  \x1b[31m✗\x1b[0m DROP {}: {}",
                                entry.key,
                                entry.reason.as_deref().unwrap_or("")
                            );
                        }
                        if let Ok(secret) = store.get(&vault_path) {
                            let raw = secret.expose_secret();
                            let _ = append_audit_log(&AuditEntry {
                                timestamp: Utc::now().to_rfc3339(),
                                action: "drop-shape".to_string(),
                                project: project_name.clone(),
                                key: entry.key.clone(),
                                value_shape: shape::classify(raw),
                                result: "failed".to_string(),
                                error: entry.reason.clone(),
                            });
                        }
                    }
                    DiffAction::Orphan => {
                        if !json_output {
                            println!(
                                "  \x1b[31m⚠\x1b[0m  Orphan: {} (not deleted — remove manually or add to vault)",
                                entry.key
                            );
                        }
                    }
                    DiffAction::Skip => {}
                }
            }

            let applied = diff
                .iter()
                .filter(|e| matches!(e.action, DiffAction::Add | DiffAction::Update))
                .count();
            if !json_output {
                println!("  {} changes applied", applied);
            }
        }
    }

    Ok(())
}

// ── Push mode (Fly): batch vault → Fly setSecrets ────────────────────────────
//
// Fly hides secret values, so there is no value-equality MATCH: a present name
// is an Update (re-set), an absent one an Add. All shape-valid secrets are
// batched into ONE `setSecrets` call (= one Fly release). `replace_all=false`
// means secrets not in the manifest are never deleted — orphans are surfaced
// only, mirroring the Vercel client's no-delete policy.

async fn push_mode_fly(
    store: &PassageStore,
    client: &FlyClient,
    manifest: &FlyManifest,
    apply: bool,
    json_output: bool,
) -> anyhow::Result<()> {
    for (logical_name, app_cfg) in &manifest.fly_apps {
        let remote = client.list_secret_names(&app_cfg.app).await?;
        let remote_names: std::collections::HashSet<String> =
            remote.into_iter().map(|s| s.name).collect();

        let mut diff: Vec<DiffEntry> = Vec::new();
        // (key, raw_value) pairs to push in one batched setSecrets on --apply.
        let mut batch: Vec<(String, String)> = Vec::new();

        for var_name in app_cfg.vars.keys() {
            if app_cfg.skip.contains(var_name) {
                diff.push(DiffEntry {
                    key: var_name.clone(),
                    action: DiffAction::Skip,
                    reason: Some("in skip list".to_string()),
                });
                continue;
            }

            let (vault_path, declared_shape) = match app_cfg.vault_path_for(var_name) {
                Some(v) => v,
                None => continue, // unreachable: var_name came from vars.keys()
            };

            let vault_value = match store.get(&vault_path) {
                Ok(s) => s,
                Err(e) => {
                    if !json_output {
                        eprintln!(
                            "  \x1b[31m✗\x1b[0m {} — cannot read vault path {}: {}",
                            var_name, vault_path, e
                        );
                    }
                    continue;
                }
            };
            let raw_value = vault_value.expose_secret();

            if let Some(v) = shape::check(raw_value, declared_shape).err() {
                diff.push(DiffEntry {
                    key: var_name.clone(),
                    action: DiffAction::DropShape,
                    reason: Some(format!("shape violation: {v}")),
                });
                continue;
            }

            diff.push(DiffEntry {
                key: var_name.clone(),
                action: if remote_names.contains(var_name) {
                    DiffAction::Update
                } else {
                    DiffAction::Add
                },
                reason: None,
            });
            batch.push((var_name.clone(), raw_value.to_string()));
        }

        // Orphans: set on Fly but not in the manifest (never auto-deleted).
        for name in &remote_names {
            if app_cfg.skip.contains(name) || app_cfg.vars.contains_key(name) {
                continue;
            }
            diff.push(DiffEntry {
                key: name.clone(),
                action: DiffAction::Orphan,
                reason: Some("set on Fly but not in manifest".to_string()),
            });
        }

        if json_output {
            println!(
                "{}",
                serde_json::json!({
                    "app": app_cfg.app,
                    "logical": logical_name,
                    "mode": "push-fly",
                    "dry_run": !apply,
                    "diff": diff,
                })
            );
        } else {
            println!(
                "\n\x1b[1m{}\x1b[0m → Fly app \x1b[1m{}\x1b[0m (push{})",
                logical_name,
                app_cfg.app,
                if apply { "" } else { " — dry-run" }
            );
            for entry in &diff {
                let (symbol, color) = match entry.action {
                    DiffAction::Add => ("+", "\x1b[32m"),
                    DiffAction::Update => ("~", "\x1b[33m"),
                    DiffAction::Match => ("=", "\x1b[90m"),
                    DiffAction::Orphan => ("!", "\x1b[31m"),
                    DiffAction::Skip => ("-", "\x1b[90m"),
                    DiffAction::DropShape => ("✗", "\x1b[31m"),
                };
                let reason = entry
                    .reason
                    .as_deref()
                    .map(|r| format!(" ({})", r))
                    .unwrap_or_default();
                println!("  {}{}\x1b[0m {}{}", color, symbol, entry.key, reason);
            }
        }

        // Apply: one batched setSecrets call = one Fly release.
        if apply {
            if batch.is_empty() {
                if !json_output {
                    println!("  no secrets to set");
                }
            } else {
                let result = client
                    .set_secrets(&app_cfg.app, &batch, false)
                    .await
                    .with_context(|| format!("setSecrets failed for Fly app '{}'", app_cfg.app))?;
                for (key, raw) in &batch {
                    let _ = append_audit_log(&AuditEntry {
                        timestamp: Utc::now().to_rfc3339(),
                        action: "set-fly".to_string(),
                        project: app_cfg.app.clone(),
                        key: key.clone(),
                        value_shape: shape::classify(raw),
                        result: "ok".to_string(),
                        error: None,
                    });
                }
                if !json_output {
                    match result.release_version {
                        Some(v) => println!("  {} secrets set — Fly release v{}", batch.len(), v),
                        None => println!("  {} secrets set", batch.len()),
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project_with_vars(vars: HashMap<String, VarEntry>) -> ProjectSync {
        ProjectSync {
            project_id: "prj_test".to_string(),
            vault_prefix: "revealui/vercel/api".to_string(),
            targets: default_targets(),
            skip: vec![],
            vars,
        }
    }

    fn project_with_string_vars(vars: HashMap<String, String>) -> ProjectSync {
        let entries = vars
            .into_iter()
            .map(|(k, v)| (k, VarEntry::Path(v)))
            .collect();
        project_with_vars(entries)
    }

    #[test]
    fn vault_path_for_returns_prefix_default_when_no_override() {
        let cfg = project_with_vars(HashMap::new());
        let (path, shape) = cfg.vault_path_for("STRIPE_SECRET_KEY");
        assert_eq!(path, "revealui/vercel/api/STRIPE_SECRET_KEY");
        assert_eq!(shape, Shape::Any);
    }

    #[test]
    fn vault_path_for_returns_override_when_set() {
        let mut vars = HashMap::new();
        vars.insert(
            "POSTGRES_URL".to_string(),
            VarEntry::Path("revealui/prod/db/postgres-url".to_string()),
        );
        let cfg = project_with_vars(vars);
        let (path, shape) = cfg.vault_path_for("POSTGRES_URL");
        assert_eq!(path, "revealui/prod/db/postgres-url");
        assert_eq!(shape, Shape::Any);
        let (path2, _) = cfg.vault_path_for("STRIPE_SECRET_KEY");
        assert_eq!(path2, "revealui/vercel/api/STRIPE_SECRET_KEY");
    }

    #[test]
    fn vault_path_for_object_entry_returns_declared_shape() {
        let mut vars = HashMap::new();
        vars.insert(
            "POSTGRES_URL".to_string(),
            VarEntry::Object {
                path: "revealui/prod/db/postgres-url".to_string(),
                shape: Shape::PostgresUrl,
            },
        );
        let cfg = project_with_vars(vars);
        let (path, shape) = cfg.vault_path_for("POSTGRES_URL");
        assert_eq!(path, "revealui/prod/db/postgres-url");
        assert_eq!(shape, Shape::PostgresUrl);
    }

    #[test]
    fn vault_path_for_supports_two_vars_pointing_at_same_path() {
        let mut vars = HashMap::new();
        vars.insert(
            "POSTGRES_URL".to_string(),
            VarEntry::Path("revealui/prod/db/postgres-url".to_string()),
        );
        vars.insert(
            "DATABASE_URL".to_string(),
            VarEntry::Path("revealui/prod/db/postgres-url".to_string()),
        );
        let cfg = project_with_vars(vars);
        let (path1, _) = cfg.vault_path_for("POSTGRES_URL");
        let (path2, _) = cfg.vault_path_for("DATABASE_URL");
        assert_eq!(path1, path2);
    }

    #[test]
    fn manifest_parses_without_vars_field_for_backwards_compat() {
        let toml_src = r#"
            [projects.api]
            project_id = "prj_test"
            vault_prefix = "revealui/vercel/api"
        "#;
        let manifest: SyncManifest = toml::from_str(toml_src).unwrap();
        let api = manifest.projects.get("api").unwrap();
        assert!(api.vars.is_empty());
        let (path, shape) = api.vault_path_for("FOO");
        assert_eq!(path, "revealui/vercel/api/FOO");
        assert_eq!(shape, Shape::Any);
    }

    #[test]
    fn manifest_parses_with_string_vars_table() {
        let toml_src = r#"
            [projects.api]
            project_id = "prj_test"
            vault_prefix = "revealui/vercel/api"

            [projects.api.vars]
            POSTGRES_URL = "revealui/prod/db/postgres-url"
            DATABASE_URL = "revealui/prod/db/postgres-url"
        "#;
        let manifest: SyncManifest = toml::from_str(toml_src).unwrap();
        let api = manifest.projects.get("api").unwrap();
        assert_eq!(api.vars.len(), 2);
        let (path, shape) = api.vault_path_for("POSTGRES_URL");
        assert_eq!(path, "revealui/prod/db/postgres-url");
        assert_eq!(shape, Shape::Any);
        let (foo_path, _) = api.vault_path_for("FOO");
        assert_eq!(foo_path, "revealui/vercel/api/FOO");
    }

    #[test]
    fn manifest_parses_with_object_vars_table() {
        let toml_src = r#"
            [projects.api]
            project_id = "prj_test"
            vault_prefix = "revealui/vercel/api"

            [projects.api.vars]
            POSTGRES_URL = { path = "revealui/prod/db/postgres-url", shape = "postgres-url" }
            STRIPE_SECRET_KEY = { path = "revealui/prod/stripe/secret-key", shape = "stripe-key-live-only" }
        "#;
        let manifest: SyncManifest = toml::from_str(toml_src).unwrap();
        let api = manifest.projects.get("api").unwrap();
        let (path, shape) = api.vault_path_for("POSTGRES_URL");
        assert_eq!(path, "revealui/prod/db/postgres-url");
        assert_eq!(shape, Shape::PostgresUrl);
        let (_, stripe_shape) = api.vault_path_for("STRIPE_SECRET_KEY");
        assert_eq!(stripe_shape, Shape::StripeKeyLiveOnly);
    }

    #[test]
    fn manifest_parses_mixed_string_and_object_vars() {
        let toml_src = r#"
            [projects.api]
            project_id = "prj_test"
            vault_prefix = "revealui/vercel/api"

            [projects.api.vars]
            POSTGRES_URL = "revealui/prod/db/postgres-url"
            STRIPE_KEY = { path = "revealui/prod/stripe/key", shape = "stripe-key-live-only" }
        "#;
        let manifest: SyncManifest = toml::from_str(toml_src).unwrap();
        let api = manifest.projects.get("api").unwrap();
        let (_, pg_shape) = api.vault_path_for("POSTGRES_URL");
        assert_eq!(pg_shape, Shape::Any);
        let (_, stripe_shape) = api.vault_path_for("STRIPE_KEY");
        assert_eq!(stripe_shape, Shape::StripeKeyLiveOnly);
    }

    /// Helper: build a ProjectSync with old-style string vars for tests that
    /// predate D6 (vault_path_for now returns (path, shape) — these tests
    /// only care about the path half).
    #[allow(dead_code)]
    fn project_string_only(vars: HashMap<String, String>) -> ProjectSync {
        project_with_string_vars(vars)
    }

    // ── Fly manifest ─────────────────────────────────────────────────────────

    #[test]
    fn fly_manifest_parses_apps_and_vars() {
        let toml_src = r#"
            [fly-apps.revealui-worker]
            app = "revealui-worker"

            [fly-apps.revealui-worker.vars]
            POSTGRES_URL = "revealui/prod/db/postgres-url"
            ELECTRIC_SECRET = "revealui/prod/electric/secret"
        "#;
        let manifest: FlyManifest = toml::from_str(toml_src).unwrap();
        let app = manifest.fly_apps.get("revealui-worker").unwrap();
        assert_eq!(app.app, "revealui-worker");
        assert_eq!(app.vars.len(), 2);
        let (path, shape) = app.vault_path_for("POSTGRES_URL").unwrap();
        assert_eq!(path, "revealui/prod/db/postgres-url");
        assert_eq!(shape, Shape::Any);
        assert!(app.vault_path_for("NOT_DECLARED").is_none());
    }

    #[test]
    fn fly_manifest_supports_object_var_with_shape() {
        let toml_src = r#"
            [fly-apps.worker]
            app = "revealui-worker"

            [fly-apps.worker.vars]
            POSTGRES_URL = { path = "revealui/prod/db/postgres-url", shape = "postgres-url" }
        "#;
        let manifest: FlyManifest = toml::from_str(toml_src).unwrap();
        let app = manifest.fly_apps.get("worker").unwrap();
        let (_, shape) = app.vault_path_for("POSTGRES_URL").unwrap();
        assert_eq!(shape, Shape::PostgresUrl);
    }

    #[test]
    fn fly_manifest_skip_list_parses() {
        let toml_src = r#"
            [fly-apps.worker]
            app = "revealui-worker"
            skip = ["NODE_ENV"]

            [fly-apps.worker.vars]
            FOO = "revealui/prod/foo"
        "#;
        let manifest: FlyManifest = toml::from_str(toml_src).unwrap();
        let app = manifest.fly_apps.get("worker").unwrap();
        assert!(app.skip.contains(&"NODE_ENV".to_string()));
    }

    #[test]
    fn empty_fly_manifest_is_rejected() {
        // A Vercel-style manifest has no [fly-apps]; unknown fields are ignored,
        // so it deserializes into an empty FlyManifest. The guard must reject it
        // rather than let `sync fly` silently no-op.
        let vercel_like = r#"
            [projects.revealui-api]
            project_id = "prj_x"
            vault_prefix = "revealui/prod"
        "#;
        let manifest: FlyManifest = toml::from_str(vercel_like).unwrap();
        assert!(manifest.fly_apps.is_empty());
        let err = validate_fly_manifest(&manifest, std::path::Path::new("revvault-vercel.toml"))
            .unwrap_err();
        assert!(err.to_string().contains("No [fly-apps"));
    }

    #[test]
    fn populated_fly_manifest_passes_validation() {
        let toml_src = r#"
            [fly-apps.worker]
            app = "revealui-worker"

            [fly-apps.worker.vars]
            FOO = "revealui/prod/foo"
        "#;
        let manifest: FlyManifest = toml::from_str(toml_src).unwrap();
        validate_fly_manifest(&manifest, std::path::Path::new("fly.toml")).unwrap();
    }
}

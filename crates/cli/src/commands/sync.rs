use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use anyhow::{bail, Context};
use chrono::Utc;
use clap::Args;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

use revvault_core::sync::shape::{self, Shape};
use revvault_core::sync::vercel::{VercelClient, VercelEnvVar};
use revvault_core::{Config, PassageStore};

// ── CLI args ────────────────────────────────────────────────────────────────

#[derive(Args)]
pub struct SyncArgs {
    /// Target to sync with (currently only "vercel" is supported)
    pub target: String,

    /// Path to the sync manifest (default: revvault-vercel.toml)
    #[arg(long, default_value = "revvault-vercel.toml")]
    pub manifest: PathBuf,

    /// Apply changes (default is dry-run)
    #[arg(long)]
    pub apply: bool,

    /// Vercel API token (or set VERCEL_TOKEN env var)
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
    if args.target != "vercel" {
        bail!("Unknown sync target '{}'. Supported: vercel", args.target);
    }

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
        let remote_decrypted_map: Option<HashMap<String, String>> = match client
            .list_env_vars_with_values(&project_cfg.project_id)
            .await
        {
            Ok(Some(vars)) => Some(
                vars.into_iter()
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
}

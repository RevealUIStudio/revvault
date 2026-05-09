use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use anyhow::{bail, Context};
use chrono::Utc;
use clap::Args;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

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

    /// Pull: import existing Vercel vars into the vault
    #[arg(long)]
    pub pull: bool,

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
    /// Per-var path overrides. Maps a Vercel var name to an absolute vault
    /// path. When a var is in this map, its vault path is the override
    /// instead of `<vault_prefix>/<VAR_NAME>`.
    ///
    /// Use case: one canonical kebab-cased vault path (e.g.
    /// `revealui/prod/db/postgres-url`) feeding multiple Vercel vars
    /// (e.g. `POSTGRES_URL` + `DATABASE_URL`) across one or more projects,
    /// without duplicating the value in the vault.
    ///
    /// TOML form:
    /// ```toml
    /// [projects.api.vars]
    /// POSTGRES_URL = "revealui/prod/db/postgres-url"
    /// DATABASE_URL = "revealui/prod/db/postgres-url"
    /// ```
    #[serde(default)]
    vars: HashMap<String, String>,
}

impl ProjectSync {
    /// Resolve the vault path for a given Vercel var name. Returns the override
    /// if one is set in `vars`, otherwise the prefix-derived default.
    fn vault_path_for(&self, var_name: &str) -> String {
        self.vars
            .get(var_name)
            .cloned()
            .unwrap_or_else(|| format!("{}/{}", self.vault_prefix, var_name))
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
    Orphan,
    Skip,
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
    action: String,
    project: String,
    key: String,
    result: String,
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

    if args.pull {
        return pull_mode(&store, &client, &manifest, args.apply, json_output).await;
    }

    push_mode(&store, &client, &manifest, args.apply, json_output).await
}

// ── Pull mode: import Vercel vars into vault ────────────────────────────────

async fn pull_mode(
    store: &PassageStore,
    client: &VercelClient,
    manifest: &SyncManifest,
    apply: bool,
    json_output: bool,
) -> anyhow::Result<()> {
    for (project_name, project_cfg) in &manifest.projects {
        let remote_vars = client.list_env_vars(&project_cfg.project_id).await?;

        if !json_output {
            println!("\n\x1b[1m{}\x1b[0m (pull)", project_name);
        }

        let mut imported = 0u32;
        let mut skipped = 0u32;

        for var in &remote_vars {
            if project_cfg.skip.contains(&var.key) {
                skipped += 1;
                continue;
            }
            // Integration-managed vars have a configurationId — skip them
            if var.configuration_id.is_some() {
                skipped += 1;
                continue;
            }

            let vault_path = project_cfg.vault_path_for(&var.key);
            let value = var.value.as_deref().unwrap_or("");

            if !json_output {
                if apply {
                    print!("  \x1b[32m+\x1b[0m {} ", var.key);
                } else {
                    print!("  \x1b[33m~\x1b[0m {} (dry-run) ", var.key);
                }
            }

            if apply {
                store.upsert(&vault_path, value.as_bytes())?;
                imported += 1;
                if !json_output {
                    println!("→ {}", vault_path);
                }
                let _ = append_audit_log(&AuditEntry {
                    timestamp: Utc::now().to_rfc3339(),
                    action: "pull".to_string(),
                    project: project_name.clone(),
                    key: var.key.clone(),
                    result: "ok".to_string(),
                });
            } else {
                imported += 1;
                if !json_output {
                    println!("→ {}", vault_path);
                }
            }
        }

        if json_output {
            println!(
                "{}",
                serde_json::json!({
                    "project": project_name,
                    "mode": "pull",
                    "dry_run": !apply,
                    "imported": imported,
                    "skipped": skipped,
                })
            );
        } else {
            println!(
                "  {} imported, {} skipped{}",
                imported,
                skipped,
                if !apply { " (dry-run)" } else { "" }
            );
        }
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
        let remote_map: HashMap<String, &VercelEnvVar> =
            remote_vars.iter().map(|v| (v.key.clone(), v)).collect();

        // Build the union of vars to sync: explicit overrides + everything
        // under the project's vault_prefix. Overrides win — a var name in
        // `vars` is never read from `<prefix>/<VAR_NAME>` even if both exist.
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

            if remote_map.contains_key(var_name) {
                diff.push(DiffEntry {
                    key: var_name.clone(),
                    action: DiffAction::Update,
                    reason: None,
                });
            } else {
                diff.push(DiffEntry {
                    key: var_name.clone(),
                    action: DiffAction::Add,
                    reason: None,
                });
            }
        }

        // Detect orphans (in Vercel but not in vault)
        for remote_var in &remote_vars {
            if project_cfg.skip.contains(&remote_var.key) {
                continue;
            }
            if remote_var.configuration_id.is_some() {
                continue; // Integration-managed
            }
            if !vault_var_names.contains(&remote_var.key) {
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
                    DiffAction::Orphan => ("!", "\x1b[31m"),
                    DiffAction::Skip => ("-", "\x1b[90m"),
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
                let vault_path = project_cfg.vault_path_for(&entry.key);
                match entry.action {
                    DiffAction::Add => {
                        let secret = store.get(&vault_path)?;
                        client
                            .create_env_var(
                                &project_cfg.project_id,
                                &entry.key,
                                secret.expose_secret(),
                                &project_cfg.targets,
                            )
                            .await?;
                        let _ = append_audit_log(&AuditEntry {
                            timestamp: Utc::now().to_rfc3339(),
                            action: "create".to_string(),
                            project: project_name.clone(),
                            key: entry.key.clone(),
                            result: "ok".to_string(),
                        });
                    }
                    DiffAction::Update => {
                        let secret = store.get(&vault_path)?;
                        if let Some(remote) = remote_map.get(&entry.key) {
                            if let Some(ref id) = remote.id {
                                client
                                    .update_env_var(
                                        &project_cfg.project_id,
                                        id,
                                        secret.expose_secret(),
                                        &project_cfg.targets,
                                    )
                                    .await?;
                                let _ = append_audit_log(&AuditEntry {
                                    timestamp: Utc::now().to_rfc3339(),
                                    action: "update".to_string(),
                                    project: project_name.clone(),
                                    key: entry.key.clone(),
                                    result: "ok".to_string(),
                                });
                            }
                        }
                    }
                    DiffAction::Orphan => {
                        if !json_output {
                            println!("  \x1b[31m⚠\x1b[0m  Orphan: {} (not deleted — remove manually or add to vault)", entry.key);
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

    fn project_with_vars(vars: HashMap<String, String>) -> ProjectSync {
        ProjectSync {
            project_id: "prj_test".to_string(),
            vault_prefix: "revealui/vercel/api".to_string(),
            targets: default_targets(),
            skip: vec![],
            vars,
        }
    }

    #[test]
    fn vault_path_for_returns_prefix_default_when_no_override() {
        let cfg = project_with_vars(HashMap::new());
        assert_eq!(
            cfg.vault_path_for("STRIPE_SECRET_KEY"),
            "revealui/vercel/api/STRIPE_SECRET_KEY"
        );
    }

    #[test]
    fn vault_path_for_returns_override_when_set() {
        let mut vars = HashMap::new();
        vars.insert(
            "POSTGRES_URL".to_string(),
            "revealui/prod/db/postgres-url".to_string(),
        );
        let cfg = project_with_vars(vars);
        assert_eq!(
            cfg.vault_path_for("POSTGRES_URL"),
            "revealui/prod/db/postgres-url"
        );
        // Non-overridden var still uses the prefix-derived default.
        assert_eq!(
            cfg.vault_path_for("STRIPE_SECRET_KEY"),
            "revealui/vercel/api/STRIPE_SECRET_KEY"
        );
    }

    #[test]
    fn vault_path_for_supports_two_vars_pointing_at_same_path() {
        let mut vars = HashMap::new();
        vars.insert(
            "POSTGRES_URL".to_string(),
            "revealui/prod/db/postgres-url".to_string(),
        );
        vars.insert(
            "DATABASE_URL".to_string(),
            "revealui/prod/db/postgres-url".to_string(),
        );
        let cfg = project_with_vars(vars);
        assert_eq!(
            cfg.vault_path_for("POSTGRES_URL"),
            cfg.vault_path_for("DATABASE_URL")
        );
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
        assert_eq!(api.vault_path_for("FOO"), "revealui/vercel/api/FOO");
    }

    #[test]
    fn manifest_parses_with_vars_table() {
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
        assert_eq!(
            api.vault_path_for("POSTGRES_URL"),
            "revealui/prod/db/postgres-url"
        );
        assert_eq!(api.vault_path_for("FOO"), "revealui/vercel/api/FOO");
    }
}

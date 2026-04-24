use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use anyhow::{bail, Context};
use chrono::Utc;
use clap::Args;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

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
}

fn default_targets() -> Vec<String> {
    vec![
        "production".to_string(),
        "preview".to_string(),
        "development".to_string(),
    ]
}

// ── Vercel API types ────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct VercelEnvVar {
    id: Option<String>,
    key: String,
    value: Option<String>,
    target: Vec<String>,
    #[serde(rename = "type")]
    var_type: Option<String>,
    #[serde(rename = "configurationId")]
    configuration_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct VercelEnvListResponse {
    envs: Vec<VercelEnvVar>,
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

// ── Vercel API client ───────────────────────────────────────────────────────

struct VercelClient {
    token: String,
    team_id: Option<String>,
    client: reqwest::Client,
}

impl VercelClient {
    fn new(token: String, team_id: Option<String>) -> Self {
        Self {
            token,
            team_id,
            client: reqwest::Client::new(),
        }
    }

    fn base_url(&self, project_id: &str) -> String {
        let mut url = format!("https://api.vercel.com/v10/projects/{}/env", project_id);
        if let Some(ref team) = self.team_id {
            url.push_str(&format!("?teamId={}", team));
        }
        url
    }

    async fn list_env_vars(&self, project_id: &str) -> anyhow::Result<Vec<VercelEnvVar>> {
        let url = self.base_url(project_id);
        let resp = self
            .client
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .context("Failed to reach Vercel API")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Vercel API returned {}: {}", status, body);
        }

        let data: VercelEnvListResponse = resp.json().await?;
        Ok(data.envs)
    }

    async fn create_env_var(
        &self,
        project_id: &str,
        key: &str,
        value: &str,
        targets: &[String],
    ) -> anyhow::Result<()> {
        let url = self.base_url(project_id);
        let body = serde_json::json!({
            "key": key,
            "value": value,
            "target": targets,
            "type": "encrypted",
        });

        let resp = self
            .client
            .post(&url)
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Failed to create env var '{}': {} {}", key, status, body);
        }
        Ok(())
    }

    async fn update_env_var(
        &self,
        project_id: &str,
        env_id: &str,
        value: &str,
        targets: &[String],
    ) -> anyhow::Result<()> {
        let mut url = format!("https://api.vercel.com/v10/projects/{}/env/{}", project_id, env_id);
        if let Some(ref team) = self.team_id {
            url.push_str(&format!("?teamId={}", team));
        }

        let body = serde_json::json!({
            "value": value,
            "target": targets,
            "type": "encrypted",
        });

        let resp = self
            .client
            .patch(&url)
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Failed to update env var '{}': {} {}", env_id, status, body);
        }
        Ok(())
    }

    /// Delete an env var. Reserved for future orphan cleanup mode.
    #[allow(dead_code)]
    async fn delete_env_var(&self, project_id: &str, env_id: &str) -> anyhow::Result<()> {
        let mut url = format!("https://api.vercel.com/v10/projects/{}/env/{}", project_id, env_id);
        if let Some(ref team) = self.team_id {
            url.push_str(&format!("?teamId={}", team));
        }

        let resp = self
            .client
            .delete(&url)
            .bearer_auth(&self.token)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Failed to delete env var '{}': {} {}", env_id, status, body);
        }
        Ok(())
    }
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
        .ok_or_else(|| anyhow::anyhow!("VERCEL_TOKEN not set. Pass --token or set VERCEL_TOKEN env var"))?;

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

            let vault_path = format!("{}/{}", project_cfg.vault_prefix, var.key);
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
            remote_vars.iter().filter_map(|v| Some((v.key.clone(), v))).collect();

        // List vault secrets under this project's prefix
        let vault_secrets = store.list(Some(&project_cfg.vault_prefix))?;

        let mut diff: Vec<DiffEntry> = Vec::new();

        // Compare vault → remote
        for entry in &vault_secrets {
            let key = entry
                .path
                .strip_prefix(&format!("{}/", project_cfg.vault_prefix))
                .unwrap_or(&entry.path);

            if project_cfg.skip.contains(&key.to_string()) {
                diff.push(DiffEntry {
                    key: key.to_string(),
                    action: DiffAction::Skip,
                    reason: Some("in skip list".to_string()),
                });
                continue;
            }

            if remote_map.contains_key(key) {
                diff.push(DiffEntry {
                    key: key.to_string(),
                    action: DiffAction::Update,
                    reason: None,
                });
            } else {
                diff.push(DiffEntry {
                    key: key.to_string(),
                    action: DiffAction::Add,
                    reason: None,
                });
            }
        }

        // Detect orphans (in Vercel but not in vault)
        let vault_keys: Vec<String> = vault_secrets
            .iter()
            .map(|e| {
                e.path
                    .strip_prefix(&format!("{}/", project_cfg.vault_prefix))
                    .unwrap_or(&e.path)
                    .to_string()
            })
            .collect();

        for remote_var in &remote_vars {
            if project_cfg.skip.contains(&remote_var.key) {
                continue;
            }
            if remote_var.configuration_id.is_some() {
                continue; // Integration-managed
            }
            if !vault_keys.contains(&remote_var.key) {
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
            println!("\n\x1b[1m{}\x1b[0m (push{})", project_name, if apply { "" } else { " — dry-run" });
            for entry in &diff {
                let (symbol, color) = match entry.action {
                    DiffAction::Add => ("+", "\x1b[32m"),
                    DiffAction::Update => ("~", "\x1b[33m"),
                    DiffAction::Orphan => ("!", "\x1b[31m"),
                    DiffAction::Skip => ("-", "\x1b[90m"),
                };
                let reason = entry.reason.as_deref().map(|r| format!(" ({})", r)).unwrap_or_default();
                println!("  {}{}\x1b[0m {}{}", color, symbol, entry.key, reason);
            }
        }

        // Apply changes
        if apply {
            for entry in &diff {
                let vault_path = format!("{}/{}", project_cfg.vault_prefix, entry.key);
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

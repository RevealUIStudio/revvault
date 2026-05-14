//! `revvault doctor` — vault-only health check.
//!
//! Reads every var declared in the sync manifest, fetches its value from the
//! vault, and validates the shape. Never touches any external system. Never
//! mutates the vault.
//!
//! Exit codes:
//! - `0` — all entries pass
//! - `1` — one or more entries failed shape validation or could not be read

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use anyhow::Context;
use clap::Args;
use serde::Serialize;

use revvault_core::sync::shape::{self, Shape};
use revvault_core::{Config, PassageStore};

// ── CLI args ────────────────────────────────────────────────────────────────

#[derive(Args)]
pub struct DoctorArgs {
    /// Path to the sync manifest (default: revvault-vercel.toml in CWD)
    #[arg(long, default_value = "revvault-vercel.toml")]
    pub manifest: PathBuf,

    /// Output structured JSON
    #[arg(long)]
    pub json: bool,
}

// ── Manifest schema (subset — only what doctor needs) ───────────────────────

#[derive(Debug, serde::Deserialize)]
struct SyncManifest {
    #[serde(default)]
    projects: HashMap<String, ProjectSync>,
}

#[derive(Debug, serde::Deserialize)]
struct ProjectSync {
    vault_prefix: String,
    #[serde(default)]
    vars: HashMap<String, VarEntry>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(untagged)]
enum VarEntry {
    Path(String),
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

// ── Output types ─────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct DoctorEntry {
    pub path: String,
    pub var_name: String,
    pub project: String,
    /// "postgres-url" / "stripe-key" / "empty" / "unknown" / etc.
    pub actual_shape: String,
    /// Declared shape name from manifest, or "any" if not declared.
    pub expected_shape: String,
    /// "pass" | "fail" | "missing"
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
struct DoctorReport {
    entries: Vec<DoctorEntry>,
    total: usize,
    passed: usize,
    failed: usize,
}

// ── Runner ───────────────────────────────────────────────────────────────────

pub fn run(args: DoctorArgs) -> anyhow::Result<()> {
    let manifest_content = fs::read_to_string(&args.manifest)
        .with_context(|| format!("Cannot read manifest: {}", args.manifest.display()))?;
    let manifest: SyncManifest =
        toml::from_str(&manifest_content).context("Invalid manifest TOML")?;

    let config = Config::resolve()?;
    let store = PassageStore::open(config)?;

    let mut entries: Vec<DoctorEntry> = Vec::new();

    for (project_name, project_cfg) in &manifest.projects {
        // Collect all var names: explicit overrides + everything under the prefix.
        let mut var_pairs: Vec<(String, String, Shape)> = Vec::new();

        for (var_name, entry) in &project_cfg.vars {
            var_pairs.push((var_name.clone(), entry.path().to_string(), entry.shape()));
        }

        // Discover additional paths from the vault under the prefix.
        let prefix_secrets = store
            .list(Some(&project_cfg.vault_prefix))
            .unwrap_or_default();
        for secret_entry in &prefix_secrets {
            let var_name = secret_entry
                .path
                .strip_prefix(&format!("{}/", project_cfg.vault_prefix))
                .unwrap_or(&secret_entry.path)
                .to_string();
            if !project_cfg.vars.contains_key(&var_name) {
                var_pairs.push((var_name, secret_entry.path.clone(), Shape::Any));
            }
        }

        for (var_name, vault_path, declared_shape) in var_pairs {
            let entry = match store.get(&vault_path) {
                Err(e) => DoctorEntry {
                    path: vault_path.clone(),
                    var_name: var_name.clone(),
                    project: project_name.clone(),
                    actual_shape: "missing".into(),
                    expected_shape: shape_name(declared_shape),
                    status: "missing".into(),
                    error: Some(format!("{e}")),
                },
                Ok(secret) => {
                    let raw = secret.expose_secret_str();
                    let actual = shape::classify(raw);
                    match shape::check(raw, declared_shape) {
                        Ok(()) => DoctorEntry {
                            path: vault_path.clone(),
                            var_name: var_name.clone(),
                            project: project_name.clone(),
                            actual_shape: actual,
                            expected_shape: shape_name(declared_shape),
                            status: "pass".into(),
                            error: None,
                        },
                        Err(violation) => DoctorEntry {
                            path: vault_path.clone(),
                            var_name: var_name.clone(),
                            project: project_name.clone(),
                            actual_shape: actual,
                            expected_shape: shape_name(declared_shape),
                            status: "fail".into(),
                            error: Some(violation.to_string()),
                        },
                    }
                }
            };
            entries.push(entry);
        }
    }

    // Sort for stable output (project + path).
    entries.sort_by(|a, b| a.project.cmp(&b.project).then(a.path.cmp(&b.path)));

    let total = entries.len();
    let failed = entries.iter().filter(|e| e.status != "pass").count();
    let passed = total - failed;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&DoctorReport {
                entries,
                total,
                passed,
                failed,
            })?
        );
    } else {
        for entry in &entries {
            let (symbol, color) = match entry.status.as_str() {
                "pass" => ("✓", "\x1b[32m"),
                "fail" => ("✗", "\x1b[31m"),
                _ => ("?", "\x1b[33m"),
            };
            let detail = match entry.status.as_str() {
                "pass" => format!("{} ({})", entry.path, entry.actual_shape),
                _ => format!(
                    "{} — {}",
                    entry.path,
                    entry.error.as_deref().unwrap_or("unknown error")
                ),
            };
            println!("  {color}{symbol}\x1b[0m {}", detail);
        }
        println!();
        if failed == 0 {
            println!("\x1b[32mAll {} entries pass.\x1b[0m", total);
        } else {
            println!("\x1b[31m{} of {} entries failed.\x1b[0m", failed, total);
        }
    }

    if failed > 0 {
        std::process::exit(1);
    }

    Ok(())
}

fn shape_name(shape: Shape) -> String {
    serde_json::to_value(shape)
        .ok()
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_else(|| format!("{shape:?}"))
}

// Helper trait to expose &str from SecretString without leaking to logs.
trait ExposeSecretStr {
    fn expose_secret_str(&self) -> &str;
}

impl ExposeSecretStr for secrecy::SecretString {
    fn expose_secret_str(&self) -> &str {
        use secrecy::ExposeSecret;
        self.expose_secret()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_temp_store() -> (tempfile::TempDir, PassageStore) {
        let dir = tempfile::tempdir().unwrap();
        let store_dir = dir.path().join("store");
        std::fs::create_dir_all(&store_dir).unwrap();

        let id = age::x25519::Identity::generate();
        let recipient = id.to_public();

        let id_file = dir.path().join("keys.txt");
        std::fs::write(
            &id_file,
            format!(
                "# test key\n{}\n",
                secrecy::ExposeSecret::expose_secret(&id.to_string())
            ),
        )
        .unwrap();

        let recip_file = store_dir.join(".age-recipients");
        std::fs::write(&recip_file, format!("{}\n", recipient)).unwrap();

        let config = revvault_core::Config {
            store_dir,
            identity_file: id_file,
            recipients_file: recip_file,
            editor: None,
            tmpdir: None,
        };
        let store = PassageStore::open(config).unwrap();
        (dir, store)
    }

    fn write_manifest(dir: &tempfile::TempDir, content: &str) -> PathBuf {
        let path = dir.path().join("revvault-vercel.toml");
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn doctor_passes_when_vault_matches_manifest_shapes() {
        let (dir, store) = setup_temp_store();
        store
            .upsert("revealui/prod/db/postgres-url", b"postgresql://host/db")
            .unwrap();

        let manifest = write_manifest(
            &dir,
            r#"
            [projects.api]
            project_id = "prj_test"
            vault_prefix = "revealui/prod"

            [projects.api.vars]
            POSTGRES_URL = { path = "revealui/prod/db/postgres-url", shape = "postgres-url" }
            "#,
        );

        // Build entries directly to test the logic without spawning a process.
        let manifest_content = std::fs::read_to_string(&manifest).unwrap();
        let manifest_parsed: SyncManifest = toml::from_str(&manifest_content).unwrap();

        for project_cfg in manifest_parsed.projects.values() {
            for (var_name, entry) in &project_cfg.vars {
                let secret = store.get(entry.path()).unwrap();
                let raw = {
                    use secrecy::ExposeSecret;
                    secret.expose_secret().to_string()
                };
                let result = shape::check(&raw, entry.shape());
                assert!(result.is_ok(), "expected pass for {var_name}: {result:?}");
            }
        }
    }

    #[test]
    fn doctor_fails_when_any_entry_is_corrupted() {
        let (dir, store) = setup_temp_store();
        // Write a Vercel envelope (the 2026-05-09 incident corruption).
        store
            .upsert(
                "revealui/prod/db/postgres-url",
                b"eyJ2IjoidjIiLCJlcGsiOnsieCI6InRlc3QifX0=",
            )
            .unwrap();

        let manifest = write_manifest(
            &dir,
            r#"
            [projects.api]
            project_id = "prj_test"
            vault_prefix = "revealui/prod"

            [projects.api.vars]
            POSTGRES_URL = { path = "revealui/prod/db/postgres-url", shape = "postgres-url" }
            "#,
        );

        let manifest_content = std::fs::read_to_string(&manifest).unwrap();
        let manifest_parsed: SyncManifest = toml::from_str(&manifest_content).unwrap();

        let mut found_failure = false;
        for project_cfg in manifest_parsed.projects.values() {
            for entry in project_cfg.vars.values() {
                let secret = store.get(entry.path()).unwrap();
                let raw = {
                    use secrecy::ExposeSecret;
                    secret.expose_secret().to_string()
                };
                if shape::check(&raw, entry.shape()).is_err() {
                    found_failure = true;
                }
            }
        }
        assert!(
            found_failure,
            "expected at least one failure for corrupted entry"
        );
    }

    #[test]
    fn doctor_json_output_stable() {
        let entry = DoctorEntry {
            path: "revealui/prod/db/postgres-url".into(),
            var_name: "POSTGRES_URL".into(),
            project: "api".into(),
            actual_shape: "postgres-url".into(),
            expected_shape: "postgres-url".into(),
            status: "pass".into(),
            error: None,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains(r#""path":"revealui/prod/db/postgres-url""#));
        assert!(json.contains(r#""status":"pass""#));
        assert!(json.contains(r#""actual_shape":"postgres-url""#));
        assert!(!json.contains("error"));

        let report = DoctorReport {
            entries: vec![entry],
            total: 1,
            passed: 1,
            failed: 0,
        };
        let report_json = serde_json::to_string_pretty(&report).unwrap();
        assert!(report_json.contains("\"entries\""));
        assert!(report_json.contains("\"total\": 1"));
    }

    #[test]
    fn shape_name_serializes_correctly() {
        assert_eq!(shape_name(Shape::PostgresUrl), "postgres-url");
        assert_eq!(shape_name(Shape::StripeKeyLiveOnly), "stripe-key-live-only");
        assert_eq!(shape_name(Shape::Any), "any");
    }
}

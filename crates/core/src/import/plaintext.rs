use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

use crate::error::{Result, RevaultError};
use crate::store::PassageStore;

/// Record of a single imported file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportRecord {
    pub source_path: PathBuf,
    pub target_path: String,
    pub namespace: String,
    pub categorized_by: String,
}

/// Manifest written after a migration run.
#[derive(Debug, Serialize, Deserialize)]
pub struct MigrationManifest {
    pub timestamp: String,
    pub source_dir: PathBuf,
    pub records: Vec<ImportRecord>,
}

/// Importer for plaintext secret files.
pub struct PlaintextImporter {
    source_dir: PathBuf,
}

impl PlaintextImporter {
    pub fn new(source_dir: PathBuf) -> Self {
        Self { source_dir }
    }

    /// Scan the source directory and categorize files into store paths.
    pub fn scan(&self) -> Result<Vec<ImportRecord>> {
        if !self.source_dir.is_dir() {
            return Err(RevaultError::MigrationFailed(format!(
                "source directory not found: {}",
                self.source_dir.display()
            )));
        }

        let mut records = Vec::new();

        for entry in WalkDir::new(&self.source_dir)
            .min_depth(1)
            .max_depth(1)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            let file_name = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_lowercase();

            let (namespace, target_name, reason) = categorize_by_filename(&file_name);

            records.push(ImportRecord {
                source_path: path.to_path_buf(),
                target_path: format!("{namespace}/{target_name}"),
                namespace: namespace.to_string(),
                categorized_by: reason.to_string(),
            });
        }

        records.sort_by(|a, b| a.target_path.cmp(&b.target_path));
        Ok(records)
    }

    /// Execute the import (encrypt files into the store).
    pub fn execute(&self, store: &PassageStore, records: &[ImportRecord]) -> Result<MigrationManifest> {
        for record in records {
            let content = std::fs::read_to_string(&record.source_path).map_err(|e| {
                RevaultError::MigrationFailed(format!(
                    "failed to read {}: {e}",
                    record.source_path.display()
                ))
            })?;

            let trimmed = content.trim();
            if trimmed.is_empty() {
                continue;
            }

            store.upsert(&record.target_path, trimmed.as_bytes())?;
        }

        let manifest = MigrationManifest {
            timestamp: chrono::Utc::now().to_rfc3339(),
            source_dir: self.source_dir.clone(),
            records: records.to_vec(),
        };

        Ok(manifest)
    }
}

/// Heuristic categorization of a plaintext file into namespace/name.
fn categorize_by_filename(name: &str) -> (&str, String, &str) {
    let lower = name.to_lowercase();

    if lower.contains("stripe") {
        return ("credentials/stripe", sanitize_name(name), "filename:stripe");
    }
    if lower.contains("vercel") {
        return ("credentials/vercel", sanitize_name(name), "filename:vercel");
    }
    if lower.contains("neon") {
        return ("credentials/neon", sanitize_name(name), "filename:neon");
    }
    if lower.contains("supabase") {
        return ("credentials/supabase", sanitize_name(name), "filename:supabase");
    }
    if lower.contains("github") || lower.contains("gh_") {
        return ("credentials/github", sanitize_name(name), "filename:github");
    }
    if lower.contains("openai") || lower.contains("gpt") {
        return ("credentials/openai", sanitize_name(name), "filename:openai");
    }
    if lower.contains("anthropic") || lower.contains("claude") {
        return (
            "credentials/anthropic",
            sanitize_name(name),
            "filename:anthropic",
        );
    }
    if lower.contains("aws") {
        return ("credentials/aws", sanitize_name(name), "filename:aws");
    }
    if lower.contains("ssh") || lower.contains("id_rsa") || lower.contains("id_ed25519") {
        return ("ssh", sanitize_name(name), "filename:ssh");
    }
    if lower.contains("database") || lower.contains("postgres") || lower.contains("db_") {
        return ("credentials/database", sanitize_name(name), "filename:database");
    }

    ("misc", sanitize_name(name), "uncategorized")
}

fn sanitize_name(name: &str) -> String {
    name.replace(' ', "-")
        .replace('_', "-")
        .to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn categorize_known_services() {
        let cases = vec![
            ("stripe-api-key", "credentials/stripe", "filename:stripe"),
            ("vercel_token", "credentials/vercel", "filename:vercel"),
            ("neon-connection-string", "credentials/neon", "filename:neon"),
            ("supabase_anon_key", "credentials/supabase", "filename:supabase"),
            ("github-pat", "credentials/github", "filename:github"),
            ("gh_token", "credentials/github", "filename:github"),
            ("openai-api-key", "credentials/openai", "filename:openai"),
            ("gpt-key", "credentials/openai", "filename:openai"),
            ("anthropic-key", "credentials/anthropic", "filename:anthropic"),
            ("claude-api-key", "credentials/anthropic", "filename:anthropic"),
            ("aws-access-key", "credentials/aws", "filename:aws"),
            ("ssh-deploy-key", "ssh", "filename:ssh"),
            ("id_ed25519", "ssh", "filename:ssh"),
            ("database-url", "credentials/database", "filename:database"),
            ("postgres-password", "credentials/database", "filename:database"),
            ("random-notes", "misc", "uncategorized"),
        ];

        for (filename, expected_ns, expected_reason) in cases {
            let (ns, _name, reason) = categorize_by_filename(filename);
            assert_eq!(ns, expected_ns, "namespace mismatch for {filename}");
            assert_eq!(reason, expected_reason, "reason mismatch for {filename}");
        }
    }

    #[test]
    fn sanitize_normalizes_names() {
        assert_eq!(sanitize_name("My API Key"), "my-api-key");
        assert_eq!(sanitize_name("stripe_secret_key"), "stripe-secret-key");
        assert_eq!(sanitize_name("UPPER"), "upper");
    }
}

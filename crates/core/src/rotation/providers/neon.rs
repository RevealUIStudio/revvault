//! Neon Postgres password rotation.
//!
//! Resets a database role's password via Neon's v2 API and stores the
//! resulting connection URI back in the vault. Unlike `GenericHttpProvider`,
//! the auth token (Neon API key) is a **separate** vault secret from the
//! value being rotated (the connection URI), so this provider takes the
//! API key independently from `current_key`. The factory in
//! `providers::build_provider` reads the API key from
//! `settings["api_key_path"]` before constructing the provider.
//!
//! # Rotation TOML example
//!
//! ```toml
//! [providers.neon-production]
//! secret_path = "revealui/db/neon-production"
//!
//! [providers.neon-production.settings]
//! type          = "neon"
//! api_key_path  = "credentials/neon/api-key"
//! project_id    = "<project-id-from-neon-console>"
//! role          = "neondb_owner"
//! database      = "neondb"
//! # branch_id is optional — when absent the primary branch is resolved at rotate-time
//! # pooled = "true"   # default false; set to "true" for the pgbouncer-pooled URI
//! ```
//!
//! # Available settings
//!
//! | Key | Required | Default | Description |
//! |-----|----------|---------|-------------|
//! | `type` | yes | — | Must be `"neon"` to dispatch this provider |
//! | `api_key_path` | yes | — | Vault path holding the Neon API key (bearer token) |
//! | `project_id` | yes | — | Neon project ID (visible in console URL) |
//! | `role` | yes | — | Database role whose password to reset |
//! | `database` | yes | — | Database name (used by `connection_uri` lookup) |
//! | `branch_id` | no | (primary branch) | Override branch for non-default rotations |
//! | `pooled` | no | `"false"` | `"true"` to fetch the pgbouncer URI instead of direct |

use std::collections::HashMap;

use async_trait::async_trait;
use reqwest::Client;
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::Value;

use crate::error::{Result, RevvaultError};
use crate::rotation::provider::{RotationOutcome, RotationProvider};

const NEON_API: &str = "https://console.neon.tech/api/v2";

#[derive(Debug)]
pub struct NeonProvider {
    name: String,
    /// Bearer token for the Neon API. Distinct from `current_key`
    /// (which would be the connection URI being rotated) — the executor
    /// loads this from `settings["api_key_path"]` and hands it in via
    /// the factory.
    api_key: SecretString,
    project_id: String,
    /// Optional: when absent the primary branch is resolved at rotate-time.
    branch_id: Option<String>,
    role: String,
    database: String,
    /// When true, fetch the pgbouncer-pooled URI (host suffix `-pooler`)
    /// instead of the direct host.
    pooled: bool,
}

impl NeonProvider {
    /// Build a provider from `ProviderConfig::settings`. The API key is
    /// loaded by the factory and passed in here; `current_key` (the URI
    /// being rotated) isn't needed for the password-reset flow because
    /// Neon's API uses the API key for auth and returns the new URI.
    pub fn from_config(
        name: String,
        api_key: SecretString,
        settings: &HashMap<String, String>,
    ) -> Result<Self> {
        // Extract required fields BEFORE moving `name` into the struct —
        // the `require` closure captures `name` by reference, so the
        // closure's borrow has to end before the move (matches the
        // pattern in GenericHttpProvider::from_config).
        let require = |key: &str| -> Result<String> {
            settings.get(key).cloned().ok_or_else(|| {
                RevvaultError::Other(anyhow::anyhow!(
                    "provider '{}': missing required setting '{}'",
                    name,
                    key
                ))
            })
        };

        let project_id = require("project_id")?;
        let role = require("role")?;
        let database = require("database")?;
        let branch_id = settings.get("branch_id").cloned();
        let pooled = settings
            .get("pooled")
            .map(|v| matches!(v.as_str(), "true" | "1" | "yes"))
            .unwrap_or(false);

        Ok(Self {
            name,
            api_key,
            project_id,
            branch_id,
            role,
            database,
            pooled,
        })
    }

    fn rotation_failed(&self, reason: impl Into<String>) -> RevvaultError {
        RevvaultError::RotationFailed {
            provider: self.name.clone(),
            reason: reason.into(),
        }
    }

    /// Resolve the branch id to use. If the user pinned `branch_id` in
    /// settings we honor it; otherwise we pick the project's primary
    /// branch via the list-branches endpoint. The Neon API has used both
    /// `primary` and `default` boolean fields across versions — we accept
    /// either.
    async fn resolve_branch_id(&self, client: &Client) -> Result<String> {
        if let Some(id) = &self.branch_id {
            return Ok(id.clone());
        }
        let url = format!("{NEON_API}/projects/{}/branches", self.project_id);
        let resp = client
            .get(&url)
            .bearer_auth(self.api_key.expose_secret())
            .send()
            .await
            .map_err(|e| self.rotation_failed(format!("list branches request failed: {e}")))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(self.rotation_failed(format!("list branches returned {status}: {text}")));
        }
        let json: Value = resp
            .json()
            .await
            .map_err(|e| self.rotation_failed(format!("list branches not JSON: {e}")))?;
        let branches = json
            .get("branches")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                self.rotation_failed("list branches response missing 'branches' array")
            })?;
        for b in branches {
            let is_primary = b.get("primary").and_then(Value::as_bool).unwrap_or(false)
                || b.get("default").and_then(Value::as_bool).unwrap_or(false);
            if is_primary {
                if let Some(id) = b.get("id").and_then(Value::as_str) {
                    return Ok(id.to_string());
                }
            }
        }
        Err(self.rotation_failed("no primary branch found in project"))
    }
}

#[async_trait]
impl RotationProvider for NeonProvider {
    fn name(&self) -> &str {
        &self.name
    }

    async fn preflight(&self) -> Result<()> {
        // Validate URLs parse without making any network requests. Use a
        // placeholder branch id when the user didn't pin one — the real
        // branch is fetched at rotate-time.
        let dummy_branch = self.branch_id.as_deref().unwrap_or("br-placeholder");
        let reset_url = format!(
            "{NEON_API}/projects/{}/branches/{}/roles/{}/reset_password",
            self.project_id, dummy_branch, self.role
        );
        reqwest::Url::parse(&reset_url).map_err(|e| {
            RevvaultError::Other(anyhow::anyhow!(
                "provider '{}': invalid reset URL '{reset_url}': {e}",
                self.name
            ))
        })?;
        let conn_url = format!(
            "{NEON_API}/projects/{}/connection_uri?role_name={}&database_name={}",
            self.project_id, self.role, self.database
        );
        reqwest::Url::parse(&conn_url).map_err(|e| {
            RevvaultError::Other(anyhow::anyhow!(
                "provider '{}': invalid connection_uri URL '{conn_url}': {e}",
                self.name
            ))
        })?;
        Ok(())
    }

    async fn dry_run(&self) -> Result<String> {
        let branch_label = self
            .branch_id
            .as_deref()
            .map(String::from)
            .unwrap_or_else(|| "(primary, resolved at rotate-time)".into());
        let pooled_label = if self.pooled { "pooled" } else { "direct" };
        Ok([
            "1. Read Neon API key from vault (already loaded by factory)".to_string(),
            format!("2. Resolve branch_id: {branch_label}"),
            format!(
                "3. POST {NEON_API}/projects/{}/branches/<branch>/roles/{}/reset_password",
                self.project_id, self.role
            ),
            "   Bearer auth via the Neon API key".to_string(),
            "4. Validate the response (Neon returns the new password inline,".to_string(),
            "   but we use connection_uri to assemble the full URI atomically)".to_string(),
            format!(
                "5. GET {NEON_API}/projects/{}/connection_uri?role_name={}&database_name={}&pooled={}",
                self.project_id, self.role, self.database, self.pooled
            ),
            format!(
                "   Returns the {pooled_label}-host connection URI reflecting the new password"
            ),
            "6. Overwrite vault secret with the new connection URI".to_string(),
            "7. Append entry to rotation-log.jsonl".to_string(),
        ]
        .join("\n"))
    }

    async fn rotate(&self) -> Result<RotationOutcome> {
        let client = Client::new();
        let branch_id = self.resolve_branch_id(&client).await?;

        // --- Step 1: reset password ---
        let reset_url = format!(
            "{NEON_API}/projects/{}/branches/{}/roles/{}/reset_password",
            self.project_id, branch_id, self.role
        );
        let resp = client
            .post(&reset_url)
            .bearer_auth(self.api_key.expose_secret())
            .header("Content-Type", "application/json")
            .send()
            .await
            .map_err(|e| self.rotation_failed(format!("reset_password request failed: {e}")))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(self.rotation_failed(format!("reset_password returned {status}: {text}")));
        }
        // We don't extract the password from this response — the
        // connection_uri lookup below returns the full URI atomically with
        // the new password substituted. But we still parse the body to
        // surface JSON-shape errors loudly rather than silently moving on.
        let _: Value = resp
            .json()
            .await
            .map_err(|e| self.rotation_failed(format!("reset_password not JSON: {e}")))?;

        // --- Step 2: fetch connection URI (now reflects the new password) ---
        let conn_url = format!(
            "{NEON_API}/projects/{}/connection_uri?role_name={}&database_name={}&pooled={}",
            self.project_id, self.role, self.database, self.pooled
        );
        let resp = client
            .get(&conn_url)
            .bearer_auth(self.api_key.expose_secret())
            .send()
            .await
            .map_err(|e| self.rotation_failed(format!("connection_uri request failed: {e}")))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(self.rotation_failed(format!("connection_uri returned {status}: {text}")));
        }
        let json: Value = resp
            .json()
            .await
            .map_err(|e| self.rotation_failed(format!("connection_uri not JSON: {e}")))?;
        let uri = json
            .get("uri")
            .and_then(Value::as_str)
            .ok_or_else(|| self.rotation_failed("connection_uri response missing 'uri' field"))?;

        Ok(RotationOutcome {
            new_value: SecretString::from(uri.to_string()),
            // Neon doesn't expose a stable rotation-id concept — the
            // connection URI itself is the only identifier, and it changes
            // on every rotation. Leave new_key_id as None; the executor
            // skips writing the `-id` companion path when it's absent.
            new_key_id: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn from_config_requires_project_id() {
        let s = settings(&[
            ("type", "neon"),
            ("api_key_path", "credentials/neon/api-key"),
            ("role", "neondb_owner"),
            ("database", "neondb"),
        ]);
        let err = NeonProvider::from_config("test".into(), SecretString::from("k"), &s)
            .expect_err("should fail without project_id");
        let msg = format!("{err}");
        assert!(
            msg.contains("project_id"),
            "expected error to mention project_id, got: {msg}"
        );
    }

    #[test]
    fn from_config_requires_role() {
        let s = settings(&[
            ("type", "neon"),
            ("api_key_path", "credentials/neon/api-key"),
            ("project_id", "p1"),
            ("database", "neondb"),
        ]);
        let err = NeonProvider::from_config("test".into(), SecretString::from("k"), &s)
            .expect_err("should fail without role");
        assert!(format!("{err}").contains("role"));
    }

    #[test]
    fn from_config_requires_database() {
        let s = settings(&[
            ("type", "neon"),
            ("api_key_path", "credentials/neon/api-key"),
            ("project_id", "p1"),
            ("role", "neondb_owner"),
        ]);
        let err = NeonProvider::from_config("test".into(), SecretString::from("k"), &s)
            .expect_err("should fail without database");
        assert!(format!("{err}").contains("database"));
    }

    #[test]
    fn from_config_succeeds_with_required_fields() {
        let s = settings(&[
            ("type", "neon"),
            ("api_key_path", "credentials/neon/api-key"),
            ("project_id", "p-test-123"),
            ("role", "neondb_owner"),
            ("database", "neondb"),
        ]);
        let p = NeonProvider::from_config("test".into(), SecretString::from("k"), &s).unwrap();
        assert_eq!(p.project_id, "p-test-123");
        assert_eq!(p.role, "neondb_owner");
        assert_eq!(p.database, "neondb");
        assert_eq!(p.branch_id, None);
        assert!(!p.pooled);
    }

    #[test]
    fn from_config_pooled_truthy_values() {
        for v in ["true", "1", "yes"] {
            let s = settings(&[
                ("type", "neon"),
                ("api_key_path", "credentials/neon/api-key"),
                ("project_id", "p"),
                ("role", "r"),
                ("database", "d"),
                ("pooled", v),
            ]);
            let p = NeonProvider::from_config("t".into(), SecretString::from("k"), &s).unwrap();
            assert!(p.pooled, "pooled='{v}' should parse as true");
        }
    }

    #[test]
    fn from_config_pooled_falsy_default() {
        let s = settings(&[
            ("type", "neon"),
            ("api_key_path", "credentials/neon/api-key"),
            ("project_id", "p"),
            ("role", "r"),
            ("database", "d"),
            ("pooled", "no"),
        ]);
        let p = NeonProvider::from_config("t".into(), SecretString::from("k"), &s).unwrap();
        assert!(!p.pooled);
    }

    #[tokio::test]
    async fn preflight_succeeds_with_valid_config() {
        let s = settings(&[
            ("project_id", "p-test-123"),
            ("role", "neondb_owner"),
            ("database", "neondb"),
            ("branch_id", "br-test-456"),
        ]);
        let p = NeonProvider::from_config("t".into(), SecretString::from("k"), &s).unwrap();
        p.preflight().await.expect("preflight should pass");
    }

    #[tokio::test]
    async fn dry_run_mentions_endpoints_and_branch_resolution() {
        let s = settings(&[
            ("project_id", "p-test-123"),
            ("role", "neondb_owner"),
            ("database", "neondb"),
        ]);
        let p = NeonProvider::from_config("t".into(), SecretString::from("k"), &s).unwrap();
        let plan = p.dry_run().await.unwrap();
        assert!(plan.contains("reset_password"));
        assert!(plan.contains("connection_uri"));
        assert!(plan.contains("primary, resolved"));
        assert!(plan.contains("p-test-123"));
        assert!(plan.contains("neondb_owner"));
        assert!(plan.contains("direct")); // pooled=false default
    }

    #[tokio::test]
    async fn dry_run_pooled_marker() {
        let s = settings(&[
            ("project_id", "p"),
            ("role", "r"),
            ("database", "d"),
            ("pooled", "true"),
        ]);
        let p = NeonProvider::from_config("t".into(), SecretString::from("k"), &s).unwrap();
        let plan = p.dry_run().await.unwrap();
        assert!(plan.contains("pooled-host"));
    }
}

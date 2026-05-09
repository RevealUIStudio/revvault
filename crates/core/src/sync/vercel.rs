//! Vercel REST API client for env-var sync.
//!
//! Two callers consume this transport:
//! - `revvault sync vercel` (cli/src/commands/sync.rs) — whole-project
//!   push/pull from a `revvault-vercel.toml` manifest.
//! - `revvault rotate <provider>` via `rotation::sync_hook` — per-secret
//!   push chained after a rotation outcome.
//!
//! Both flows share the `VercelClient` here (transport + retry + DTOs);
//! manifest deserialization stays in the cli crate.
//!
//! # Retry
//!
//! All four mutating endpoints retry on `429 Too Many Requests` with
//! exponential backoff: 100ms → 500ms → 2000ms. After 3 retries (4
//! total attempts) the original 429 surfaces. Other 5xx responses
//! pass through unchanged — Vercel's published rate-limit guidance
//! treats 429 as the only retryable status.
//!
//! # Test injection
//!
//! [`VercelClient::with_base_url`] swaps the default
//! `https://api.vercel.com/v10` host for a mockito server's URL so
//! retry + happy-path can be exercised without network access.

use std::time::Duration;

use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};

const DEFAULT_BASE_URL: &str = "https://api.vercel.com/v10";
const RETRY_BACKOFFS_MS: [u64; 3] = [100, 500, 2000];

// ── Vercel API types ────────────────────────────────────────────────────────

/// One env-var record returned by the Vercel envs endpoint.
///
/// `id` identifies the row for PATCH/DELETE; `value` is only populated
/// when the GET passes `decrypt=true` (default `false` on the v10
/// list endpoint, so this field is normally `None`).
#[derive(Debug, Serialize, Deserialize)]
pub struct VercelEnvVar {
    pub id: Option<String>,
    pub key: String,
    pub value: Option<String>,
    pub target: Vec<String>,
    #[serde(rename = "type")]
    pub var_type: Option<String>,
    /// Set when the env-var is managed by a Vercel integration
    /// (e.g. Neon, Supabase). The CLI sync tool skips these to
    /// avoid double-managing them.
    #[serde(rename = "configurationId")]
    pub configuration_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct VercelEnvListResponse {
    envs: Vec<VercelEnvVar>,
}

// ── Client ──────────────────────────────────────────────────────────────────

/// Thin async client over the Vercel envs API.
///
/// Constructed via [`VercelClient::new`] for production use; tests use
/// [`VercelClient::with_base_url`] to point the requests at a mock
/// server.
pub struct VercelClient {
    token: String,
    team_id: Option<String>,
    base: String,
    client: reqwest::Client,
}

impl VercelClient {
    /// Construct a client with the production Vercel API base URL.
    pub fn new(token: String, team_id: Option<String>) -> Self {
        Self {
            token,
            team_id,
            base: DEFAULT_BASE_URL.to_string(),
            client: reqwest::Client::new(),
        }
    }

    /// Override the Vercel API base URL — used by tests to point
    /// the client at a mockito server.
    pub fn with_base_url(mut self, base: impl Into<String>) -> Self {
        self.base = base.into();
        self
    }

    fn base_url(&self, project_id: &str) -> String {
        let mut url = format!("{}/projects/{}/env", self.base, project_id);
        if let Some(ref team) = self.team_id {
            url.push_str(&format!("?teamId={}", team));
        }
        url
    }

    fn item_url(&self, project_id: &str, env_id: &str) -> String {
        let mut url = format!("{}/projects/{}/env/{}", self.base, project_id, env_id);
        if let Some(ref team) = self.team_id {
            url.push_str(&format!("?teamId={}", team));
        }
        url
    }

    /// Send a request, retrying up to 3 times on `429 Too Many Requests`
    /// with backoffs of 100ms / 500ms / 2000ms. Builder must be
    /// cloneable (no streamed bodies); `.json()` and bare GET/DELETE
    /// are fine.
    async fn send_retrying(
        &self,
        builder: reqwest::RequestBuilder,
    ) -> anyhow::Result<reqwest::Response> {
        let mut attempt = 0usize;
        loop {
            let cloned = builder
                .try_clone()
                .expect("VercelClient request must be cloneable for retry-on-429");
            let resp = cloned.send().await.context("Failed to reach Vercel API")?;
            if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS
                && attempt < RETRY_BACKOFFS_MS.len()
            {
                tokio::time::sleep(Duration::from_millis(RETRY_BACKOFFS_MS[attempt])).await;
                attempt += 1;
                continue;
            }
            return Ok(resp);
        }
    }

    /// List all env vars on a project (current target snapshot).
    /// `value` fields are unpopulated unless `decrypt=true` is
    /// requested — this client does not request decryption.
    pub async fn list_env_vars(&self, project_id: &str) -> anyhow::Result<Vec<VercelEnvVar>> {
        let url = self.base_url(project_id);
        let req = self.client.get(&url).bearer_auth(&self.token);
        let resp = self.send_retrying(req).await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Vercel API returned {}: {}", status, body);
        }

        let data: VercelEnvListResponse = resp.json().await?;
        Ok(data.envs)
    }

    /// Create a new env var. The Vercel API rejects duplicates with
    /// 409; callers detect existing rows via [`Self::list_env_vars`]
    /// + dispatch to [`Self::update_env_var`] when present.
    pub async fn create_env_var(
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

        let req = self.client.post(&url).bearer_auth(&self.token).json(&body);
        let resp = self.send_retrying(req).await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Failed to create env var '{}': {} {}", key, status, body);
        }
        Ok(())
    }

    /// Update an existing env var by id (PATCH). The id is the
    /// opaque string returned by [`Self::list_env_vars`].
    ///
    /// Sends ONLY the `value` field in the PATCH body. Target list and
    /// var type (encrypted/sensitive) are preserved by Vercel as-is.
    /// This matters for two reasons:
    ///
    /// 1. **Sensitive-flagged vars:** Vercel's PATCH rejects with 400
    ///    "You cannot change the type of a Sensitive Environment Variable"
    ///    if the body includes `"type": "encrypted"`. Omitting type lets
    ///    sensitive vars keep their flag during value rotation.
    ///
    /// 2. **Multi-target preservation:** if a var has target=[production,
    ///    preview], sending target=[production] in the PATCH would shrink
    ///    its target list. Operators usually want value-only rotation,
    ///    not target changes, so omitting target keeps existing targets.
    ///
    /// `_targets` is retained in the signature for callsite stability but
    /// no longer used in the body. A future PR may add a separate
    /// `update_env_var_with_targets` for the rare case where intentional
    /// target change is desired.
    pub async fn update_env_var(
        &self,
        project_id: &str,
        env_id: &str,
        value: &str,
        _targets: &[String],
    ) -> anyhow::Result<()> {
        let url = self.item_url(project_id, env_id);

        let body = serde_json::json!({
            "value": value,
        });

        let req = self.client.patch(&url).bearer_auth(&self.token).json(&body);
        let resp = self.send_retrying(req).await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Failed to update env var '{}': {} {}", env_id, status, body);
        }
        Ok(())
    }

    /// Delete an env var by id. Reserved for the cli sync tool's
    /// future orphan-cleanup mode; the rotation chain never deletes.
    #[allow(dead_code)]
    pub async fn delete_env_var(&self, project_id: &str, env_id: &str) -> anyhow::Result<()> {
        let url = self.item_url(project_id, env_id);

        let req = self.client.delete(&url).bearer_auth(&self.token);
        let resp = self.send_retrying(req).await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Failed to delete env var '{}': {} {}", env_id, status, body);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn list_env_vars_happy_path() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/projects/prj_test/env")
            .match_header("authorization", "Bearer token-x")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"envs":[{"id":"e1","key":"POSTGRES_URL","target":["production"],"type":"encrypted"}]}"#,
            )
            .create_async()
            .await;

        let client = VercelClient::new("token-x".into(), None).with_base_url(server.url());
        let envs = client.list_env_vars("prj_test").await.unwrap();
        assert_eq!(envs.len(), 1);
        assert_eq!(envs[0].key, "POSTGRES_URL");
        assert_eq!(envs[0].id.as_deref(), Some("e1"));

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn list_env_vars_includes_team_id_query() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/projects/prj_test/env?teamId=team_x")
            .with_status(200)
            .with_body(r#"{"envs":[]}"#)
            .create_async()
            .await;

        let client =
            VercelClient::new("t".into(), Some("team_x".into())).with_base_url(server.url());
        client.list_env_vars("prj_test").await.unwrap();

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn list_env_vars_retries_on_429_then_succeeds() {
        let mut server = mockito::Server::new_async().await;
        let m429 = server
            .mock("GET", "/projects/p/env")
            .with_status(429)
            .with_body("{}")
            .expect(2)
            .create_async()
            .await;
        let m200 = server
            .mock("GET", "/projects/p/env")
            .with_status(200)
            .with_body(r#"{"envs":[]}"#)
            .expect(1)
            .create_async()
            .await;

        let client = VercelClient::new("t".into(), None).with_base_url(server.url());
        let envs = client.list_env_vars("p").await.unwrap();
        assert!(envs.is_empty());

        m429.assert_async().await;
        m200.assert_async().await;
    }

    #[tokio::test]
    async fn list_env_vars_retries_at_most_3_times() {
        // 4 total attempts (1 initial + 3 retries), all 429 → final 429
        // surfaces as an error (no successful response).
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("GET", "/projects/p/env")
            .with_status(429)
            .with_body("rate limited")
            .expect(4)
            .create_async()
            .await;

        let client = VercelClient::new("t".into(), None).with_base_url(server.url());
        let err = client
            .list_env_vars("p")
            .await
            .expect_err("4 consecutive 429s must surface");
        let msg = format!("{err}");
        assert!(
            msg.contains("429"),
            "expected error to mention 429, got: {msg}"
        );

        m.assert_async().await;
    }

    #[tokio::test]
    async fn create_env_var_posts_expected_body() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/projects/p/env")
            .match_header("authorization", "Bearer t")
            .match_body(mockito::Matcher::PartialJson(serde_json::json!({
                "key": "POSTGRES_URL",
                "value": "postgres://...",
                "target": ["production"],
                "type": "encrypted",
            })))
            .with_status(201)
            .with_body("{}")
            .create_async()
            .await;

        let client = VercelClient::new("t".into(), None).with_base_url(server.url());
        client
            .create_env_var(
                "p",
                "POSTGRES_URL",
                "postgres://...",
                &["production".to_string()],
            )
            .await
            .unwrap();

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn update_env_var_patches_by_id_with_value_only() {
        // Body must contain ONLY "value" — target + type are deliberately
        // omitted so existing target list and Sensitive flag are preserved.
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("PATCH", "/projects/p/env/env_abc")
            .match_body(mockito::Matcher::Json(serde_json::json!({
                "value": "v2",
            })))
            .with_status(200)
            .with_body("{}")
            .create_async()
            .await;

        let client = VercelClient::new("t".into(), None).with_base_url(server.url());
        client
            .update_env_var("p", "env_abc", "v2", &["production".to_string()])
            .await
            .unwrap();

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn list_env_vars_propagates_non_429_errors() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/projects/p/env")
            .with_status(500)
            .with_body("server error")
            .expect(1) // no retry on 500
            .create_async()
            .await;

        let client = VercelClient::new("t".into(), None).with_base_url(server.url());
        let err = client.list_env_vars("p").await.expect_err("500 surfaces");
        assert!(format!("{err}").contains("500"));

        mock.assert_async().await;
    }
}

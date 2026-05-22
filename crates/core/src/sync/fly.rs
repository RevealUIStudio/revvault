//! Fly.io secrets sync client.
//!
//! Consumed by `revvault sync fly` (cli/src/commands/sync.rs) to push vault
//! secrets onto a Fly app. Mirrors [`super::vercel::VercelClient`] (transport +
//! 429 retry + DTOs); manifest deserialization stays in the cli crate.
//!
//! # Why this differs from the Vercel client
//!
//! Fly's API is **write-only for secret values**. The `app.secrets` query
//! returns only secret *names* + an opaque `digest` — never the value. So
//! unlike the Vercel flow, the sync diff cannot do value-equality MATCH
//! detection; it can only tell Add (name absent) from Set (name present).
//! [`FlyClient::set_secrets`] batches every managed secret into one
//! `setSecrets` mutation (= one Fly release) and passes `replaceAll: false`
//! so secrets not in the manifest are never deleted.
//!
//! # Retry
//!
//! [`FlyClient::send_retrying`] retries `429 Too Many Requests` with backoffs
//! of 100ms / 500ms / 2000ms — identical policy to the Vercel client. Other
//! non-2xx statuses surface immediately. GraphQL-level errors (HTTP 200 with a
//! non-empty `errors` array) are also surfaced as `Err`.
//!
//! # Test injection
//!
//! [`FlyClient::with_base_url`] swaps the default `https://api.fly.io/graphql`
//! endpoint for a mockito server URL so the request shape + retry can be
//! exercised without network access or a real Fly token.

use std::time::Duration;

use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};

const DEFAULT_BASE_URL: &str = "https://api.fly.io/graphql";
const RETRY_BACKOFFS_MS: [u64; 3] = [100, 500, 2000];

// ── Fly API types ─────────────────────────────────────────────────────────

/// A secret as reported by Fly's `app.secrets` query — name + opaque digest.
/// Never carries a value (Fly does not expose secret values via the API).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FlySecret {
    pub name: String,
    pub digest: Option<String>,
}

/// Outcome of a `setSecrets` mutation — the release it triggered, if any.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetSecretsResult {
    pub release_id: Option<String>,
    pub release_version: Option<i64>,
}

// ── Client ────────────────────────────────────────────────────────────────

/// Thin async client over Fly's GraphQL secrets API.
///
/// Constructed via [`FlyClient::new`] for production use; tests use
/// [`FlyClient::with_base_url`] to point requests at a mock server.
pub struct FlyClient {
    token: String,
    base: String,
    client: reqwest::Client,
}

impl FlyClient {
    /// Construct a client with the production Fly GraphQL endpoint. `token` is
    /// a Fly API token (org token or app deploy token) — passed as a bearer.
    pub fn new(token: String) -> Self {
        Self {
            token,
            base: DEFAULT_BASE_URL.to_string(),
            client: reqwest::Client::new(),
        }
    }

    /// Override the GraphQL endpoint — used by tests to point the client at a
    /// mockito server.
    pub fn with_base_url(mut self, base: impl Into<String>) -> Self {
        self.base = base.into();
        self
    }

    /// Send a request, retrying up to 3 times on `429 Too Many Requests` with
    /// backoffs of 100ms / 500ms / 2000ms. Builder must be cloneable; a JSON
    /// body (the only kind this client sends) is fine.
    async fn send_retrying(
        &self,
        builder: reqwest::RequestBuilder,
    ) -> anyhow::Result<reqwest::Response> {
        let mut attempt = 0usize;
        loop {
            let cloned = builder
                .try_clone()
                .expect("FlyClient request must be cloneable for retry-on-429");
            let resp = cloned.send().await.context("Failed to reach Fly API")?;
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

    /// POST a GraphQL operation and return the parsed JSON `data`-bearing body.
    /// Surfaces transport errors, non-2xx HTTP, and GraphQL `errors` as `Err`.
    async fn graphql(
        &self,
        query: &str,
        variables: serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        let body = serde_json::json!({ "query": query, "variables": variables });
        let req = self
            .client
            .post(&self.base)
            .bearer_auth(&self.token)
            .json(&body);
        let resp = self.send_retrying(req).await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            bail!("Fly GraphQL returned {}: {}", status, text);
        }

        let value: serde_json::Value = resp.json().await.context("parsing Fly GraphQL JSON")?;
        if let Some(errors) = value.get("errors") {
            if errors.as_array().map(|a| !a.is_empty()).unwrap_or(false) {
                bail!("Fly GraphQL errors: {}", errors);
            }
        }
        Ok(value)
    }

    /// List the NAMES (+ opaque digests) of secrets set on a Fly app. Returns
    /// an empty vec when the app has no secrets; errors when the app is not
    /// found (wrong name or insufficient token scope).
    pub async fn list_secret_names(&self, app_name: &str) -> anyhow::Result<Vec<FlySecret>> {
        let query = r#"query($name: String!) { app(name: $name) { secrets { name digest } } }"#;
        let value = self
            .graphql(query, serde_json::json!({ "name": app_name }))
            .await?;

        #[derive(Deserialize)]
        struct SecretNode {
            name: String,
            digest: Option<String>,
        }
        #[derive(Deserialize)]
        struct AppNode {
            secrets: Vec<SecretNode>,
        }
        #[derive(Deserialize)]
        struct Data {
            app: Option<AppNode>,
        }

        let data: Data = serde_json::from_value(
            value
                .get("data")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        )
        .context("unexpected Fly app.secrets response shape")?;

        let app = data.app.ok_or_else(|| {
            anyhow::anyhow!(
                "Fly app '{}' not found (check the app name and that the token has access)",
                app_name
            )
        })?;

        Ok(app
            .secrets
            .into_iter()
            .map(|s| FlySecret {
                name: s.name,
                digest: s.digest,
            })
            .collect())
    }

    /// Set (create or update) secrets on a Fly app in one batched mutation,
    /// which triggers a single release. `replace_all = false` leaves secrets
    /// not in the batch untouched (no deletion) — orphan cleanup is never
    /// automatic, mirroring the Vercel client's no-delete policy.
    pub async fn set_secrets(
        &self,
        app_name: &str,
        secrets: &[(String, String)],
        replace_all: bool,
    ) -> anyhow::Result<SetSecretsResult> {
        let mutation = r#"mutation($input: SetSecretsInput!) { setSecrets(input: $input) { release { id version } } }"#;
        let secret_inputs: Vec<serde_json::Value> = secrets
            .iter()
            .map(|(k, v)| serde_json::json!({ "key": k, "value": v }))
            .collect();
        let variables = serde_json::json!({
            "input": {
                "appId": app_name,
                "secrets": secret_inputs,
                "replaceAll": replace_all,
            }
        });
        let value = self.graphql(mutation, variables).await?;

        let release = value
            .pointer("/data/setSecrets/release")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        Ok(SetSecretsResult {
            release_id: release.get("id").and_then(|v| v.as_str()).map(String::from),
            release_version: release.get("version").and_then(serde_json::Value::as_i64),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn list_secret_names_parses_names_and_digests() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/")
            .match_header("authorization", "Bearer tok")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"data":{"app":{"secrets":[{"name":"POSTGRES_URL","digest":"abc"},{"name":"REVEALUI_SECRET","digest":null}]}}}"#,
            )
            .create_async()
            .await;

        let client = FlyClient::new("tok".into()).with_base_url(server.url());
        let secrets = client.list_secret_names("revealui-worker").await.unwrap();

        assert_eq!(secrets.len(), 2);
        assert_eq!(secrets[0].name, "POSTGRES_URL");
        assert_eq!(secrets[0].digest.as_deref(), Some("abc"));
        assert_eq!(secrets[1].name, "REVEALUI_SECRET");
        assert_eq!(secrets[1].digest, None);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn list_secret_names_empty_when_no_secrets() {
        let mut server = mockito::Server::new_async().await;
        server
            .mock("POST", "/")
            .with_status(200)
            .with_body(r#"{"data":{"app":{"secrets":[]}}}"#)
            .create_async()
            .await;

        let client = FlyClient::new("tok".into()).with_base_url(server.url());
        let secrets = client.list_secret_names("revealui-worker").await.unwrap();
        assert!(secrets.is_empty());
    }

    #[tokio::test]
    async fn list_secret_names_errors_when_app_missing() {
        let mut server = mockito::Server::new_async().await;
        server
            .mock("POST", "/")
            .with_status(200)
            .with_body(r#"{"data":{"app":null}}"#)
            .create_async()
            .await;

        let client = FlyClient::new("tok".into()).with_base_url(server.url());
        let err = client.list_secret_names("nope").await.unwrap_err();
        assert!(format!("{err}").contains("not found"));
    }

    #[tokio::test]
    async fn set_secrets_sends_batched_input_and_parses_release() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/")
            .match_header("authorization", "Bearer tok")
            .match_body(mockito::Matcher::PartialJson(serde_json::json!({
                "variables": {
                    "input": {
                        "appId": "revealui-worker",
                        "replaceAll": false,
                        "secrets": [ { "key": "POSTGRES_URL", "value": "postgres://x" } ],
                    }
                }
            })))
            .with_status(200)
            .with_body(r#"{"data":{"setSecrets":{"release":{"id":"rel_1","version":7}}}}"#)
            .create_async()
            .await;

        let client = FlyClient::new("tok".into()).with_base_url(server.url());
        let res = client
            .set_secrets(
                "revealui-worker",
                &[("POSTGRES_URL".to_string(), "postgres://x".to_string())],
                false,
            )
            .await
            .unwrap();

        assert_eq!(res.release_id.as_deref(), Some("rel_1"));
        assert_eq!(res.release_version, Some(7));
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn graphql_errors_surface_as_err() {
        let mut server = mockito::Server::new_async().await;
        server
            .mock("POST", "/")
            .with_status(200)
            .with_body(r#"{"errors":[{"message":"Unauthorized"}]}"#)
            .create_async()
            .await;

        let client = FlyClient::new("tok".into()).with_base_url(server.url());
        let err = client.list_secret_names("x").await.unwrap_err();
        assert!(format!("{err}").contains("GraphQL errors"));
    }

    #[tokio::test]
    async fn retries_on_429_then_succeeds() {
        let mut server = mockito::Server::new_async().await;
        let m429 = server
            .mock("POST", "/")
            .with_status(429)
            .with_body("{}")
            .expect(2)
            .create_async()
            .await;
        let m200 = server
            .mock("POST", "/")
            .with_status(200)
            .with_body(r#"{"data":{"app":{"secrets":[]}}}"#)
            .expect(1)
            .create_async()
            .await;

        let client = FlyClient::new("tok".into()).with_base_url(server.url());
        client.list_secret_names("p").await.unwrap();

        m429.assert_async().await;
        m200.assert_async().await;
    }

    #[tokio::test]
    async fn non_429_error_surfaces_without_retry() {
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("POST", "/")
            .with_status(500)
            .with_body("boom")
            .expect(1)
            .create_async()
            .await;

        let client = FlyClient::new("tok".into()).with_base_url(server.url());
        let err = client.list_secret_names("p").await.unwrap_err();
        assert!(format!("{err}").contains("500"));
        m.assert_async().await;
    }
}

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
//! `https://api.vercel.com` host for a mockito server's URL so
//! retry + happy-path can be exercised without network access.

use std::{collections::BTreeSet, time::Duration};

use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};

const DEFAULT_BASE_URL: &str = "https://api.vercel.com";
const RETRY_BACKOFFS_MS: [u64; 3] = [100, 500, 2000];

// ── Vercel API types ────────────────────────────────────────────────────────

/// One env-var record returned by the Vercel envs endpoint.
///
/// `id` identifies the row for PATCH/DELETE; `value` is only populated
/// when the GET passes `decrypt=true` (default `false` on the v10
/// list endpoint, so this field is normally `None`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VercelEnvVar {
    pub id: Option<String>,
    pub key: String,
    pub value: Option<String>,
    #[serde(default, deserialize_with = "deserialize_targets")]
    pub target: Vec<String>,
    #[serde(rename = "type")]
    pub var_type: Option<String>,
    /// Set when the env-var is managed by a Vercel integration
    /// (e.g. Neon, Supabase). The CLI sync tool skips these to
    /// avoid double-managing them.
    #[serde(rename = "configurationId")]
    pub configuration_id: Option<String>,
    #[serde(rename = "gitBranch")]
    pub git_branch: Option<String>,
    #[serde(default, rename = "customEnvironmentIds")]
    pub custom_environment_ids: Vec<String>,
    pub visibility: Option<String>,
    #[serde(default)]
    pub system: bool,
    /// Provider metadata is retained for scope-change detection, never printed.
    #[serde(flatten)]
    pub metadata: std::collections::BTreeMap<String, serde_json::Value>,
}

fn deserialize_targets<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Targets {
        One(String),
        Many(Vec<String>),
    }
    Ok(match Targets::deserialize(d)? {
        Targets::One(t) => vec![t],
        Targets::Many(t) => t,
    })
}

fn target_set(targets: &[String]) -> BTreeSet<&str> {
    targets.iter().map(String::as_str).collect()
}

impl VercelEnvVar {
    /// Current Secret classification. Read availability depends on the
    /// environment; Development Secret values may be returned by the API.
    pub fn is_sensitive(&self) -> bool {
        self.visibility.as_deref() == Some("secret")
            || self.var_type.as_deref() == Some("sensitive")
    }

    /// Preserve historical secret intent on create without treating a
    /// deprecated `secret` reference as proof of current Secret protection.
    pub fn requires_sensitive_create(&self) -> bool {
        self.is_sensitive() || self.var_type.as_deref() == Some("secret")
    }

    /// Target order has no semantic significance.
    pub fn has_targets(&self, targets: &[String]) -> bool {
        target_set(&self.target) == target_set(targets)
    }

    /// Compare row identity, classification and all preserved metadata.
    /// Write timestamps and decryption flags are expected to change after PATCH.
    pub fn same_scope(&self, other: &Self) -> bool {
        self.id == other.id
            && self.key == other.key
            && self.has_targets(&other.target)
            && self.var_type == other.var_type
            && self.visibility == other.visibility
            && self.git_branch == other.git_branch
            && target_set(&self.custom_environment_ids) == target_set(&other.custom_environment_ids)
            && self.configuration_id == other.configuration_id
            && self.system == other.system
            && self.stable_metadata().eq(other.stable_metadata())
    }

    fn stable_metadata(&self) -> impl Iterator<Item = (&String, &serde_json::Value)> {
        self.metadata
            .iter()
            .filter(|(key, _)| !matches!(key.as_str(), "updatedAt" | "updatedBy" | "decrypted"))
    }
}

/// Select a single writable project row without losing branch/custom scope.
/// Managed targets own the whole target set of one row, including disjoint drift.
/// Value-only callers select by target overlap and never change that set.
pub fn select_env_var<'a>(
    rows: &'a [VercelEnvVar],
    key: &str,
    targets: &[String],
    branch: Option<&str>,
    manage_targets: bool,
) -> anyhow::Result<Option<&'a VercelEnvVar>> {
    if targets.is_empty()
        || targets
            .iter()
            .any(|t| !matches!(t.as_str(), "production" | "preview" | "development"))
    {
        bail!("Invalid or empty targets for '{key}'");
    }
    if branch.is_some() && !targets.iter().any(|t| t == "preview") {
        bail!("Branch-scoped '{key}' requires a preview target");
    }
    let mut ids = BTreeSet::new();
    let mut selected = None;
    for row in rows.iter().filter(|r| r.key == key) {
        let id = row
            .id
            .as_deref()
            .filter(|id| !id.is_empty())
            .with_context(|| format!("Missing remote row ID for '{key}'"))?;
        if !ids.insert(id) {
            bail!("Duplicate remote row ID for '{key}'");
        }
        // Every same-key row contributes to the no-downgrade decision on create.
        if !matches!(
            row.var_type.as_deref(),
            Some("plain" | "encrypted" | "sensitive" | "secret" | "system")
        ) || !matches!(row.visibility.as_deref(), None | Some("config" | "secret"))
        {
            bail!("Remote '{key}' has unsupported classification");
        }
        if row.git_branch.as_deref() != branch || !row.custom_environment_ids.is_empty() {
            continue;
        }
        if !manage_targets && !row.target.iter().any(|t| targets.contains(t)) {
            continue;
        }
        if row.configuration_id.is_some()
            || row.system
            || !matches!(
                row.var_type.as_deref(),
                Some("plain" | "encrypted" | "sensitive" | "secret")
            )
            || !matches!(row.visibility.as_deref(), None | Some("config" | "secret"))
        {
            bail!("Remote '{key}' is integration/system managed or has unsupported classification");
        }
        if row.target.is_empty()
            || row
                .target
                .iter()
                .any(|t| !matches!(t.as_str(), "production" | "preview" | "development"))
        {
            bail!("Remote '{key}' has unsupported target scope");
        }
        if selected.replace(row).is_some() {
            bail!("Ambiguous remote rows for '{key}'");
        }
    }
    Ok(selected)
}

/// Reject an observed change to any same-key row before writing a saved plan.
pub fn ensure_key_snapshot(
    before: &[VercelEnvVar],
    after: &[VercelEnvVar],
    key: &str,
) -> anyhow::Result<()> {
    let old: Vec<_> = before.iter().filter(|r| r.key == key).collect();
    let new: Vec<_> = after.iter().filter(|r| r.key == key).collect();
    if old.len() != new.len()
        || old.iter().any(|r| {
            !new.iter().any(|n| {
                r.same_scope(n)
                    && r.metadata.get("updatedAt") == n.metadata.get("updatedAt")
                    && r.metadata.get("updatedBy") == n.metadata.get("updatedBy")
            })
        })
    {
        bail!("Remote scope changed for '{key}'; rerun sync to review a fresh plan");
    }
    Ok(())
}

/// Env-var `type` written on create.
///
/// Vercel distinguishes `encrypted` (encrypted at rest, but any project
/// member can reveal the plaintext in the UI / API) from `sensitive`
/// (Secret protection; Production/Preview values are not returned by pulls,
/// while Development Secret values may be returned). Credentials
/// that can charge cards, forge webhooks, or sign tokens belong in
/// `Sensitive`. This client never writes the other Vercel types (`plain`,
/// `system`, legacy `secret`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvVarType {
    /// Vercel default — any project member can reveal the value.
    Encrypted,
    /// Secret protection, with environment-specific API read availability.
    Sensitive,
}

impl EnvVarType {
    /// Wire value for the Vercel `type` field.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Encrypted => "encrypted",
            Self::Sensitive => "sensitive",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct VercelEnvListResponse {
    envs: Vec<VercelEnvVar>,
    #[serde(default)]
    pagination: Option<serde_json::Value>,
    #[serde(default, rename = "hiddenProductionEnvCount")]
    hidden_production_env_count: u64,
}

impl VercelEnvListResponse {
    fn complete(self) -> anyhow::Result<Vec<VercelEnvVar>> {
        // The published endpoint has no pagination request parameter. Never
        // infer absence from a partial page or permission-filtered response.
        if self.hidden_production_env_count != 0
            || self
                .pagination
                .as_ref()
                .is_some_and(|p| p.get("next") != Some(&serde_json::Value::Null))
        {
            bail!("Vercel environment inventory is hidden or incomplete; no safe sync plan is available");
        }
        let mut ids = BTreeSet::new();
        if self
            .envs
            .iter()
            .filter_map(|r| r.id.as_deref())
            .any(|id| !ids.insert(id))
        {
            bail!("Duplicate immutable IDs in Vercel environment inventory");
        }
        Ok(self.envs)
    }
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
        let mut url = format!("{}/v10/projects/{}/env", self.base, project_id);
        if let Some(ref team) = self.team_id {
            url.push_str(&format!("?teamId={}", team));
        }
        url
    }

    fn item_url(&self, project_id: &str, env_id: &str) -> String {
        let mut url = format!("{}/v9/projects/{}/env/{}", self.base, project_id, env_id);
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
            bail!("Vercel API returned {}", status);
        }

        let data: VercelEnvListResponse = resp.json().await?;
        data.complete()
    }

    /// List env vars with decrypted values via `decrypt=true`.
    ///
    /// Requires the `env:read:decrypted` scope on the Vercel token. Returns
    /// `Ok(None)` when the token lacks the scope (403) so callers can fall
    /// back to assume-drift rather than hard-failing. Any other non-success
    /// status is returned as `Err`.
    pub async fn list_env_vars_with_values(
        &self,
        project_id: &str,
    ) -> anyhow::Result<Option<Vec<VercelEnvVar>>> {
        let base = self.base_url(project_id);
        let separator = if base.contains('?') { '&' } else { '?' };
        let url = format!("{base}{separator}decrypt=true");
        let req = self.client.get(&url).bearer_auth(&self.token);
        let resp = self.send_retrying(req).await?;

        if resp.status() == reqwest::StatusCode::FORBIDDEN {
            return Ok(None);
        }
        if !resp.status().is_success() {
            let status = resp.status();
            bail!("Vercel API (decrypt=true) returned {}", status);
        }

        let data: VercelEnvListResponse = resp.json().await?;
        Ok(Some(data.complete()?))
    }

    /// Require a complete shared-variable inventory before taking ownership of
    /// targets. Linked shared variables are outside project-row ownership.
    /// Permission failures are fatal; absence must never be guessed.
    pub async fn ensure_no_shared_keys(
        &self,
        project_id: &str,
        keys: &[&str],
    ) -> anyhow::Result<()> {
        if keys.is_empty() {
            return Ok(());
        }
        let mut url = reqwest::Url::parse(&format!("{}/v1/env", self.base))?;
        url.query_pairs_mut().append_pair("projectId", project_id);
        if let Some(team) = &self.team_id {
            url.query_pairs_mut().append_pair("teamId", team);
        }
        let req = self.client.get(url).bearer_auth(&self.token);
        let resp = self.send_retrying(req).await?;
        if !resp.status().is_success() {
            bail!(
                "Cannot verify shared environment ownership: {}",
                resp.status()
            );
        }
        #[derive(Deserialize)]
        struct SharedList {
            data: Vec<SharedRow>,
            pagination: serde_json::Value,
        }
        #[derive(Deserialize)]
        struct SharedRow {
            key: String,
        }
        let data: SharedList = resp.json().await?;
        if data.pagination.get("next") != Some(&serde_json::Value::Null) {
            bail!("Shared environment inventory is incomplete");
        }
        if let Some(row) = data.data.iter().find(|r| keys.contains(&r.key.as_str())) {
            bail!(
                "Managed key '{}' has a linked shared environment variable",
                row.key
            );
        }
        Ok(())
    }

    /// Verify PATCH scope and classification by immutable ID. Return only
    /// verified same-key rows so later plans can recognize our own writes.
    /// This is detection, not a remote compare-and-swap.
    pub async fn verify_update(
        &self,
        project: &str,
        before: &[VercelEnvVar],
        row: &VercelEnvVar,
        targets: Option<&[String]>,
    ) -> anyhow::Result<Vec<VercelEnvVar>> {
        let after = self.list_env_vars(project).await?;
        let mut expected = before.to_vec();
        let updated = expected
            .iter_mut()
            .find(|r| r.id == row.id)
            .context("Planned row missing from snapshot")?;
        if let Some(targets) = targets {
            updated.target = targets.to_vec();
        }
        // Only the row we wrote may acquire a new write revision. Preserve
        // revision checking for every other same-key row.
        if let Some(actual) = after.iter().find(|r| r.id == row.id) {
            for field in ["updatedAt", "updatedBy"] {
                if let Some(value) = actual.metadata.get(field) {
                    updated.metadata.insert(field.into(), value.clone());
                } else {
                    updated.metadata.remove(field);
                }
            }
        }
        ensure_key_snapshot(&expected, &after, &row.key).context(
            "PATCH completed but remote metadata verification failed; review a fresh sync plan",
        )?;
        Ok(after
            .into_iter()
            .filter(|current| current.key == row.key)
            .collect())
    }

    /// Verify a create and preservation of every previously existing
    /// same-key row. The provider supplies the new immutable row ID.
    pub async fn verify_create(
        &self,
        project: &str,
        before: &[VercelEnvVar],
        key: &str,
        targets: &[String],
        branch: Option<&str>,
        requested_type: EnvVarType,
    ) -> anyhow::Result<VercelEnvVar> {
        let after = self.list_env_vars(project).await?;
        let row = select_env_var(&after, key, targets, branch, false)?
            .context("Create completed but created row is missing")?;
        if !row.has_targets(targets)
            || !matches!(
                row.var_type.as_deref(),
                Some("encrypted" | "sensitive" | "secret")
            )
            || (row.var_type.as_deref() == Some("secret") && !row.is_sensitive())
            || (requested_type == EnvVarType::Sensitive && !row.is_sensitive())
            || before.iter().any(|old| old.id == row.id)
        {
            bail!("Create completed but scope or classification verification failed for '{key}'");
        }
        let remainder: Vec<_> = after.iter().filter(|r| r.id != row.id).cloned().collect();
        ensure_key_snapshot(before, &remainder, key)
            .context("Create completed but preserved metadata changed; review a fresh sync plan")?;
        Ok(row.clone())
    }

    /// Create a new env var with the requested [`EnvVarType`]. The Vercel
    /// API rejects duplicates with 409; callers detect existing rows via
    /// [`Self::list_env_vars`] + dispatch to [`Self::update_env_var`] when
    /// present.
    ///
    /// The `type` is part of the POST body. If Vercel rejects the requested
    /// type, the error names that type and the call fails — there is
    /// deliberately no fallback that retries with a downgraded type.
    /// Re-creating a sensitive credential as `encrypted` is the
    /// silent-downgrade class this parameter closes (observed 2026-06-10:
    /// a sync apply re-created sensitive Stripe + signing secrets as
    /// UI-revealable `encrypted` rows).
    ///
    /// `git_branch` scopes the var to a single preview git branch (e.g.
    /// `staging`), so it is exposed only to that branch's preview
    /// deployments rather than every branch's previews. `None` omits the
    /// `gitBranch` field from the body, preserving prior behavior. Vercel
    /// only accepts `gitBranch` alongside a `targets` list that includes
    /// `"preview"`; this is checked here and fails loudly rather than
    /// surfacing as a confusing Vercel 400.
    pub async fn create_env_var(
        &self,
        project_id: &str,
        key: &str,
        value: &str,
        targets: &[String],
        var_type: EnvVarType,
        git_branch: Option<&str>,
    ) -> anyhow::Result<()> {
        if let Some(branch) = git_branch {
            if !targets.iter().any(|t| t == "preview") {
                bail!(
                    "Cannot scope env var '{}' to git branch '{}': targets {:?} do not include \"preview\" (Vercel only accepts gitBranch alongside a preview target)",
                    key,
                    branch,
                    targets
                );
            }
        }

        let url = self.base_url(project_id);
        let mut body = serde_json::json!({
            "key": key,
            "value": value,
            "target": targets,
            "type": var_type.as_str(),
        });
        if let Some(branch) = git_branch {
            body["gitBranch"] = serde_json::Value::String(branch.to_string());
        }

        let req = self.client.post(&url).bearer_auth(&self.token).json(&body);
        let resp = self.send_retrying(req).await?;

        if !resp.status().is_success() {
            let status = resp.status();
            bail!(
                "Failed to create env var '{}' (requested type={}): {}",
                key,
                var_type.as_str(),
                status
            );
        }
        Ok(())
    }

    /// PATCH an immutable row ID with only the fields that changed. Omit value
    /// only when exact-ID decrypted evidence proves equality; omit targets for
    /// normal rotation. Empty updates fail. Type, visibility, branch, custom
    /// scopes and ownership are never sent.
    pub async fn update_env_var(
        &self,
        project_id: &str,
        env_id: &str,
        value: Option<&str>,
        targets: Option<&[String]>,
    ) -> anyhow::Result<()> {
        let url = self.item_url(project_id, env_id);

        if value.is_none() && targets.is_none() {
            bail!("Refusing empty update for row '{env_id}'");
        }
        let mut body = serde_json::json!({});
        if let Some(value) = value {
            body["value"] = serde_json::json!(value);
        }
        if let Some(targets) = targets {
            if targets.is_empty()
                || targets
                    .iter()
                    .any(|t| !matches!(t.as_str(), "production" | "preview" | "development"))
            {
                bail!("Invalid managed targets for row '{env_id}'");
            }
            body["target"] = serde_json::json!(targets);
        }

        let req = self.client.patch(&url).bearer_auth(&self.token).json(&body);
        let resp = self.send_retrying(req).await?;

        if !resp.status().is_success() {
            let status = resp.status();
            bail!("Failed to update env var '{}': {}", env_id, status);
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
            bail!("Failed to delete env var '{}': {}", env_id, status);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(extra: serde_json::Value) -> VercelEnvVar {
        let mut value = serde_json::json!({"id":"e1", "key":"KEY", "target":["production"], "type":"sensitive"});
        value
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn managed_selection_finds_disjoint_drift_and_ignores_target_order() {
        let rows = vec![row(serde_json::json!({"target":"preview"}))];
        let production = vec!["production".into()];
        assert!(select_env_var(&rows, "KEY", &production, None, false)
            .unwrap()
            .is_none());
        assert_eq!(
            select_env_var(&rows, "KEY", &production, None, true)
                .unwrap()
                .unwrap()
                .id
                .as_deref(),
            Some("e1")
        );
        let both = row(serde_json::json!({"target":["preview", "production"]}));
        assert!(both.has_targets(&["production".into(), "preview".into()]));
    }

    #[test]
    fn selection_preserves_branch_and_custom_scopes() {
        let rows = vec![
            row(serde_json::json!({"id":"branch", "gitBranch":"staging", "target":["preview"]})),
            row(serde_json::json!({"id":"custom", "customEnvironmentIds":["env_custom"]})),
            row(serde_json::json!({})),
        ];
        assert_eq!(
            select_env_var(&rows, "KEY", &["production".into()], None, true)
                .unwrap()
                .unwrap()
                .id
                .as_deref(),
            Some("e1")
        );
        assert_eq!(
            select_env_var(&rows, "KEY", &["preview".into()], Some("staging"), false)
                .unwrap()
                .unwrap()
                .id
                .as_deref(),
            Some("branch")
        );
        assert!(
            select_env_var(&rows, "KEY", &["production".into()], Some("staging"), true).is_err()
        );
    }

    #[test]
    fn selection_rejects_ambiguous_missing_and_protected_rows() {
        let targets = vec!["production".into()];
        for extra in [
            serde_json::json!({"id":null}),
            serde_json::json!({"id":""}),
            serde_json::json!({"configurationId":"integration"}),
            serde_json::json!({"system":true}),
            serde_json::json!({"visibility":"future-type"}),
            serde_json::json!({"target":[]}),
        ] {
            assert!(select_env_var(&[row(extra)], "KEY", &targets, None, true).is_err());
        }
        for id in ["e1", "e2"] {
            let rows = vec![
                row(serde_json::json!({})),
                row(serde_json::json!({"id":id})),
            ];
            assert!(select_env_var(&rows, "KEY", &targets, None, true).is_err());
            assert!(select_env_var(&rows, "KEY", &targets, None, false).is_err());
        }
    }

    #[test]
    fn snapshot_rejects_scope_classification_and_metadata_changes() {
        let before = vec![row(serde_json::json!({}))];
        for extra in [
            serde_json::json!({"id":"replaced"}),
            serde_json::json!({"gitBranch":"changed"}),
            serde_json::json!({"type":"encrypted"}),
            serde_json::json!({"visibility":"config"}),
            serde_json::json!({"configurationId":"integration"}),
            serde_json::json!({"comment":"changed"}),
            serde_json::json!({"updatedAt":42}),
            serde_json::json!({"customEnvironmentIds":["new"]}),
            serde_json::json!({"target":["preview"]}),
        ] {
            assert!(ensure_key_snapshot(&before, &[row(extra)], "KEY").is_err());
        }
        assert!(ensure_key_snapshot(&before, &[], "KEY").is_err());
        assert!(row(serde_json::json!({"type":"encrypted", "visibility":"secret"})).is_sensitive());
    }

    #[test]
    fn incomplete_project_inventory_is_never_absence() {
        for extra in [
            serde_json::json!({"hiddenProductionEnvCount":1}),
            serde_json::json!({"pagination":{"next":123}}),
            serde_json::json!({"pagination":{}}),
        ] {
            let mut value = serde_json::json!({"envs":[]});
            value
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            assert!(serde_json::from_value::<VercelEnvListResponse>(value)
                .unwrap()
                .complete()
                .is_err());
        }
        let duplicate = serde_json::json!({"envs":[
            {"id":"duplicate", "key":"A", "target":"production", "type":"encrypted"},
            {"id":"duplicate", "key":"B", "target":"preview", "type":"encrypted"}
        ]});
        assert!(serde_json::from_value::<VercelEnvListResponse>(duplicate)
            .unwrap()
            .complete()
            .is_err());
    }

    #[tokio::test]
    async fn managed_patch_retries_exact_body_and_never_writes_classification() {
        let mut server = mockito::Server::new_async().await;
        let body = serde_json::json!({"value":"new", "target":["production"]});
        let limited = server
            .mock("PATCH", "/v9/projects/p/env/e1")
            .match_body(mockito::Matcher::Json(body.clone()))
            .with_status(429)
            .expect(1)
            .create_async()
            .await;
        let success = server
            .mock("PATCH", "/v9/projects/p/env/e1")
            .match_body(mockito::Matcher::Json(body))
            .with_status(200)
            .expect(1)
            .create_async()
            .await;
        let client = VercelClient::new("t".into(), None).with_base_url(server.url());
        client
            .update_env_var("p", "e1", Some("new"), Some(&["production".into()]))
            .await
            .unwrap();
        limited.assert_async().await;
        success.assert_async().await;
    }

    #[tokio::test]
    async fn target_only_patch_omits_value_and_empty_updates_never_send() {
        let mut server = mockito::Server::new_async().await;
        let patch = server
            .mock("PATCH", "/v9/projects/p/env/e1")
            .match_body(mockito::Matcher::Json(
                serde_json::json!({"target":["production"]}),
            ))
            .with_status(200)
            .expect(1)
            .create_async()
            .await;
        let client = VercelClient::new("t".into(), None).with_base_url(server.url());
        assert!(client.update_env_var("p", "e1", None, None).await.is_err());
        assert!(!patch.matched_async().await);
        client
            .update_env_var("p", "e1", None, Some(&["production".into()]))
            .await
            .unwrap();
        patch.assert_async().await;
    }

    #[tokio::test]
    async fn shared_inventory_rejects_linked_keys_hidden_pages_and_permission_errors() {
        for (status, body) in [
            (
                200,
                r#"{"data":[{"key":"KEY"}],"pagination":{"next":null}}"#,
            ),
            (200, r#"{"data":[],"pagination":{"next":123}}"#),
            (403, "{}"),
            (500, "{}"),
        ] {
            let mut server = mockito::Server::new_async().await;
            let mock = server
                .mock("GET", "/v1/env?projectId=p&teamId=team")
                .with_status(status)
                .with_body(body)
                .expect(1)
                .create_async()
                .await;
            let client =
                VercelClient::new("t".into(), Some("team".into())).with_base_url(server.url());
            assert!(client.ensure_no_shared_keys("p", &["KEY"]).await.is_err());
            mock.assert_async().await;
        }
    }

    #[tokio::test]
    async fn successful_patch_requires_metadata_verification() {
        let mut server = mockito::Server::new_async().await;
        let before = vec![row(serde_json::json!({"target":["production", "preview"]}))];
        let mock = server
            .mock("GET", "/v10/projects/p/env")
            .with_status(200)
            .with_body(serde_json::json!({"envs":before}).to_string())
            .create_async()
            .await;
        let client = VercelClient::new("t".into(), None).with_base_url(server.url());
        assert!(client
            .verify_update("p", &before, &before[0], Some(&["production".into()]))
            .await
            .is_err());
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn list_env_vars_happy_path() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/v10/projects/prj_test/env")
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
            .mock("GET", "/v10/projects/prj_test/env?teamId=team_x")
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
            .mock("GET", "/v10/projects/p/env")
            .with_status(429)
            .with_body("{}")
            .expect(2)
            .create_async()
            .await;
        let m200 = server
            .mock("GET", "/v10/projects/p/env")
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
            .mock("GET", "/v10/projects/p/env")
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
            .mock("POST", "/v10/projects/p/env")
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
                EnvVarType::Encrypted,
                None,
            )
            .await
            .unwrap();

        mock.assert_async().await;
    }

    #[test]
    fn historical_secret_intent_is_not_current_protection_evidence() {
        for metadata in [
            serde_json::json!({"type":"secret"}),
            serde_json::json!({"type":"secret", "visibility":"config"}),
        ] {
            let historical = row(metadata);
            assert!(historical.requires_sensitive_create());
            assert!(!historical.is_sensitive());
        }
        assert!(row(serde_json::json!({"type":"secret", "visibility":"secret"})).is_sensitive());
        assert!(row(serde_json::json!({"type":"sensitive"})).is_sensitive());
    }

    #[tokio::test]
    async fn create_verification_enforces_requested_protection_floor() {
        for (requested, actual_type, visibility, valid) in [
            (EnvVarType::Encrypted, "plain", Some("config"), false),
            (EnvVarType::Encrypted, "plain", Some("secret"), false),
            (EnvVarType::Encrypted, "encrypted", Some("config"), true),
            (EnvVarType::Encrypted, "sensitive", Some("secret"), true),
            (EnvVarType::Encrypted, "secret", None, false),
            (EnvVarType::Encrypted, "secret", Some("config"), false),
            (EnvVarType::Encrypted, "secret", Some("secret"), true),
            (EnvVarType::Sensitive, "encrypted", Some("config"), false),
            (EnvVarType::Sensitive, "encrypted", Some("secret"), true),
            (EnvVarType::Sensitive, "sensitive", None, true),
            (EnvVarType::Sensitive, "sensitive", Some("secret"), true),
            (EnvVarType::Sensitive, "secret", None, false),
            (EnvVarType::Sensitive, "secret", Some("config"), false),
            (EnvVarType::Sensitive, "secret", Some("secret"), true),
        ] {
            let mut server = mockito::Server::new_async().await;
            let mut actual = serde_json::json!({"id":"created", "key":"KEY", "type":actual_type, "target":["production"]});
            if let Some(visibility) = visibility {
                actual["visibility"] = visibility.into();
            }
            let list = server
                .mock("GET", "/v10/projects/p/env")
                .with_status(200)
                .with_body(serde_json::json!({"envs":[actual]}).to_string())
                .expect(1)
                .create_async()
                .await;
            let client = VercelClient::new("t".into(), None).with_base_url(server.url());
            let result = client
                .verify_create("p", &[], "KEY", &["production".into()], None, requested)
                .await;
            assert_eq!(
                result.is_ok(),
                valid,
                "{requested:?}/{actual_type}/{visibility:?}: {result:?}"
            );
            if let Ok(row) = result {
                assert_eq!(row.id.as_deref(), Some("created"));
            }
            list.assert_async().await;
        }
    }

    #[tokio::test]
    async fn create_env_var_posts_sensitive_type_when_requested() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/v10/projects/p/env")
            .match_body(mockito::Matcher::PartialJson(serde_json::json!({
                "key": "STRIPE_SECRET_KEY",
                "type": "sensitive",
            })))
            .with_status(201)
            .with_body("{}")
            .create_async()
            .await;

        let client = VercelClient::new("t".into(), None).with_base_url(server.url());
        client
            .create_env_var(
                "p",
                "STRIPE_SECRET_KEY",
                "sk_live_x",
                &["production".to_string()],
                EnvVarType::Sensitive,
                None,
            )
            .await
            .unwrap();

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn create_env_var_rejected_type_fails_loudly_naming_the_type() {
        // If the API refuses the requested type there must be no silent
        // fallback to a downgraded type — the error surfaces and names it.
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/v10/projects/p/env")
            .with_status(400)
            .with_body(r#"{"error":{"message":"type not allowed"}}"#)
            .expect(1)
            .create_async()
            .await;

        let client = VercelClient::new("t".into(), None).with_base_url(server.url());
        let err = client
            .create_env_var(
                "p",
                "STRIPE_SECRET_KEY",
                "sk_live_x",
                &["production".to_string()],
                EnvVarType::Sensitive,
                None,
            )
            .await
            .expect_err("400 must surface");
        let msg = format!("{err}");
        assert!(msg.contains("type=sensitive"), "got: {msg}");
        assert!(msg.contains("400"), "got: {msg}");

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn create_env_var_posts_git_branch_when_scoped_to_preview() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/v10/projects/p/env")
            .match_body(mockito::Matcher::PartialJson(serde_json::json!({
                "key": "STAGING_SECRET",
                "target": ["preview"],
                "gitBranch": "staging",
            })))
            .with_status(201)
            .with_body("{}")
            .create_async()
            .await;

        let client = VercelClient::new("t".into(), None).with_base_url(server.url());
        client
            .create_env_var(
                "p",
                "STAGING_SECRET",
                "value",
                &["preview".to_string()],
                EnvVarType::Encrypted,
                Some("staging"),
            )
            .await
            .unwrap();

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn create_env_var_omits_git_branch_when_none() {
        // Exact-body match (no partial matcher): asserts there is no
        // "gitBranch" key at all when git_branch is None, not merely
        // that the named fields are present.
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/v10/projects/p/env")
            .match_body(mockito::Matcher::Json(serde_json::json!({
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
                EnvVarType::Encrypted,
                None,
            )
            .await
            .unwrap();

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn create_env_var_rejects_git_branch_without_preview_target() {
        let client = VercelClient::new("t".into(), None);
        let err = client
            .create_env_var(
                "p",
                "STAGING_SECRET",
                "value",
                &["production".to_string()],
                EnvVarType::Encrypted,
                Some("staging"),
            )
            .await
            .expect_err(
                "gitBranch without a preview target must be rejected before the request is sent",
            );
        let msg = format!("{err}");
        assert!(msg.contains("staging"), "got: {msg}");
        assert!(msg.contains("preview"), "got: {msg}");
    }

    #[tokio::test]
    async fn update_env_var_patches_by_id_with_value_only() {
        // Body must contain ONLY "value" — target + type are deliberately
        // omitted so existing target list and Sensitive flag are preserved.
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("PATCH", "/v9/projects/p/env/env_abc")
            .match_body(mockito::Matcher::Json(serde_json::json!({
                "value": "v2",
            })))
            .with_status(200)
            .with_body("{}")
            .create_async()
            .await;

        let client = VercelClient::new("t".into(), None).with_base_url(server.url());
        client
            .update_env_var("p", "env_abc", Some("v2"), None)
            .await
            .unwrap();

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn list_env_vars_propagates_non_429_errors() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/v10/projects/p/env")
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

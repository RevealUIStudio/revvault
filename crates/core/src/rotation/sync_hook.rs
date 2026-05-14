//! Post-rotation sync hook.
//!
//! After a rotation provider returns a new secret value and the
//! executor writes it to the vault, this module pushes the same
//! value to any external secret store named under
//! `[providers.<name>.sync.*]` in `rotation.toml`. Today the only
//! supported target is Vercel; the design leaves room for more.
//!
//! # Failure semantics
//!
//! `apply_sync_after_rotation` is **infallible at the function
//! level** — it captures every per-env-var outcome as a
//! [`SyncLogEntry`] row and returns the whole vector. The executor
//! folds the rows into the rotation log and surfaces partial-success
//! warnings to stderr; the vault stays on the new value regardless
//! (vault is the source of truth, Vercel is downstream). Recovery
//! after a partial failure is documented at the message site:
//! `revvault sync vercel --apply --manifest <path>`.
//!
//! # Shape validation
//!
//! Before sending a value to Vercel, `push_to_vercel` validates it against
//! the universal structural checks (empty / null-literal / Vercel-envelope).
//! A failing check logs a `"drop-shape"` entry and skips the API call rather
//! than propagating a bad value. This catches misbehaving rotation providers
//! (e.g., a Neon API failure that returns an empty body).

use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};

use crate::store::PassageStore;
use crate::sync::shape::{self, Shape, ShapeViolation};
use crate::sync::vercel::VercelClient;

/// Per-provider sync block. Today only Vercel is supported; this
/// shape leaves room for future targets (`github`, `cloudflare`,
/// `dotenv`) without breaking config compat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncConfig {
    #[serde(default)]
    pub vercel: Option<VercelSyncRef>,
}

/// Reference to a Vercel project + the env vars to push to it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VercelSyncRef {
    /// Vault path holding the Vercel API token.
    pub api_token_path: String,
    /// Vercel project id (e.g. `prj_abc...`).
    pub project_id: String,
    /// Optional team id for team-scoped projects.
    #[serde(default)]
    pub team_id: Option<String>,
    /// Env vars to push the new value to. Each entry may target
    /// multiple Vercel environments (production / preview /
    /// development) in one API call.
    pub env_vars: Vec<VercelEnvVarRef>,
}

/// One env-var-name-and-targets pair on a Vercel project.
///
/// `Ref` suffix distinguishes this rotation-chain config struct from
/// the cli sync tool's `VercelEnvVar` API DTO over in
/// `crates/core/src/sync/vercel.rs`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VercelEnvVarRef {
    /// Vercel env-var name (e.g. `POSTGRES_URL`).
    pub name: String,
    /// Targets to apply the value to. Default `["production"]`.
    #[serde(default = "default_targets")]
    pub targets: Vec<String>,
}

fn default_targets() -> Vec<String> {
    vec!["production".to_string()]
}

/// One row in the per-rotation sync audit. The executor folds the
/// vector returned by [`apply_sync_after_rotation`] into the rotation
/// log entry; the JSONL log captures `target`, `status`,
/// per-env-var and per-vercel-target detail, the value shape category,
/// and an optional error reason.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncLogEntry {
    /// Sync target identifier (currently always `"vercel"`).
    pub target: String,
    /// One of `"success"`, `"failed"`, `"skipped"`, `"drop-shape"`.
    pub status: String,
    /// Env-var name on the remote target.
    pub env_var: String,
    /// Vercel target environment (e.g. `"production"`,
    /// `"preview"`).
    pub vercel_target: String,
    /// Shape category of the value (e.g. `"postgres-url"`, `"stripe-key"`,
    /// `"vercel-envelope"`, `"empty"`). Never includes the value itself.
    pub value_shape: String,
    /// Failure reason when `status == "failed"` or `"drop-shape"`. Never
    /// includes secret values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl SyncLogEntry {
    fn success(env_var: &str, vercel_target: &str, value_shape: &str) -> Self {
        Self {
            target: "vercel".into(),
            status: "success".into(),
            env_var: env_var.to_string(),
            vercel_target: vercel_target.to_string(),
            value_shape: value_shape.to_string(),
            error: None,
        }
    }

    fn failed(
        env_var: &str,
        vercel_target: &str,
        value_shape: &str,
        error: impl Into<String>,
    ) -> Self {
        Self {
            target: "vercel".into(),
            status: "failed".into(),
            env_var: env_var.to_string(),
            vercel_target: vercel_target.to_string(),
            value_shape: value_shape.to_string(),
            error: Some(error.into()),
        }
    }

    fn drop_shape(
        env_var: &str,
        vercel_target: &str,
        value_shape: &str,
        violation: &ShapeViolation,
    ) -> Self {
        Self {
            target: "vercel".into(),
            status: "drop-shape".into(),
            env_var: env_var.to_string(),
            vercel_target: vercel_target.to_string(),
            value_shape: value_shape.to_string(),
            error: Some(violation.to_string()),
        }
    }
}

/// Push the new secret value to every target named under
/// `sync_config`. Returns one [`SyncLogEntry`] per `(env_var,
/// vercel_target)` pair so the rotation log captures fan-out.
///
/// # Errors
///
/// None — every failure is captured as a log entry. Caller decides
/// whether partial success counts as overall success (currently it
/// does: vault is the source of truth and Vercel is best-effort).
pub async fn apply_sync_after_rotation(
    store: &PassageStore,
    sync_config: &SyncConfig,
    new_value: &SecretString,
) -> Vec<SyncLogEntry> {
    apply_sync_after_rotation_inner(store, sync_config, new_value, None).await
}

/// Internal entry point that allows tests to override the Vercel
/// API base URL. Production code calls
/// [`apply_sync_after_rotation`] which omits the override.
pub(crate) async fn apply_sync_after_rotation_inner(
    store: &PassageStore,
    sync_config: &SyncConfig,
    new_value: &SecretString,
    base_url_override: Option<&str>,
) -> Vec<SyncLogEntry> {
    let mut log: Vec<SyncLogEntry> = Vec::new();

    if let Some(vercel_ref) = &sync_config.vercel {
        push_to_vercel(store, vercel_ref, new_value, base_url_override, &mut log).await;
    }

    log
}

async fn push_to_vercel(
    store: &PassageStore,
    vercel_ref: &VercelSyncRef,
    new_value: &SecretString,
    base_url_override: Option<&str>,
    log: &mut Vec<SyncLogEntry>,
) {
    let value_str = new_value.expose_secret();
    let value_shape = shape::classify(value_str);

    // Universal shape guard: refuse to propagate empty / null / envelope
    // values to Vercel regardless of declared shape. A misbehaving rotation
    // provider (e.g., Neon returning an empty HTTP body) hits this guard.
    if let Err(violation) = shape::check(value_str, Shape::Any) {
        for ev in &vercel_ref.env_vars {
            for t in &ev.targets {
                log.push(SyncLogEntry::drop_shape(
                    &ev.name,
                    t,
                    &value_shape,
                    &violation,
                ));
            }
        }
        return;
    }

    // Fetch the Vercel API token from the vault. If we can't read
    // it, the rotation succeeded but no sync can run — record one
    // failed entry per env-var × target.
    let token = match store.get(&vercel_ref.api_token_path) {
        Ok(t) => t.expose_secret().to_string(),
        Err(e) => {
            for ev in &vercel_ref.env_vars {
                for t in &ev.targets {
                    log.push(SyncLogEntry::failed(
                        &ev.name,
                        t,
                        &value_shape,
                        format!(
                            "cannot read Vercel API token at '{}': {}",
                            vercel_ref.api_token_path, e
                        ),
                    ));
                }
            }
            return;
        }
    };

    let mut client = VercelClient::new(token, vercel_ref.team_id.clone());
    if let Some(base) = base_url_override {
        client = client.with_base_url(base);
    }

    // List existing env vars once per project — used to dispatch
    // create vs update per env-var.
    let existing = match client.list_env_vars(&vercel_ref.project_id).await {
        Ok(v) => v,
        Err(e) => {
            for ev in &vercel_ref.env_vars {
                for t in &ev.targets {
                    log.push(SyncLogEntry::failed(
                        &ev.name,
                        t,
                        &value_shape,
                        format!("Vercel list_env_vars failed: {e}"),
                    ));
                }
            }
            return;
        }
    };

    for ev in &vercel_ref.env_vars {
        // Find an existing row for this env-var name. Vercel allows
        // multiple rows per name (different `target` arrays); for
        // sync we update the first match and create otherwise.
        let existing_id = existing
            .iter()
            .find(|x| x.key == ev.name)
            .and_then(|x| x.id.clone());

        let result = match existing_id {
            Some(id) => {
                client
                    .update_env_var(&vercel_ref.project_id, &id, value_str, &ev.targets)
                    .await
            }
            None => {
                client
                    .create_env_var(&vercel_ref.project_id, &ev.name, value_str, &ev.targets)
                    .await
            }
        };

        match result {
            Ok(()) => {
                for t in &ev.targets {
                    log.push(SyncLogEntry::success(&ev.name, t, &value_shape));
                }
            }
            Err(e) => {
                let reason = format!("{e}");
                for t in &ev.targets {
                    log.push(SyncLogEntry::failed(
                        &ev.name,
                        t,
                        &value_shape,
                        reason.clone(),
                    ));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vercel_env_var_ref_default_targets_is_production() {
        let toml_src = r#"name = "POSTGRES_URL""#;
        let ev: VercelEnvVarRef = toml::from_str(toml_src).unwrap();
        assert_eq!(ev.name, "POSTGRES_URL");
        assert_eq!(ev.targets, vec!["production".to_string()]);
    }

    #[test]
    fn vercel_env_var_ref_explicit_targets() {
        let toml_src = r#"
            name = "POSTGRES_URL"
            targets = ["production", "preview"]
        "#;
        let ev: VercelEnvVarRef = toml::from_str(toml_src).unwrap();
        assert_eq!(ev.targets, vec!["production".to_string(), "preview".into()]);
    }

    #[test]
    fn sync_config_round_trip_via_toml() {
        let toml_src = r#"
            [vercel]
            api_token_path = "credentials/vercel/api-token"
            project_id     = "prj_test"
            team_id        = "team_x"

            [[vercel.env_vars]]
            name = "POSTGRES_URL"

            [[vercel.env_vars]]
            name    = "POSTGRES_PRISMA_URL"
            targets = ["production", "preview"]
        "#;
        let cfg: SyncConfig = toml::from_str(toml_src).unwrap();
        let v = cfg.vercel.expect("vercel block parsed");
        assert_eq!(v.project_id, "prj_test");
        assert_eq!(v.team_id.as_deref(), Some("team_x"));
        assert_eq!(v.env_vars.len(), 2);
        assert_eq!(v.env_vars[0].targets, vec!["production".to_string()]);
        assert_eq!(
            v.env_vars[1].targets,
            vec!["production".to_string(), "preview".into()]
        );
    }

    #[test]
    fn sync_log_entry_serializes_with_value_shape() {
        let e = SyncLogEntry::success("POSTGRES_URL", "production", "postgres-url");
        let json = serde_json::to_string(&e).unwrap();
        assert!(!json.contains("error"));
        assert!(json.contains(r#""status":"success""#));
        assert!(json.contains(r#""env_var":"POSTGRES_URL""#));
        assert!(json.contains(r#""value_shape":"postgres-url""#));
    }

    #[test]
    fn sync_log_entry_includes_error_when_failed() {
        let e = SyncLogEntry::failed("POSTGRES_URL", "production", "unknown", "boom");
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains(r#""status":"failed""#));
        assert!(json.contains(r#""error":"boom""#));
        assert!(json.contains(r#""value_shape":"unknown""#));
    }

    #[test]
    fn sync_log_entry_drop_shape_records_violation() {
        let v = ShapeViolation::Empty;
        let e = SyncLogEntry::drop_shape("POSTGRES_URL", "production", "empty", &v);
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains(r#""status":"drop-shape""#));
        assert!(json.contains(r#""value_shape":"empty""#));
    }

    /// Create a temp store with a generated age identity. Mirrors the
    /// pattern from `store.rs`'s test module.
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

        let config = crate::config::Config {
            store_dir,
            identity_file: id_file,
            recipients_file: recip_file,
            editor: None,
            tmpdir: None,
        };
        let store = PassageStore::open(config).unwrap();
        (dir, store)
    }

    #[tokio::test]
    async fn apply_sync_pushes_two_env_vars_one_existing_one_new() {
        let (_dir, store) = setup_temp_store();
        store
            .upsert("credentials/vercel/api-token", b"token-x")
            .unwrap();

        let mut server = mockito::Server::new_async().await;
        let m_list = server
            .mock("GET", "/projects/prj/env")
            .with_status(200)
            .with_body(
                r#"{"envs":[{"id":"e1","key":"POSTGRES_URL","target":["production"],"type":"encrypted"}]}"#,
            )
            .expect(1)
            .create_async()
            .await;
        let m_update = server
            .mock("PATCH", "/projects/prj/env/e1")
            .with_status(200)
            .with_body("{}")
            .expect(1)
            .create_async()
            .await;
        let m_create = server
            .mock("POST", "/projects/prj/env")
            .with_status(201)
            .with_body("{}")
            .expect(1)
            .create_async()
            .await;

        let sync = SyncConfig {
            vercel: Some(VercelSyncRef {
                api_token_path: "credentials/vercel/api-token".into(),
                project_id: "prj".into(),
                team_id: None,
                env_vars: vec![
                    VercelEnvVarRef {
                        name: "POSTGRES_URL".into(),
                        targets: vec!["production".into(), "preview".into()],
                    },
                    VercelEnvVarRef {
                        name: "POSTGRES_NEW".into(),
                        targets: vec!["production".into()],
                    },
                ],
            }),
        };

        let log = apply_sync_after_rotation_inner(
            &store,
            &sync,
            &SecretString::from("postgres://new"),
            Some(&server.url()),
        )
        .await;

        assert_eq!(log.len(), 3);
        for row in &log {
            assert_eq!(row.target, "vercel");
            assert_eq!(row.status, "success", "row failed: {row:?}");
            assert_eq!(row.value_shape, "postgres-url");
        }

        m_list.assert_async().await;
        m_update.assert_async().await;
        m_create.assert_async().await;
    }

    #[tokio::test]
    async fn apply_sync_records_failure_when_token_missing() {
        let (_dir, store) = setup_temp_store();

        let sync = SyncConfig {
            vercel: Some(VercelSyncRef {
                api_token_path: "credentials/vercel/api-token".into(),
                project_id: "prj".into(),
                team_id: None,
                env_vars: vec![VercelEnvVarRef {
                    name: "POSTGRES_URL".into(),
                    targets: vec!["production".into()],
                }],
            }),
        };

        let log = apply_sync_after_rotation_inner(
            &store,
            &sync,
            &SecretString::from("postgres://new"),
            None,
        )
        .await;

        assert_eq!(log.len(), 1);
        assert_eq!(log[0].status, "failed");
        assert!(log[0].error.as_deref().unwrap_or("").contains("api-token"));
    }

    /// Proves the bug class: a rotation provider returning an empty string
    /// must NEVER be pushed to Vercel.
    #[tokio::test]
    async fn sync_hook_refuses_empty_rotation_output() {
        let (_dir, store) = setup_temp_store();
        store
            .upsert("credentials/vercel/api-token", b"token-x")
            .unwrap();

        let sync = SyncConfig {
            vercel: Some(VercelSyncRef {
                api_token_path: "credentials/vercel/api-token".into(),
                project_id: "prj".into(),
                team_id: None,
                env_vars: vec![VercelEnvVarRef {
                    name: "POSTGRES_URL".into(),
                    targets: vec!["production".into()],
                }],
            }),
        };

        let log =
            apply_sync_after_rotation_inner(&store, &sync, &SecretString::from(""), None).await;

        assert_eq!(log.len(), 1);
        assert_eq!(log[0].status, "drop-shape");
        assert_eq!(log[0].value_shape, "empty");
    }

    /// Proves the 2026-05-09 incident class: a Vercel v2 envelope must never
    /// be pushed back to Vercel as a value.
    #[tokio::test]
    async fn sync_hook_refuses_envelope_rotation_output() {
        let (_dir, store) = setup_temp_store();
        store
            .upsert("credentials/vercel/api-token", b"token-x")
            .unwrap();

        let sync = SyncConfig {
            vercel: Some(VercelSyncRef {
                api_token_path: "credentials/vercel/api-token".into(),
                project_id: "prj".into(),
                team_id: None,
                env_vars: vec![VercelEnvVarRef {
                    name: "POSTGRES_URL".into(),
                    targets: vec!["production".into()],
                }],
            }),
        };

        let envelope = SecretString::from("eyJ2IjoidjIiLCJlcGsiOnsieCI6InRlc3QifX0=");
        let log = apply_sync_after_rotation_inner(&store, &sync, &envelope, None).await;

        assert_eq!(log.len(), 1);
        assert_eq!(log[0].status, "drop-shape");
        assert_eq!(log[0].value_shape, "vercel-envelope");
    }
}

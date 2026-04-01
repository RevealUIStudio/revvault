use std::collections::HashMap;

use age::x25519;
use mockito::Server;
use secrecy::{ExposeSecret, SecretString};
use tempfile::TempDir;

use revvault_core::config::Config;
use revvault_core::rotation::executor;
use revvault_core::rotation::providers::GenericHttpProvider;
use revvault_core::rotation::RotationProvider;
use revvault_core::store::PassageStore;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn setup_store() -> (TempDir, PassageStore) {
    let dir = tempfile::tempdir().unwrap();
    let store_dir = dir.path().join("store");
    std::fs::create_dir_all(&store_dir).unwrap();

    let id = x25519::Identity::generate();
    let recipient = id.to_public();

    let id_file = dir.path().join("keys.txt");
    std::fs::write(
        &id_file,
        format!(
            "# test identity\n{}\n",
            id.to_string().expose_secret()
        ),
    )
    .unwrap();

    let recip_file = store_dir.join(".age-recipients");
    std::fs::write(&recip_file, format!("{}\n", recipient)).unwrap();

    let config = Config {
        store_dir,
        identity_file: id_file,
        recipients_file: recip_file,
        editor: None,
        tmpdir: None,
    };

    let store = PassageStore::open(config).unwrap();
    (dir, store)
}

fn settings(overrides: &[(&str, &str)]) -> HashMap<String, String> {
    overrides
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

// ---------------------------------------------------------------------------
// Provider config validation
// ---------------------------------------------------------------------------

#[test]
fn from_config_rejects_missing_create_url() {
    let s = settings(&[("response_field", "key")]);
    let err = GenericHttpProvider::from_config("test".into(), SecretString::from("old".to_string()), None, &s);
    assert!(err.is_err());
    assert!(err.unwrap_err().to_string().contains("create_url"));
}

#[test]
fn from_config_rejects_missing_response_field() {
    let s = settings(&[("create_url", "https://example.com/keys")]);
    let err = GenericHttpProvider::from_config("test".into(), SecretString::from("old".to_string()), None, &s);
    assert!(err.is_err());
    assert!(err.unwrap_err().to_string().contains("response_field"));
}

#[test]
fn from_config_accepts_minimal_settings() {
    let s = settings(&[
        ("create_url", "https://example.com/keys"),
        ("response_field", "key"),
    ]);
    assert!(GenericHttpProvider::from_config("test".into(), SecretString::from("old".to_string()), None, &s).is_ok());
}

// ---------------------------------------------------------------------------
// Preflight URL validation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn preflight_rejects_invalid_create_url() {
    let s = settings(&[
        ("create_url", "not-a-url"),
        ("response_field", "key"),
    ]);
    let p = GenericHttpProvider::from_config("test".into(), SecretString::from("old".to_string()), None, &s).unwrap();
    assert!(p.preflight().await.is_err());
}

#[tokio::test]
async fn preflight_accepts_valid_urls() {
    let s = settings(&[
        ("create_url", "https://api.example.com/keys"),
        ("response_field", "key"),
        ("revoke_url", "https://api.example.com/keys/{old_key_id}"),
    ]);
    let p = GenericHttpProvider::from_config("test".into(), SecretString::from("old".to_string()), None, &s).unwrap();
    assert!(p.preflight().await.is_ok());
}

// ---------------------------------------------------------------------------
// Dry-run output
// ---------------------------------------------------------------------------

#[tokio::test]
async fn dry_run_mentions_create_url_and_response_field() {
    let s = settings(&[
        ("create_url", "https://api.example.com/keys"),
        ("response_field", "data.token"),
    ]);
    let p = GenericHttpProvider::from_config("test".into(), SecretString::from("old".to_string()), None, &s).unwrap();
    let plan = p.dry_run().await.unwrap();
    assert!(plan.contains("https://api.example.com/keys"));
    assert!(plan.contains("data.token"));
    assert!(plan.contains("No revoke_url configured"));
}

#[tokio::test]
async fn dry_run_shows_revoke_url_when_configured() {
    let s = settings(&[
        ("create_url", "https://api.example.com/keys"),
        ("response_field", "key"),
        ("revoke_url", "https://api.example.com/keys/{old_key_id}"),
    ]);
    let p = GenericHttpProvider::from_config("test".into(), SecretString::from("old".to_string()), None, &s).unwrap();
    let plan = p.dry_run().await.unwrap();
    assert!(plan.contains("https://api.example.com/keys/{old_key_id}"));
}

// ---------------------------------------------------------------------------
// HTTP rotation — mock server tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rotate_creates_key_and_returns_new_value() {
    let mut server = Server::new_async().await;

    let _mock = server
        .mock("POST", "/keys")
        .with_status(201)
        .with_header("content-type", "application/json")
        .with_body(r#"{"key":"new-secret-value"}"#)
        .create_async()
        .await;

    let s = settings(&[
        ("create_url", &format!("{}/keys", server.url())),
        ("response_field", "key"),
    ]);
    let p = GenericHttpProvider::from_config("test".into(), SecretString::from("old-key".to_string()), None, &s).unwrap();
    let outcome = p.rotate().await.unwrap();

    assert_eq!(outcome.new_value.expose_secret(), "new-secret-value");
    assert!(outcome.new_key_id.is_none());
}

#[tokio::test]
async fn rotate_extracts_nested_response_field() {
    let mut server = Server::new_async().await;

    let _mock = server
        .mock("POST", "/keys")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"data":{"token":"nested-token","id":"tok_123"}}"#)
        .create_async()
        .await;

    let s = settings(&[
        ("create_url", &format!("{}/keys", server.url())),
        ("response_field", "data.token"),
        ("id_field", "data.id"),
    ]);
    let p = GenericHttpProvider::from_config("test".into(), SecretString::from("old-key".to_string()), None, &s).unwrap();
    let outcome = p.rotate().await.unwrap();

    assert_eq!(outcome.new_value.expose_secret(), "nested-token");
    assert_eq!(outcome.new_key_id.as_deref(), Some("tok_123"));
}

#[tokio::test]
async fn rotate_revokes_old_key_by_value() {
    let mut server = Server::new_async().await;

    let _create = server
        .mock("POST", "/keys")
        .with_status(201)
        .with_header("content-type", "application/json")
        .with_body(r#"{"key":"brand-new-key"}"#)
        .create_async()
        .await;

    let _revoke = server
        .mock("DELETE", "/keys/old-key-value")
        .with_status(204)
        .create_async()
        .await;

    let s = settings(&[
        ("create_url", &format!("{}/keys", server.url())),
        ("response_field", "key"),
        (
            "revoke_url",
            &format!("{}/keys/{{old_key}}", server.url()),
        ),
    ]);
    let p =
        GenericHttpProvider::from_config("test".into(), SecretString::from("old-key-value".to_string()), None, &s).unwrap();
    let outcome = p.rotate().await.unwrap();

    assert_eq!(outcome.new_value.expose_secret(), "brand-new-key");
    _revoke.assert_async().await;
}

#[tokio::test]
async fn rotate_revokes_old_key_by_id() {
    let mut server = Server::new_async().await;

    let _create = server
        .mock("POST", "/keys")
        .with_status(201)
        .with_header("content-type", "application/json")
        .with_body(r#"{"key":"new-key","id":"new-id-456"}"#)
        .create_async()
        .await;

    let _revoke = server
        .mock("DELETE", "/keys/old-id-123")
        .with_status(204)
        .create_async()
        .await;

    let s = settings(&[
        ("create_url", &format!("{}/keys", server.url())),
        ("response_field", "key"),
        ("id_field", "id"),
        (
            "revoke_url",
            &format!("{}/keys/{{old_key_id}}", server.url()),
        ),
    ]);
    let p = GenericHttpProvider::from_config(
        "test".into(),
        SecretString::from("old-key-value".to_string()),
        Some("old-id-123".into()),
        &s,
    )
    .unwrap();
    let outcome = p.rotate().await.unwrap();

    assert_eq!(outcome.new_value.expose_secret(), "new-key");
    assert_eq!(outcome.new_key_id.as_deref(), Some("new-id-456"));
    _revoke.assert_async().await;
}

#[tokio::test]
async fn rotate_fails_on_non_2xx_create() {
    let mut server = Server::new_async().await;

    let _mock = server
        .mock("POST", "/keys")
        .with_status(401)
        .with_body("unauthorized")
        .create_async()
        .await;

    let s = settings(&[
        ("create_url", &format!("{}/keys", server.url())),
        ("response_field", "key"),
    ]);
    let p = GenericHttpProvider::from_config("test".into(), SecretString::from("bad-key".to_string()), None, &s).unwrap();
    let err = p.rotate().await.unwrap_err();
    assert!(err.to_string().contains("401"));
}

#[tokio::test]
async fn rotate_fails_when_response_field_missing() {
    let mut server = Server::new_async().await;

    let _mock = server
        .mock("POST", "/keys")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"different_field":"value"}"#)
        .create_async()
        .await;

    let s = settings(&[
        ("create_url", &format!("{}/keys", server.url())),
        ("response_field", "key"),
    ]);
    let p = GenericHttpProvider::from_config("test".into(), SecretString::from("old".to_string()), None, &s).unwrap();
    let err = p.rotate().await.unwrap_err();
    assert!(err.to_string().contains("'key' not found"));
}

// ---------------------------------------------------------------------------
// Executor integration — vault + HTTP
// ---------------------------------------------------------------------------

#[tokio::test]
async fn executor_writes_new_key_to_vault_and_logs() {
    let mut server = Server::new_async().await;

    let _mock = server
        .mock("POST", "/rotate")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"token":"rotated-token-value","tokenId":"tid-999"}"#)
        .create_async()
        .await;

    let (_dir, store) = setup_store();

    // Seed the current key
    store
        .set("credentials/svc/api-key", b"initial-key")
        .unwrap();

    let provider_config = revvault_core::rotation::config::ProviderConfig {
        secret_path: "credentials/svc/api-key".into(),
        settings: settings(&[
            ("create_url", &format!("{}/rotate", server.url())),
            ("response_field", "token"),
            ("id_field", "tokenId"),
        ]),
    };

    executor::execute(&store, "svc", &provider_config)
        .await
        .unwrap();

    // New key written to vault
    let new_key = store.get("credentials/svc/api-key").unwrap();
    assert_eq!(new_key.expose_secret(), "rotated-token-value");

    // Key ID written for next rotation
    let stored_id = store.get("credentials/svc/api-key-id").unwrap();
    assert_eq!(stored_id.expose_secret(), "tid-999");

    // Log file created
    let log_path = store
        .store_dir()
        .join(".revvault/rotation-log.jsonl");
    assert!(log_path.exists());
    let log = std::fs::read_to_string(&log_path).unwrap();
    assert!(log.contains("\"provider\":\"svc\""));
    assert!(log.contains("\"status\":\"success\""));
    assert!(log.contains("tid-999"));
}

#[tokio::test]
async fn executor_uses_stored_key_id_for_revocation() {
    let mut server = Server::new_async().await;

    let _create = server
        .mock("POST", "/keys")
        .with_status(201)
        .with_header("content-type", "application/json")
        .with_body(r#"{"key":"next-key","id":"next-id"}"#)
        .create_async()
        .await;

    let _revoke = server
        .mock("DELETE", "/keys/prev-id-from-vault")
        .with_status(204)
        .create_async()
        .await;

    let (_dir, store) = setup_store();
    store.set("credentials/svc/token", b"current-token").unwrap();
    // Simulate a previous rotation having stored the key ID
    store
        .set("credentials/svc/token-id", b"prev-id-from-vault")
        .unwrap();

    let provider_config = revvault_core::rotation::config::ProviderConfig {
        secret_path: "credentials/svc/token".into(),
        settings: settings(&[
            ("create_url", &format!("{}/keys", server.url())),
            ("response_field", "key"),
            ("id_field", "id"),
            (
                "revoke_url",
                &format!("{}/keys/{{old_key_id}}", server.url()),
            ),
        ]),
    };

    executor::execute(&store, "svc", &provider_config)
        .await
        .unwrap();

    _revoke.assert_async().await;
    let new_key = store.get("credentials/svc/token").unwrap();
    assert_eq!(new_key.expose_secret(), "next-key");
}


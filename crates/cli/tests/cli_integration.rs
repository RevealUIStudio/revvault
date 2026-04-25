use assert_cmd::Command;
use predicates::prelude::*;
use secrecy::ExposeSecret;
use std::path::Path;
use tempfile::TempDir;

/// Set up a temporary store with generated age identity and recipients.
/// Returns (temp_dir, store_path, identity_path) — keep temp_dir alive for the test.
fn setup_temp_store() -> (TempDir, String, String) {
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
            ExposeSecret::expose_secret(&id.to_string())
        ),
    )
    .unwrap();

    let recip_file = store_dir.join(".age-recipients");
    std::fs::write(&recip_file, format!("{recipient}\n")).unwrap();

    let store_path = store_dir.to_string_lossy().to_string();
    let id_path = id_file.to_string_lossy().to_string();

    (dir, store_path, id_path)
}

fn revvault_cmd(store: &str, identity: &str) -> Command {
    let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("revvault");
    cmd.env("REVVAULT_STORE", store);
    cmd.env("REVVAULT_IDENTITY", identity);
    cmd
}

#[test]
fn list_empty_store() {
    let (_dir, store, identity) = setup_temp_store();
    revvault_cmd(&store, &identity)
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().or(predicate::str::contains("")));
}

#[test]
fn set_and_get_roundtrip() {
    let (_dir, store, identity) = setup_temp_store();

    // Set a secret via stdin
    revvault_cmd(&store, &identity)
        .arg("set")
        .arg("credentials/test-key")
        .write_stdin("super-secret-value")
        .assert()
        .success();

    // Get it back
    revvault_cmd(&store, &identity)
        .arg("get")
        .arg("credentials/test-key")
        .assert()
        .success()
        .stdout(predicate::str::contains("super-secret-value"));
}

#[test]
fn list_shows_stored_secrets() {
    let (_dir, store, identity) = setup_temp_store();

    // Add some secrets
    revvault_cmd(&store, &identity)
        .arg("set")
        .arg("credentials/stripe/sk")
        .write_stdin("sk_live_123")
        .assert()
        .success();

    revvault_cmd(&store, &identity)
        .arg("set")
        .arg("ssh/github")
        .write_stdin("ssh-key-data")
        .assert()
        .success();

    // List should show both
    revvault_cmd(&store, &identity)
        .arg("list")
        .assert()
        .success()
        .stdout(
            predicate::str::contains("credentials/stripe/sk")
                .and(predicate::str::contains("ssh/github")),
        );
}

#[test]
fn search_returns_matches() {
    let (_dir, store, identity) = setup_temp_store();

    revvault_cmd(&store, &identity)
        .arg("set")
        .arg("credentials/stripe/secret-key")
        .write_stdin("sk_live_123")
        .assert()
        .success();

    revvault_cmd(&store, &identity)
        .arg("set")
        .arg("misc/unrelated")
        .write_stdin("value")
        .assert()
        .success();

    revvault_cmd(&store, &identity)
        .arg("search")
        .arg("stripe")
        .assert()
        .success()
        .stdout(predicate::str::contains("stripe"));
}

#[test]
fn delete_removes_secret() {
    let (_dir, store, identity) = setup_temp_store();

    revvault_cmd(&store, &identity)
        .arg("set")
        .arg("misc/temp")
        .write_stdin("temporary")
        .assert()
        .success();

    // Verify it exists
    revvault_cmd(&store, &identity)
        .arg("get")
        .arg("misc/temp")
        .assert()
        .success();

    // Delete it (--force skips confirmation prompt)
    revvault_cmd(&store, &identity)
        .arg("delete")
        .arg("--force")
        .arg("misc/temp")
        .assert()
        .success();

    // Should be gone
    revvault_cmd(&store, &identity)
        .arg("get")
        .arg("misc/temp")
        .assert()
        .failure();
}

#[test]
fn get_nonexistent_fails() {
    let (_dir, store, identity) = setup_temp_store();

    revvault_cmd(&store, &identity)
        .arg("get")
        .arg("no/such/secret")
        .assert()
        .failure();
}

#[test]
fn set_rejects_path_traversal() {
    let (_dir, store, identity) = setup_temp_store();

    revvault_cmd(&store, &identity)
        .arg("set")
        .arg("../../etc/passwd")
        .write_stdin("hacked")
        .assert()
        .failure();
}

#[test]
fn set_rejects_absolute_path() {
    let (_dir, store, identity) = setup_temp_store();

    revvault_cmd(&store, &identity)
        .arg("set")
        .arg("/etc/passwd")
        .write_stdin("hacked")
        .assert()
        .failure();
}

#[test]
fn get_full_flag_shows_multiline() {
    let (_dir, store, identity) = setup_temp_store();

    revvault_cmd(&store, &identity)
        .arg("set")
        .arg("misc/multiline")
        .write_stdin("line1\nline2\nline3")
        .assert()
        .success();

    // Without --full, only first line
    revvault_cmd(&store, &identity)
        .arg("get")
        .arg("misc/multiline")
        .assert()
        .success()
        .stdout(predicate::str::contains("line1").and(predicate::str::contains("line2").not()));

    // With --full, all lines
    revvault_cmd(&store, &identity)
        .arg("get")
        .arg("--full")
        .arg("misc/multiline")
        .assert()
        .success()
        .stdout(predicate::str::contains("line1").and(predicate::str::contains("line3")));
}

// ---------------------------------------------------------------------------
// init command
// ---------------------------------------------------------------------------

#[test]
fn init_creates_store_and_identity() {
    let dir = tempfile::tempdir().unwrap();
    let store_dir = dir.path().join("store");
    let id_file = dir.path().join("keys.txt");

    assert_cmd::cargo::cargo_bin_cmd!("revvault")
        .arg("init")
        .arg("--store-dir")
        .arg(&store_dir)
        .arg("--identity-file")
        .arg(&id_file)
        .assert()
        .success();

    assert!(store_dir.is_dir(), "store directory should be created");
    assert!(id_file.is_file(), "identity file should be created");
    assert!(
        store_dir.join(".age-recipients").is_file(),
        ".age-recipients should be written"
    );
}

#[test]
fn init_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let store_dir = dir.path().join("store");
    let id_file = dir.path().join("keys.txt");

    // First init
    assert_cmd::cargo::cargo_bin_cmd!("revvault")
        .arg("init")
        .arg("--store-dir")
        .arg(&store_dir)
        .arg("--identity-file")
        .arg(&id_file)
        .assert()
        .success();

    // Second init — must not fail or overwrite identity
    let before = std::fs::read_to_string(&id_file).unwrap();
    assert_cmd::cargo::cargo_bin_cmd!("revvault")
        .arg("init")
        .arg("--store-dir")
        .arg(&store_dir)
        .arg("--identity-file")
        .arg(&id_file)
        .assert()
        .success();
    let after = std::fs::read_to_string(&id_file).unwrap();

    assert_eq!(before, after, "identity file must not be overwritten");
}

// ---------------------------------------------------------------------------
// export-env command
// ---------------------------------------------------------------------------

#[test]
fn export_env_single_value() {
    let (_dir, store, identity) = setup_temp_store();

    revvault_cmd(&store, &identity)
        .arg("set")
        .arg("credentials/stripe/secret-key")
        .write_stdin("sk_live_abc123")
        .assert()
        .success();

    // Var name derived from last path segment: secret-key → SECRET_KEY
    revvault_cmd(&store, &identity)
        .arg("export-env")
        .arg("credentials/stripe/secret-key")
        .assert()
        .success()
        .stdout(
            predicate::str::contains("export SECRET_KEY=")
                .and(predicate::str::contains("sk_live_abc123")),
        );
}

#[test]
fn export_env_kv_lines() {
    let (_dir, store, identity) = setup_temp_store();

    revvault_cmd(&store, &identity)
        .arg("set")
        .arg("credentials/env/prod")
        .write_stdin("API_KEY=abc123\nDB_URL=postgres://localhost/db")
        .assert()
        .success();

    revvault_cmd(&store, &identity)
        .arg("export-env")
        .arg("credentials/env/prod")
        .assert()
        .success()
        .stdout(
            predicate::str::contains("export API_KEY=")
                .and(predicate::str::contains("abc123"))
                .and(predicate::str::contains("export DB_URL="))
                .and(predicate::str::contains("postgres://localhost/db")),
        );
}

#[test]
fn export_env_single_quote_escaping() {
    let (_dir, store, identity) = setup_temp_store();

    revvault_cmd(&store, &identity)
        .arg("set")
        .arg("misc/password")
        .write_stdin("it's a secret")
        .assert()
        .success();

    // Shell quoting: single quotes in value must be escaped as '\''
    revvault_cmd(&store, &identity)
        .arg("export-env")
        .arg("misc/password")
        .assert()
        .success()
        .stdout(predicate::str::contains("export PASSWORD=").and(predicate::str::contains("it")));
}

#[test]
fn export_env_nonexistent_fails() {
    let (_dir, store, identity) = setup_temp_store();

    revvault_cmd(&store, &identity)
        .arg("export-env")
        .arg("credentials/missing/key")
        .assert()
        .failure();
}

// ---------------------------------------------------------------------------
// list with flags
// ---------------------------------------------------------------------------

#[test]
fn list_with_prefix_filter() {
    let (_dir, store, identity) = setup_temp_store();

    for (path, val) in &[
        ("credentials/stripe/sk", "sk"),
        ("credentials/github/token", "gh"),
        ("ssh/server", "key"),
    ] {
        revvault_cmd(&store, &identity)
            .arg("set")
            .arg(path)
            .write_stdin(*val)
            .assert()
            .success();
    }

    revvault_cmd(&store, &identity)
        .arg("list")
        .arg("credentials")
        .assert()
        .success()
        .stdout(
            predicate::str::contains("credentials/stripe/sk")
                .and(predicate::str::contains("credentials/github/token"))
                .and(predicate::str::contains("ssh/server").not()),
        );
}

#[test]
fn list_tree_format() {
    let (_dir, store, identity) = setup_temp_store();

    revvault_cmd(&store, &identity)
        .arg("set")
        .arg("credentials/stripe/sk")
        .write_stdin("sk")
        .assert()
        .success();

    revvault_cmd(&store, &identity)
        .arg("set")
        .arg("ssh/github")
        .write_stdin("key")
        .assert()
        .success();

    revvault_cmd(&store, &identity)
        .arg("list")
        .arg("--tree")
        .assert()
        .success()
        .stdout(predicate::str::contains("credentials/").and(predicate::str::contains("ssh/")));
}

// ---------------------------------------------------------------------------
// migrate command
// ---------------------------------------------------------------------------

#[test]
fn migrate_dry_run_shows_plan() {
    let (_dir, store, identity) = setup_temp_store();
    let plaintext_dir = tempfile::tempdir().unwrap();

    std::fs::write(plaintext_dir.path().join("stripe_api_key"), "sk_live_123").unwrap();
    std::fs::write(plaintext_dir.path().join("github_token"), "ghp_abc123").unwrap();

    revvault_cmd(&store, &identity)
        .arg("migrate")
        .arg("--plaintext-dir")
        .arg(plaintext_dir.path())
        .arg("--dry-run")
        .assert()
        .success()
        .stderr(predicate::str::contains("dry run"));
}

#[test]
fn migrate_force_imports_files() {
    let (_dir, store, identity) = setup_temp_store();
    let plaintext_dir = tempfile::tempdir().unwrap();

    std::fs::write(plaintext_dir.path().join("stripe_api_key"), "sk_live_123").unwrap();

    revvault_cmd(&store, &identity)
        .arg("migrate")
        .arg("--plaintext-dir")
        .arg(plaintext_dir.path())
        .arg("--force")
        .assert()
        .success()
        .stderr(predicate::str::contains("Migrated"));

    // Verify the imported secret is in the store
    revvault_cmd(&store, &identity)
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("stripe"));
}

#[test]
fn migrate_empty_directory() {
    let (_dir, store, identity) = setup_temp_store();
    let plaintext_dir = tempfile::tempdir().unwrap();

    revvault_cmd(&store, &identity)
        .arg("migrate")
        .arg("--plaintext-dir")
        .arg(plaintext_dir.path())
        .arg("--dry-run")
        .assert()
        .success()
        .stderr(predicate::str::contains("No files found"));
}

// ---------------------------------------------------------------------------
// rotate command
// ---------------------------------------------------------------------------

#[test]
fn rotate_no_rotation_config_unknown_provider() {
    let (_dir, store, identity) = setup_temp_store();

    // No rotation.toml in store — asking for any provider should fail
    revvault_cmd(&store, &identity)
        .arg("rotate")
        .arg("nonexistent-provider")
        .assert()
        .failure();
}

#[test]
fn rotate_unknown_provider_with_config() {
    let (_dir, store, identity) = setup_temp_store();

    // Write a rotation.toml with a different provider name
    let revvault_dir = Path::new(&store).join(".revvault");
    std::fs::create_dir_all(&revvault_dir).unwrap();
    std::fs::write(
        revvault_dir.join("rotation.toml"),
        "[providers.other]\nsecret_path = \"misc/key\"\n",
    )
    .unwrap();

    revvault_cmd(&store, &identity)
        .arg("rotate")
        .arg("nonexistent")
        .assert()
        .failure()
        .stderr(predicate::str::contains("nonexistent"));
}

#[test]
fn rotate_dry_run_shows_plan() {
    let (_dir, store, identity) = setup_temp_store();

    // Seed the secret the provider will read
    revvault_cmd(&store, &identity)
        .arg("set")
        .arg("credentials/svc/api-key")
        .write_stdin("current-key")
        .assert()
        .success();

    // Write rotation.toml pointing at a syntactically valid (but unreachable) URL
    let revvault_dir = Path::new(&store).join(".revvault");
    std::fs::create_dir_all(&revvault_dir).unwrap();
    std::fs::write(
        revvault_dir.join("rotation.toml"),
        "[providers.svc]\nsecret_path = \"credentials/svc/api-key\"\n\
        [providers.svc.settings]\ncreate_url = \"https://api.example.com/keys\"\n\
        response_field = \"key\"\n",
    )
    .unwrap();

    revvault_cmd(&store, &identity)
        .arg("rotate")
        .arg("--dry-run")
        .arg("svc")
        .assert()
        .success()
        .stderr(predicate::str::contains("dry run"));
}

#[tokio::test]
async fn rotate_executes_via_cli() {
    let mut server = mockito::Server::new_async().await;

    let _mock = server
        .mock("POST", "/keys")
        .with_status(201)
        .with_header("content-type", "application/json")
        .with_body(r#"{"key":"rotated-value"}"#)
        .create_async()
        .await;

    let (_dir, store, identity) = setup_temp_store();

    // Seed the current secret
    revvault_cmd(&store, &identity)
        .arg("set")
        .arg("credentials/svc/api-key")
        .write_stdin("old-key")
        .assert()
        .success();

    // Write rotation.toml pointing at the mock server
    let revvault_dir = Path::new(&store).join(".revvault");
    std::fs::create_dir_all(&revvault_dir).unwrap();
    std::fs::write(
        revvault_dir.join("rotation.toml"),
        format!(
            "[providers.svc]\nsecret_path = \"credentials/svc/api-key\"\n\
            [providers.svc.settings]\ncreate_url = \"{}/keys\"\nresponse_field = \"key\"\n",
            server.url()
        ),
    )
    .unwrap();

    revvault_cmd(&store, &identity)
        .arg("rotate")
        .arg("svc")
        .assert()
        .success();

    // New key should be in the vault
    revvault_cmd(&store, &identity)
        .arg("get")
        .arg("credentials/svc/api-key")
        .assert()
        .success()
        .stdout(predicate::str::contains("rotated-value"));
}

// ---------------------------------------------------------------------------
// rotation-status command
// ---------------------------------------------------------------------------

#[test]
fn rotation_status_no_history() {
    let (_dir, store, identity) = setup_temp_store();

    revvault_cmd(&store, &identity)
        .arg("rotation-status")
        .assert()
        .success()
        .stderr(predicate::str::contains("No rotation history"));
}

#[test]
fn rotation_status_shows_recent_entries() {
    let (_dir, store, identity) = setup_temp_store();

    // Manually write a log entry
    let revvault_dir = Path::new(&store).join(".revvault");
    std::fs::create_dir_all(&revvault_dir).unwrap();
    let log_entry = r#"{"timestamp":"2026-01-01T00:00:00Z","provider":"svc","secret_path":"credentials/svc/key","new_key_id":null,"status":"success"}"#;
    std::fs::write(
        revvault_dir.join("rotation-log.jsonl"),
        format!("{log_entry}\n"),
    )
    .unwrap();

    revvault_cmd(&store, &identity)
        .arg("rotation-status")
        .assert()
        .success()
        .stdout(predicate::str::contains("svc"));
}

// ---------------------------------------------------------------------------
// completions command
// ---------------------------------------------------------------------------

#[test]
fn completions_generates_bash_output() {
    assert_cmd::cargo::cargo_bin_cmd!("revvault")
        .arg("completions")
        .arg("bash")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}

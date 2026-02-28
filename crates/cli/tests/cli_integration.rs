use std::io::Write;

use assert_cmd::Command;
use predicates::prelude::*;
use secrecy::ExposeSecret;
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
    let mut cmd = Command::cargo_bin("revvault").unwrap();
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

    // Delete it
    revvault_cmd(&store, &identity)
        .arg("delete")
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

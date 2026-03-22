use age::x25519;
use secrecy::ExposeSecret;

use revvault_core::config::Config;
use revvault_core::namespace::Namespace;
use revvault_core::store::PassageStore;

/// Create a temp store with generated identity and recipients.
fn setup_store() -> (tempfile::TempDir, PassageStore) {
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
            ExposeSecret::expose_secret(&id.to_string())
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

#[test]
fn full_lifecycle_set_get_list_search_delete() {
    let (_dir, store) = setup_store();

    // Set multiple secrets across namespaces
    store
        .set("credentials/stripe/secret-key", b"sk_live_abc123")
        .unwrap();
    store
        .set("credentials/stripe/publishable-key", b"pk_live_xyz789")
        .unwrap();
    store
        .set("ssh/github-deploy", b"ssh-ed25519 AAAA...")
        .unwrap();
    store
        .set("revealui/env/api-url", b"https://api.revealui.com")
        .unwrap();
    store.set("misc/scratch-note", b"remember this").unwrap();

    // Get: decrypt and verify
    let secret = store.get("credentials/stripe/secret-key").unwrap();
    assert_eq!(secret.expose_secret(), "sk_live_abc123");

    let secret = store.get("ssh/github-deploy").unwrap();
    assert_eq!(secret.expose_secret(), "ssh-ed25519 AAAA...");

    // List: all entries
    let all = store.list(None).unwrap();
    assert_eq!(all.len(), 5);

    // List: filtered by prefix
    let creds = store.list(Some("credentials")).unwrap();
    assert_eq!(creds.len(), 2);
    assert!(creds.iter().all(|e| e.path.starts_with("credentials/")));

    // Namespace parsing
    let stripe = all
        .iter()
        .find(|e| e.path == "credentials/stripe/secret-key")
        .unwrap();
    assert_eq!(stripe.namespace, Namespace::Credentials);

    let ssh = all.iter().find(|e| e.path == "ssh/github-deploy").unwrap();
    assert_eq!(ssh.namespace, Namespace::Ssh);

    // Search: fuzzy match
    let results = store.search("stripe").unwrap();
    assert_eq!(results.len(), 2);
    assert!(results.iter().all(|e| e.path.contains("stripe")));

    let results = store.search("github").unwrap();
    assert!(results.iter().any(|e| e.path.contains("github")));

    // Delete: remove and verify cleanup
    store.delete("credentials/stripe/publishable-key").unwrap();
    let remaining = store.list(Some("credentials/stripe")).unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].path, "credentials/stripe/secret-key");

    // Delete the last secret in a nested dir — parent dirs should be cleaned
    store.delete("credentials/stripe/secret-key").unwrap();
    let creds_after = store.list(Some("credentials")).unwrap();
    assert!(creds_after.is_empty());

    // Verify the credentials/stripe directory was cleaned up
    let stripe_dir = store.store_dir().join("credentials/stripe");
    assert!(!stripe_dir.exists());
}

#[test]
fn upsert_overwrites_and_creates() {
    let (_dir, store) = setup_store();

    // Create via upsert
    store.upsert("misc/token", b"initial").unwrap();
    let v = store.get("misc/token").unwrap();
    assert_eq!(v.expose_secret(), "initial");

    // Overwrite via upsert
    store.upsert("misc/token", b"updated").unwrap();
    let v = store.get("misc/token").unwrap();
    assert_eq!(v.expose_secret(), "updated");
}

#[test]
fn passage_compatible_format() {
    let (_dir, store) = setup_store();

    store.set("credentials/test/api-key", b"secret123").unwrap();

    // Verify .age file exists at expected path
    let age_file = store.store_dir().join("credentials/test/api-key.age");
    assert!(age_file.exists());
    assert!(age_file.is_file());

    // Verify .age file starts with age header
    let contents = std::fs::read(&age_file).unwrap();
    assert!(
        contents.starts_with(b"age-encryption.org/v1"),
        "file should have age header"
    );

    // Verify directory structure matches path
    let test_dir = store.store_dir().join("credentials/test");
    assert!(test_dir.is_dir());
}

#[test]
fn path_traversal_blocked() {
    let (_dir, store) = setup_store();

    assert!(store.set("../../etc/passwd", b"hacked").is_err());
    assert!(store.get("../../../etc/shadow").is_err());
    assert!(store.upsert("foo/../../bar", b"nope").is_err());
    assert!(store.delete("./hidden").is_err());
    assert!(store.set("", b"empty").is_err());
}

/// Validate against real passage-store (opt-in via --ignored).
/// Run with: REVVAULT_STORE=~/.revealui/passage-store REVVAULT_IDENTITY=~/.age-identity/keys.txt cargo test -p revvault-core -- --ignored
#[test]
#[ignore]
fn real_store_list_and_decrypt() {
    let config = Config::resolve().expect(
        "set REVVAULT_STORE and REVVAULT_IDENTITY env vars to point at your real passage-store",
    );
    let store = PassageStore::open(config).unwrap();

    let entries = store.list(None).unwrap();
    assert!(!entries.is_empty(), "real store should have entries");

    // Verify all entries have .age file paths
    for entry in &entries {
        assert!(
            entry.file_path.extension().unwrap() == "age",
            "entry {} should point to .age file",
            entry.path
        );
        assert!(
            entry.file_path.exists(),
            "file should exist: {}",
            entry.path
        );
    }

    // Try to decrypt the first entry
    let first = &entries[0];
    let secret = store.get(&first.path).unwrap();
    assert!(
        !secret.expose_secret().is_empty(),
        "decrypted secret should not be empty"
    );
}

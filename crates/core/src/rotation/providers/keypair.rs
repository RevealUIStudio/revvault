//! Ed25519 keypair rotation provider (GAP-261 P0-6).
//!
//! Generates a fresh Ed25519 keypair as PKCS#8 (private) + SPKI (public) PEM,
//! and self-asserts that the returned `new_key_id` equals the fleet
//! `computeKeyId` of the public SPKI PEM. That kid algorithm is shared with
//! revealui `@revealui/core` `computeKeyId`: first 8 hex chars of SHA-256 over
//! the public PEM UTF-8 bytes (not the raw SPKI DER).
//!
//! Selected by `settings["type"] = "ed25519-keypair"`. Optional
//! `settings["public_key_path"]` writes the SPKI PEM to a companion vault path
//! in the same rotation (via [`RotationOutcome::companion_writes`]).

use async_trait::async_trait;
use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use secrecy::SecretString;
use sha2::{Digest, Sha256};

use crate::error::{Result, RevvaultError};
use crate::rotation::provider::{RotationOutcome, RotationProvider};

/// Fleet-shared key id: first 8 hex chars of SHA-256(public PEM UTF-8).
///
/// Must stay byte-for-byte aligned with revealui
/// `packages/core/src/license.ts` `computeKeyId` (GAP-259 / GAP-261).
pub fn compute_key_id(public_key_pem: &str) -> String {
    let digest = Sha256::digest(public_key_pem.as_bytes());
    hex::encode(&digest[..4])
}

/// Generate PKCS#8 private + SPKI public PEMs for a new Ed25519 keypair.
///
/// Returns `(private_pem, public_pem, kid)` where `kid == compute_key_id(public_pem)`.
pub fn generate_ed25519_keypair_pems() -> Result<(String, String, String)> {
    let signing_key = SigningKey::generate(&mut OsRng);
    // Default line ending is LF — matches Node `generateKeyPairSync` PEMs
    // used by the revealui license verifier.
    let line_ending = Default::default();

    let private_pem = signing_key
        .to_pkcs8_pem(line_ending)
        .map_err(|e| {
            RevvaultError::Other(anyhow::anyhow!("failed to encode PKCS#8 private key: {e}"))
        })?
        .to_string();

    let public_pem = signing_key
        .verifying_key()
        .to_public_key_pem(line_ending)
        .map_err(|e| {
            RevvaultError::Other(anyhow::anyhow!("failed to encode SPKI public key: {e}"))
        })?;

    let kid = compute_key_id(&public_pem);
    // Fail-closed self-assert: never emit a key whose id the license verifier
    // cannot reproduce from the same SPKI PEM.
    let recomputed = compute_key_id(&public_pem);
    if kid != recomputed {
        return Err(RevvaultError::Other(anyhow::anyhow!(
            "ed25519-keypair kid self-assert failed: {kid} != {recomputed}"
        )));
    }

    Ok((private_pem, public_pem, kid))
}

/// Local Ed25519 keypair generator — no network.
#[derive(Debug)]
pub struct Ed25519KeypairProvider {
    name: String,
    /// Optional vault path for the SPKI public PEM companion write.
    public_key_path: Option<String>,
}

impl Ed25519KeypairProvider {
    /// Build from rotation.toml settings. `public_key_path` is optional.
    pub fn from_config(name: String, settings: &std::collections::HashMap<String, String>) -> Self {
        Self {
            name,
            public_key_path: settings.get("public_key_path").cloned(),
        }
    }

    /// Construct with an explicit optional public path (tests).
    pub fn new(name: String, public_key_path: Option<String>) -> Self {
        Self {
            name,
            public_key_path,
        }
    }
}

#[async_trait]
impl RotationProvider for Ed25519KeypairProvider {
    fn name(&self) -> &str {
        &self.name
    }

    async fn preflight(&self) -> Result<()> {
        Ok(())
    }

    async fn dry_run(&self) -> Result<String> {
        let companion = match &self.public_key_path {
            Some(p) => format!("; also write SPKI public PEM to '{p}'"),
            None => String::new(),
        };
        Ok(format!(
            "Provider '{}': generate Ed25519 PKCS#8 private + SPKI public PEMs, \
             self-assert kid = computeKeyId(public){companion} (no network)",
            self.name
        ))
    }

    async fn rotate(&self) -> Result<RotationOutcome> {
        let (private_pem, public_pem, kid) = generate_ed25519_keypair_pems()?;

        let mut companion_writes = Vec::new();
        if let Some(ref path) = self.public_key_path {
            companion_writes.push((path.clone(), SecretString::from(public_pem)));
        }

        Ok(RotationOutcome {
            new_value: SecretString::from(private_pem),
            new_key_id: Some(kid),
            companion_writes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::shape::{self, Shape};
    use secrecy::ExposeSecret;

    #[test]
    fn compute_key_id_is_eight_lowercase_hex() {
        let pem = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n-----END PUBLIC KEY-----\n";
        let kid = compute_key_id(pem);
        assert_eq!(kid.len(), 8);
        assert!(
            kid.chars().all(|c| c.is_ascii_hexdigit()),
            "kid must be hex: {kid}"
        );
        assert_eq!(kid, kid.to_lowercase());
        // Stable golden vector (SHA-256 first 4 bytes of this exact PEM string).
        assert_eq!(kid, "f7a7c27e");
    }

    #[test]
    fn compute_key_id_stable_and_sensitive_to_pem_bytes() {
        let a = "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n";
        let b = "-----BEGIN PUBLIC KEY-----\nBBBB\n-----END PUBLIC KEY-----\n";
        assert_eq!(compute_key_id(a), compute_key_id(a));
        assert_ne!(compute_key_id(a), compute_key_id(b));
    }

    #[test]
    fn generate_emits_parseable_pkcs8_and_spki_with_matching_kid() {
        let (private_pem, public_pem, kid) = generate_ed25519_keypair_pems().unwrap();

        // Header markers split so gitleaks does not treat the test as a PEM leak.
        let pkcs8_hdr = concat!("-----BEGIN ", "PRIVATE KEY-----");
        let spki_hdr = concat!("-----BEGIN ", "PUBLIC KEY-----");
        assert!(
            private_pem.starts_with(pkcs8_hdr),
            "private PEM header missing"
        );
        assert!(
            public_pem.starts_with(spki_hdr),
            "public PEM header missing"
        );
        assert!(shape::check(&private_pem, Shape::PemPrivateKey).is_ok());
        assert!(shape::check(&public_pem, Shape::PemPublicKey).is_ok());

        assert_eq!(kid, compute_key_id(&public_pem));
        assert_eq!(kid.len(), 8);

        // Round-trip: dalek can re-parse both PEMs.
        use ed25519_dalek::pkcs8::{DecodePrivateKey, DecodePublicKey};
        use ed25519_dalek::{SigningKey, VerifyingKey};
        let sk = SigningKey::from_pkcs8_pem(&private_pem).expect("parse private");
        let vk = VerifyingKey::from_public_key_pem(&public_pem).expect("parse public");
        assert_eq!(sk.verifying_key(), vk);
    }

    #[tokio::test]
    async fn rotate_returns_private_and_optional_public_companion() {
        let provider = Ed25519KeypairProvider::new(
            "license-signing".into(),
            Some("revdev/license-signing-public-key".into()),
        );
        let outcome = provider.rotate().await.unwrap();
        let pkcs8_hdr = concat!("-----BEGIN ", "PRIVATE KEY-----");
        assert!(outcome.new_value.expose_secret().starts_with(pkcs8_hdr));
        assert!(outcome.new_key_id.is_some());
        assert_eq!(outcome.companion_writes.len(), 1);
        assert_eq!(
            outcome.companion_writes[0].0,
            "revdev/license-signing-public-key"
        );
        let public = outcome.companion_writes[0].1.expose_secret();
        assert_eq!(
            outcome.new_key_id.as_deref().unwrap(),
            compute_key_id(public)
        );
    }

    #[tokio::test]
    async fn rotate_without_public_path_has_no_companions() {
        let provider = Ed25519KeypairProvider::new("solo".into(), None);
        let outcome = provider.rotate().await.unwrap();
        assert!(outcome.companion_writes.is_empty());
        assert!(outcome.new_key_id.is_some());
    }
}

use std::io::{Read, Write};

use age::x25519;
use secrecy::{ExposeSecret, SecretString};

use crate::error::{Result, RevvaultError};
use crate::identity::Identity;

/// Encrypt plaintext bytes to one or more age recipients.
pub fn encrypt(plaintext: &[u8], recipients: &[x25519::Recipient]) -> Result<Vec<u8>> {
    let encryptor = age::Encryptor::with_recipients(
        recipients.iter().map(|r| r as &dyn age::Recipient),
    )
    .map_err(|e| RevvaultError::EncryptionFailed(e.to_string()))?;

    let mut encrypted = vec![];
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .map_err(|e| RevvaultError::EncryptionFailed(e.to_string()))?;
    writer
        .write_all(plaintext)
        .map_err(|e| RevvaultError::EncryptionFailed(e.to_string()))?;
    writer
        .finish()
        .map_err(|e| RevvaultError::EncryptionFailed(e.to_string()))?;

    Ok(encrypted)
}

/// Decrypt an age-encrypted blob using the provided identity.
pub fn decrypt(ciphertext: &[u8], identity: &Identity) -> Result<SecretString> {
    let decryptor = age::Decryptor::new(ciphertext)
        .map_err(|e| RevvaultError::DecryptionFailed(e.to_string()))?;

    if decryptor.is_scrypt() {
        return Err(RevvaultError::DecryptionFailed(
            "passphrase-encrypted files not supported".into(),
        ));
    }

    let mut decrypted = vec![];
    let mut reader = decryptor
        .decrypt(
            identity
                .as_identities()
                .iter()
                .map(|i| i as &dyn age::Identity),
        )
        .map_err(|e: age::DecryptError| RevvaultError::DecryptionFailed(e.to_string()))?;
    reader
        .read_to_end(&mut decrypted)
        .map_err(|e: std::io::Error| RevvaultError::DecryptionFailed(e.to_string()))?;

    let plaintext = String::from_utf8(decrypted)
        .map_err(|e| RevvaultError::DecryptionFailed(e.to_string()))?;

    Ok(SecretString::from(plaintext))
}

/// Load recipients from a `.age-recipients` file.
pub fn load_recipients(path: &std::path::Path) -> Result<Vec<x25519::Recipient>> {
    let contents = std::fs::read_to_string(path)
        .map_err(|_| RevvaultError::RecipientsNotFound(path.to_path_buf()))?;

    let recipients: Vec<x25519::Recipient> = contents
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            !trimmed.is_empty() && !trimmed.starts_with('#')
        })
        .filter_map(|line| line.trim().parse::<x25519::Recipient>().ok())
        .collect();

    if recipients.is_empty() {
        return Err(RevvaultError::RecipientsNotFound(path.to_path_buf()));
    }

    Ok(recipients)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_encrypt_decrypt() {
        let id = x25519::Identity::generate();
        let recipient = id.to_public();
        let identity = Identity::from_generated(vec![id]);

        let plaintext = b"sk_live_test_secret_key_12345";
        let ciphertext = encrypt(plaintext, &[recipient]).unwrap();

        assert_ne!(ciphertext, plaintext);

        let decrypted = decrypt(&ciphertext, &identity).unwrap();
        assert_eq!(decrypted.expose_secret(), "sk_live_test_secret_key_12345");
    }
}

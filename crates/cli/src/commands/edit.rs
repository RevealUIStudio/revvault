use std::env;
use std::process::Command;

use clap::Args;
use secrecy::ExposeSecret;

use revvault_core::Config;
use revvault_core::PassageStore;

#[derive(Args)]
pub struct EditArgs {
    /// Secret path to edit
    pub path: String,
}

pub fn run(args: EditArgs) -> anyhow::Result<()> {
    let config = Config::resolve()?;
    let store = PassageStore::open(config)?;

    // Decrypt current value
    let secret = store.get(&args.path)?;
    let current = secret.expose_secret().to_string();

    // Write to temp file
    let tmp = tempfile::NamedTempFile::new()?;
    std::fs::write(tmp.path(), &current)?;

    // Open in editor
    let editor = env::var("EDITOR").unwrap_or_else(|_| "vi".into());
    let status = Command::new(&editor).arg(tmp.path()).status()?;

    if !status.success() {
        anyhow::bail!("editor exited with non-zero status");
    }

    // Read back and re-encrypt
    let new_value = std::fs::read_to_string(tmp.path())?;
    let trimmed = new_value.trim();

    if trimmed == current.trim() {
        eprintln!("No changes made.");
        return Ok(());
    }

    store.upsert(&args.path, trimmed.as_bytes())?;
    eprintln!("Updated: {}", args.path);

    Ok(())
}

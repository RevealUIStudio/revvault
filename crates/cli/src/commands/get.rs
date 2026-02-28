use std::io::{self, Write};

use arboard::Clipboard;
use clap::Args;
use secrecy::ExposeSecret;

use revvault_core::Config;
use revvault_core::PassageStore;

#[derive(Args)]
pub struct GetArgs {
    /// Secret path (e.g., "credentials/stripe/secret-key")
    pub path: String,

    /// Copy to clipboard instead of printing
    #[arg(short, long)]
    pub clip: bool,

    /// Show full multiline content (default: first line only)
    #[arg(short, long)]
    pub full: bool,
}

pub fn run(args: GetArgs) -> anyhow::Result<()> {
    let config = Config::resolve()?;
    let store = PassageStore::open(config)?;
    let secret = store.get(&args.path)?;
    let value = secret.expose_secret();

    if args.clip {
        let mut clipboard = Clipboard::new()?;
        clipboard.set_text(value)?;
        eprintln!("Copied to clipboard. Remember to clear it when done.");
    } else if args.full {
        let stdout = io::stdout();
        let mut handle = stdout.lock();
        write!(handle, "{value}")?;
    } else {
        // Print first line only (most secrets are single-line)
        let first_line = value.lines().next().unwrap_or("");
        println!("{first_line}");
    }

    Ok(())
}

use std::io::{self, Write};

use arboard::Clipboard;
use clap::Args;
use secrecy::ExposeSecret;
use serde_json::json;

use super::stream_safe;

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

pub fn run(args: GetArgs, json_output: bool) -> anyhow::Result<()> {
    // Stream-safe: refuse human-visible disclosure without REVVAULT_ALLOW_PRINT=1.
    // Piped/script consumers (stdout not a TTY) still work under STREAM_SAFE.
    stream_safe::gate_human_disclosure(args.clip, json_output && stream_safe::stdout_is_tty())?;

    let store = super::open_store()?;
    let secret = store.get(&args.path)?;
    let value = secret.expose_secret();

    if value.is_empty() {
        eprintln!("warning: stored value is empty (path: {})", args.path);
    }

    if json_output {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "path": args.path,
                "value": value,
            }))?
        );
        return Ok(());
    }

    if args.clip {
        let mut clipboard = Clipboard::new()?;
        clipboard.set_text(value)?;
        eprintln!("Copied to clipboard. Remember to clear it when done.");
        if stream_safe::stream_safe_enabled() {
            eprintln!("stream-safe note: clear the clipboard after paste (Vault terminal only).");
        }
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

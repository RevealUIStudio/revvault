use std::io::{self, Write};
use std::time::SystemTime;

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

    /// Print the secret value on a TTY (default: metadata only)
    #[arg(long)]
    pub reveal: bool,
}

/// Print the secret value when `--reveal`/`--full`/`--clip` or stdout is not a TTY.
pub(crate) fn should_print_value(reveal: bool, full: bool, clip: bool, stdout_is_tty: bool) -> bool {
    reveal || full || clip || !stdout_is_tty
}

pub fn run(args: GetArgs, json_output: bool) -> anyhow::Result<()> {
    let print_value = should_print_value(
        args.reveal,
        args.full,
        args.clip,
        stream_safe::stdout_is_tty(),
    );
    if print_value {
        stream_safe::gate_human_disclosure(args.clip, json_output && stream_safe::stdout_is_tty())?;
    }

    let store = super::open_store()?;
    let secret = store.get(&args.path).map_err(|e| match e {
        revvault_core::RevvaultError::SecretNotFound(path) => {
            anyhow::anyhow!("path not found: {path}")
        }
        other => other.into(),
    })?;
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
                "bytes": value.len(),
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
        return Ok(());
    }

    if !print_value {
        print_metadata(&args.path, value.len(), store_mtime(&store, &args.path));
        return Ok(());
    }

    if args.full {
        let stdout = io::stdout();
        let mut handle = stdout.lock();
        write!(handle, "{value}")?;
    } else {
        let first_line = value.lines().next().unwrap_or("");
        println!("{first_line}");
    }

    Ok(())
}

fn store_mtime(store: &revvault_core::PassageStore, path: &str) -> Option<SystemTime> {
    store
        .list(Some(path))
        .ok()?
        .into_iter()
        .find(|e| e.path == path)
        .and_then(|e| std::fs::metadata(&e.file_path).ok()?.modified().ok())
}

fn print_metadata(path: &str, bytes: usize, mtime: Option<SystemTime>) {
    println!("path: {path}");
    println!("size: {bytes} bytes");
    if let Some(t) = mtime {
        if let Ok(d) = t.duration_since(SystemTime::UNIX_EPOCH) {
            println!("modified: {}s since epoch", d.as_secs());
        }
    }
    println!("(value not shown — pass --reveal to display)");
}

#[cfg(test)]
mod should_print_value_tests {
    use super::should_print_value;

    #[test]
    fn tty_hides_value_without_reveal() {
        assert!(!should_print_value(false, false, false, true));
    }

    #[test]
    fn tty_shows_value_with_reveal() {
        assert!(should_print_value(true, false, false, true));
    }

    #[test]
    fn piped_stdout_shows_value() {
        assert!(should_print_value(false, false, false, false));
    }

    #[test]
    fn full_implies_print() {
        assert!(should_print_value(false, true, false, true));
    }
}

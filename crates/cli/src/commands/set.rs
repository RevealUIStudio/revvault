use std::io::{self, IsTerminal, Read};

use clap::Args;
use serde_json::json;

#[derive(Args)]
pub struct SetArgs {
    /// Secret path (e.g., "credentials/stripe/secret-key")
    pub path: String,

    /// Overwrite existing secret without error
    #[arg(short, long)]
    pub force: bool,

    /// Prompt for multi-line input (visible) instead of a single hidden line
    #[arg(short, long)]
    pub multiline: bool,

    /// Literal value (discouraged for credentials — leaks to shell history)
    #[arg(long)]
    pub value: Option<String>,

    /// Accepted for compatibility. The byte-count line is always printed.
    #[arg(long)]
    pub verbose: bool,
}

/// Success line for `set` and `edit`. Byte length is the exact stored length.
/// The prefix is at most 8 Unicode scalars so the line cannot carry the secret.
pub(crate) fn stored_confirmation(path: &str, stored: &str) -> String {
    let prefix: String = stored.chars().take(8).collect();
    format!("stored {} bytes at {path} (starts: {prefix})", stored.len())
}

pub fn run(args: SetArgs, json_output: bool) -> anyhow::Result<()> {
    let store = super::open_store()?;
    let tty = io::stdin().is_terminal();

    if args.value.is_some() {
        eprintln!(
            "warning: --value exposes the secret in shell history; prefer a prompt or piped stdin"
        );
    }

    let input = read_secret(&args, tty)?;
    let trimmed = input.trim();

    if trimmed.is_empty() {
        if tty && args.value.is_none() {
            anyhow::bail!("no secret entered");
        }
        anyhow::bail!("no input provided on stdin");
    }

    if args.force {
        store.upsert(&args.path, trimmed.as_bytes())?;
    } else {
        store.set(&args.path, trimmed.as_bytes())?;
    }

    let _ = args.verbose;
    eprintln!("{}", stored_confirmation(&args.path, trimmed));
    if json_output {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "status": "stored",
                "path": args.path,
                "bytes": trimmed.len(),
            }))?
        );
    }

    Ok(())
}

/// Read the secret value: `--value`, a hidden one-line prompt on a terminal,
/// or raw stdin-to-EOF when piped.
fn read_secret(args: &SetArgs, tty: bool) -> anyhow::Result<String> {
    if let Some(value) = &args.value {
        return Ok(value.clone());
    }

    if !tty {
        let mut input = String::new();
        io::stdin().read_to_string(&mut input)?;
        return Ok(input);
    }

    let overwrite = if args.force { "yes" } else { "no" };
    eprintln!("Set {} (overwrite: {overwrite})", args.path);

    if args.multiline {
        eprintln!("Enter multi-line secret, then Ctrl-D to submit (Ctrl-C to cancel).");
        let mut input = String::new();
        io::stdin().read_to_string(&mut input)?;
        return Ok(input);
    }

    eprintln!("Enter value, then Enter to submit (Ctrl-C to cancel).");
    eprintln!("Input will not be echoed.");
    eprint!("> ");
    Ok(rpassword::read_password()?)
}

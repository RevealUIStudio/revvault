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

    /// Print byte-length confirmation even when stdin is piped
    #[arg(long)]
    pub verbose: bool,
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

    let bytes = trimmed.len();
    if json_output {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "status": "stored",
                "path": args.path,
                "bytes": bytes,
            }))?
        );
    } else if tty || args.verbose {
        eprintln!("✓ Stored: {} ({bytes} bytes)", args.path);
    } else {
        eprintln!("Stored: {}", args.path);
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

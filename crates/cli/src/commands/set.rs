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
}

pub fn run(args: SetArgs, json_output: bool) -> anyhow::Result<()> {
    let store = super::open_store()?;

    let input = read_secret(&args)?;
    let trimmed = input.trim();

    if trimmed.is_empty() {
        if io::stdin().is_terminal() {
            anyhow::bail!("no secret entered");
        }
        anyhow::bail!("no input provided on stdin");
    }

    if args.force {
        store.upsert(&args.path, trimmed.as_bytes())?;
    } else {
        store.set(&args.path, trimmed.as_bytes())?;
    }

    if json_output {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "status": "stored",
                "path": args.path,
            }))?
        );
    } else {
        eprintln!("Stored: {}", args.path);
    }

    Ok(())
}

/// Read the secret value: a hidden one-line prompt on a terminal, raw
/// stdin-to-EOF when piped (scripts and agents), `--multiline` for visible
/// multi-line terminal entry.
fn read_secret(args: &SetArgs) -> anyhow::Result<String> {
    if !io::stdin().is_terminal() {
        let mut input = String::new();
        io::stdin().read_to_string(&mut input)?;
        return Ok(input);
    }

    if args.multiline {
        eprintln!(
            "Enter multi-line secret for {} (finish with Ctrl+D on an empty line):",
            args.path
        );
        let mut input = String::new();
        io::stdin().read_to_string(&mut input)?;
        return Ok(input);
    }

    eprint!(
        "Enter secret for {} (input hidden, Enter to finish): ",
        args.path
    );
    Ok(rpassword::read_password()?)
}

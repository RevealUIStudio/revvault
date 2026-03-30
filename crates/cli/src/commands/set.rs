use std::io::{self, Read};

use clap::Args;
use serde_json::json;

use revvault_core::Config;
use revvault_core::PassageStore;

#[derive(Args)]
pub struct SetArgs {
    /// Secret path (e.g., "credentials/stripe/secret-key")
    pub path: String,

    /// Overwrite existing secret without error
    #[arg(short, long)]
    pub force: bool,
}

pub fn run(args: SetArgs, json_output: bool) -> anyhow::Result<()> {
    let config = Config::resolve()?;
    let store = PassageStore::open(config)?;

    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let trimmed = input.trim();

    if trimmed.is_empty() {
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

use clap::Args;
use serde_json::json;

use revvault_core::init::{init_vault, InitOptions};

#[derive(Args)]
pub struct InitArgs {
    /// Override the store directory (default: ~/.revealui/passage-store)
    #[arg(long, value_name = "DIR")]
    pub store_dir: Option<std::path::PathBuf>,

    /// Override the identity file (default: ~/.config/age/keys.txt)
    #[arg(long, value_name = "FILE")]
    pub identity_file: Option<std::path::PathBuf>,
}

pub fn run(args: InitArgs, json_output: bool) -> anyhow::Result<()> {
    let summary = init_vault(InitOptions {
        store_dir: args.store_dir,
        identity_file: args.identity_file,
    })?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "status": "initialized",
                "store": summary.store_dir.to_string_lossy(),
                "identity": summary.identity_file.to_string_lossy(),
                "public_key": summary.public_key,
            }))?
        );
        return Ok(());
    }

    if summary.store_existed && summary.identity_existed {
        eprintln!(
            "Vault already initialized.\n  Store:    {}\n  Identity: {}",
            summary.store_dir.display(),
            summary.identity_file.display(),
        );
        return Ok(());
    }

    if !summary.store_existed {
        eprintln!("✓ Created store:    {}", summary.store_dir.display());
    } else {
        eprintln!("  Store exists:     {}", summary.store_dir.display());
    }

    if !summary.identity_existed {
        eprintln!("✓ Generated identity: {}", summary.identity_file.display());
        eprintln!("  Public key:         {}", summary.public_key);
    } else {
        eprintln!("  Identity exists:  {}", summary.identity_file.display());
    }

    eprintln!();
    eprintln!(
        "WARNING: Back up your identity file — if you lose it, all secrets are unrecoverable."
    );
    eprintln!(
        "         Store a copy in a password manager or secure offline location."
    );
    eprintln!("         Identity: {}", summary.identity_file.display());
    eprintln!();
    eprintln!("Your vault is ready. Try:");
    eprintln!("  revvault set credentials/example/api-key   # store a secret");
    eprintln!("  revvault list                              # list secrets");

    Ok(())
}

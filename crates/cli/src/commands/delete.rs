use clap::Args;
use serde_json::json;

use revvault_core::Config;
use revvault_core::PassageStore;

#[derive(Args)]
pub struct DeleteArgs {
    /// Secret path to delete
    pub path: String,

    /// Skip confirmation
    #[arg(long)]
    pub force: bool,
}

pub fn run(args: DeleteArgs, json_output: bool) -> anyhow::Result<()> {
    // JSON mode implies --force (no interactive prompt)
    if !args.force && !json_output {
        eprint!("Delete '{}'? [y/N] ", args.path);
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            eprintln!("Aborted.");
            return Ok(());
        }
    }

    let config = Config::resolve()?;
    let store = PassageStore::open(config)?;
    store.delete(&args.path)?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "status": "deleted",
                "path": args.path,
            }))?
        );
    } else {
        eprintln!("Deleted: {}", args.path);
    }

    Ok(())
}

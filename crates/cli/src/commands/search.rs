use clap::Args;

use revvault_core::Config;
use revvault_core::PassageStore;

#[derive(Args)]
pub struct SearchArgs {
    /// Fuzzy search query
    pub query: String,
}

pub fn run(args: SearchArgs) -> anyhow::Result<()> {
    let config = Config::resolve()?;
    let store = PassageStore::open(config)?;
    let results = store.search(&args.query)?;

    if results.is_empty() {
        eprintln!("No matches found.");
        return Ok(());
    }

    for entry in &results {
        println!("{}", entry.path);
    }

    Ok(())
}

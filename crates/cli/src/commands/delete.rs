use clap::Args;

use revault_core::Config;
use revault_core::PassageStore;

#[derive(Args)]
pub struct DeleteArgs {
    /// Secret path to delete
    pub path: String,

    /// Skip confirmation
    #[arg(long)]
    pub force: bool,
}

pub fn run(args: DeleteArgs) -> anyhow::Result<()> {
    if !args.force {
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
    eprintln!("Deleted: {}", args.path);
    Ok(())
}

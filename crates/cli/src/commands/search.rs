use clap::Args;
use serde_json::json;

#[derive(Args)]
pub struct SearchArgs {
    /// Fuzzy search query
    pub query: String,
}

pub fn run(args: SearchArgs, json_output: bool) -> anyhow::Result<()> {
    let store = super::open_store()?;

    if json_output {
        let scored = store.search_scored(&args.query)?;
        let items: Vec<serde_json::Value> = scored
            .iter()
            .map(|(score, entry)| {
                json!({
                    "path": entry.path,
                    "score": score,
                })
            })
            .collect();
        println!("{}", serde_json::to_string(&items)?);
        return Ok(());
    }

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

use std::collections::BTreeMap;

use clap::Args;

use revvault_core::Config;
use revvault_core::PassageStore;

#[derive(Args)]
pub struct ListArgs {
    /// Filter by path prefix
    pub prefix: Option<String>,

    /// Show as tree view
    #[arg(short, long)]
    pub tree: bool,
}

pub fn run(args: ListArgs) -> anyhow::Result<()> {
    let config = Config::resolve()?;
    let store = PassageStore::open(config)?;
    let entries = store.list(args.prefix.as_deref())?;

    if entries.is_empty() {
        eprintln!("No secrets found.");
        return Ok(());
    }

    if args.tree {
        print_tree(&entries);
    } else {
        for entry in &entries {
            println!("{}", entry.path);
        }
    }

    Ok(())
}

fn print_tree(entries: &[revvault_core::store::SecretEntry]) {
    // Build a tree structure from paths
    let mut tree: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for entry in entries {
        let parts: Vec<&str> = entry.path.splitn(2, '/').collect();
        let (dir, name) = if parts.len() == 2 {
            (parts[0].to_string(), parts[1].to_string())
        } else {
            ("(root)".to_string(), parts[0].to_string())
        };
        tree.entry(dir).or_default().push(name);
    }

    for (dir, names) in &tree {
        println!("{dir}/");
        for (i, name) in names.iter().enumerate() {
            let prefix = if i == names.len() - 1 {
                "└── "
            } else {
                "├── "
            };
            println!("  {prefix}{name}");
        }
    }
}

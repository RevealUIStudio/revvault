use arboard::Clipboard;
use clap::Args;
use rand::seq::SliceRandom;
use rand::Rng;
use serde_json::json;

use revvault_core::Config;
use revvault_core::PassageStore;

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.<>/?~";
const AMBIGUOUS: &str = "Il1O0|`'\"";

#[derive(Args)]
pub struct GenerateArgs {
    /// Optional secret path. If provided, the generated password is stored.
    pub path: Option<String>,

    /// Password length (default: 32).
    #[arg(short, long, default_value_t = 32)]
    pub length: usize,

    /// Exclude symbol characters.
    #[arg(long)]
    pub no_symbols: bool,

    /// Exclude visually ambiguous characters (Il1O0|`'").
    #[arg(long)]
    pub no_ambiguous: bool,

    /// Copy the password to the clipboard.
    #[arg(short, long)]
    pub clip: bool,

    /// Overwrite an existing secret at the path.
    #[arg(short, long)]
    pub force: bool,

    /// Print the password to stdout even when storing.
    #[arg(short, long)]
    pub print: bool,
}

fn build_pool(no_symbols: bool, no_ambiguous: bool) -> Vec<Vec<char>> {
    let mut sets: Vec<Vec<char>> = vec![
        LOWER.chars().collect(),
        UPPER.chars().collect(),
        DIGITS.chars().collect(),
    ];
    if !no_symbols {
        sets.push(SYMBOLS.chars().collect());
    }
    if no_ambiguous {
        let bad: std::collections::HashSet<char> = AMBIGUOUS.chars().collect();
        for set in &mut sets {
            set.retain(|c| !bad.contains(c));
        }
    }
    sets
}

fn generate_password(length: usize, sets: &[Vec<char>]) -> String {
    let mut rng = rand::rng();
    let mut chars: Vec<char> = sets
        .iter()
        .map(|s| s[rng.random_range(0..s.len())])
        .collect();
    let union: Vec<char> = sets.iter().flatten().copied().collect();
    while chars.len() < length {
        chars.push(union[rng.random_range(0..union.len())]);
    }
    chars.shuffle(&mut rng);
    chars.into_iter().collect()
}

pub fn run(args: GenerateArgs, json_output: bool) -> anyhow::Result<()> {
    let sets = build_pool(args.no_symbols, args.no_ambiguous);
    if args.length < sets.len() {
        anyhow::bail!(
            "length {} too small for {} required character classes",
            args.length,
            sets.len()
        );
    }

    let password = generate_password(args.length, &sets);

    let stored_path = if let Some(path) = args.path.as_ref() {
        let config = Config::resolve()?;
        let store = PassageStore::open(config)?;
        if args.force {
            store.upsert(path, password.as_bytes())?;
        } else {
            store.set(path, password.as_bytes())?;
        }
        Some(path.clone())
    } else {
        None
    };

    if args.clip {
        let mut clipboard = Clipboard::new()?;
        clipboard.set_text(password.clone())?;
    }

    let should_print = stored_path.is_none() || args.print;

    if json_output {
        let mut out = json!({ "length": args.length });
        if let Some(p) = stored_path.as_ref() {
            out["status"] = json!("stored");
            out["path"] = json!(p);
        }
        if args.clip {
            out["clipboard"] = json!(true);
        }
        if should_print {
            out["password"] = json!(password);
        }
        println!("{}", serde_json::to_string(&out)?);
    } else {
        if should_print {
            println!("{password}");
        }
        if let Some(p) = stored_path.as_ref() {
            eprintln!("Stored: {p}");
        }
        if args.clip {
            eprintln!("Copied to clipboard. Remember to clear it when done.");
        }
    }

    Ok(())
}

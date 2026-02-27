use clap::Args;
use secrecy::ExposeSecret;

use revault_core::Config;
use revault_core::PassageStore;

#[derive(Args)]
pub struct ExportEnvArgs {
    /// Secret path (multiline secrets become KEY=VALUE lines)
    pub path: String,
}

pub fn run(args: ExportEnvArgs) -> anyhow::Result<()> {
    let config = Config::resolve()?;
    let store = PassageStore::open(config)?;
    let secret = store.get(&args.path)?;
    let value = secret.expose_secret();

    // If the secret contains KEY=VALUE lines, pass them through directly.
    // Otherwise, derive the env var name from the path.
    let has_kv_lines = value
        .lines()
        .any(|line| line.contains('=') && !line.starts_with('#'));

    if has_kv_lines {
        for line in value.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                println!("{trimmed}");
            }
        }
    } else {
        // Derive env var name from last path segment: "stripe/secret-key" → "SECRET_KEY"
        let var_name = args
            .path
            .rsplit('/')
            .next()
            .unwrap_or(&args.path)
            .to_uppercase()
            .replace('-', "_");
        println!("{var_name}={value}");
    }

    Ok(())
}

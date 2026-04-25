use clap::Args;

use revvault_core::rotation::{executor, RotationConfig};
use revvault_core::store::PassageStore;
use revvault_core::Config;

#[derive(Args)]
pub struct RotateArgs {
    /// Provider name matching a `[providers.<name>]` block in rotation.toml
    pub provider: String,

    /// Preview the rotation steps without touching the vault or any API
    #[arg(long)]
    pub dry_run: bool,
}

pub async fn run(args: RotateArgs) -> anyhow::Result<()> {
    let config = Config::resolve()?;
    let rotation_config = RotationConfig::load(&config.store_dir)?;

    let provider_config = rotation_config
        .providers
        .get(&args.provider)
        .ok_or_else(|| {
            let known: Vec<&str> = rotation_config
                .providers
                .keys()
                .map(String::as_str)
                .collect();
            if known.is_empty() {
                anyhow::anyhow!(
                    "provider '{}' not found — create {} to configure providers",
                    args.provider,
                    config.store_dir.join(".revvault/rotation.toml").display()
                )
            } else {
                anyhow::anyhow!(
                    "provider '{}' not found in rotation.toml — known: {}",
                    args.provider,
                    known.join(", ")
                )
            }
        })?;

    let store = PassageStore::open(config)?;

    if args.dry_run {
        executor::dry_run(&store, &args.provider, provider_config).await
    } else {
        executor::execute(&store, &args.provider, provider_config).await
    }
}

pub fn status() -> anyhow::Result<()> {
    let config = Config::resolve()?;
    let log_path = config.store_dir.join(".revvault/rotation-log.jsonl");

    if !log_path.exists() {
        eprintln!("No rotation history found.");
        return Ok(());
    }

    let contents = std::fs::read_to_string(&log_path)?;
    for line in contents.lines().rev().take(10) {
        println!("{line}");
    }

    Ok(())
}

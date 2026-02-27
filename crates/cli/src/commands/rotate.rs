use clap::Args;

use revault_core::rotation::RotationConfig;
use revault_core::Config;

#[derive(Args)]
pub struct RotateArgs {
    /// Provider name (stripe, vercel, neon)
    pub provider: String,

    /// Preview only, don't rotate
    #[arg(long)]
    pub dry_run: bool,
}

pub async fn run(args: RotateArgs) -> anyhow::Result<()> {
    let config = Config::resolve()?;
    let rotation_config = RotationConfig::load(&config.store_dir)?;

    let _provider_config = rotation_config
        .providers
        .get(&args.provider)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "provider '{}' not found in rotation.toml. Available: {:?}",
                args.provider,
                rotation_config.providers.keys().collect::<Vec<_>>()
            )
        })?;

    if args.dry_run {
        eprintln!(
            "[dry run] Would rotate '{}' provider secrets",
            args.provider
        );
        return Ok(());
    }

    // Provider implementations will be added in Phase 6
    eprintln!(
        "Rotation for '{}' not yet implemented. Use --dry-run to preview.",
        args.provider
    );
    Ok(())
}

pub fn status() -> anyhow::Result<()> {
    let config = Config::resolve()?;
    let log_path = config.store_dir.join(".revault/rotation-log.jsonl");

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

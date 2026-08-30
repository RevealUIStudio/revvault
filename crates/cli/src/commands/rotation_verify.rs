use clap::Args;

use revvault_core::rotation::{executor, RotationConfig};
use revvault_core::store::PassageStore;
use revvault_core::Config;

/// Read-only dual-slot next-leaf checks (GAP-261 residual operator helper).
///
/// Never prints secret material (kids/paths only). Never rotates or promotes.
#[derive(Args)]
pub struct RotationVerifyArgs {
    /// Provider name matching a dual_slot block in rotation.toml
    pub provider: String,
}

pub fn run(args: RotationVerifyArgs) -> anyhow::Result<()> {
    let config = Config::resolve()?;
    let rotation_config = RotationConfig::load(&config.store_dir)?;

    let provider_config = rotation_config
        .providers
        .get(&args.provider)
        .ok_or_else(|| {
            anyhow::anyhow!("provider '{}' not found in rotation.toml", args.provider)
        })?;

    let store = PassageStore::open(config)?;
    executor::verify_dual_slot(&store, &args.provider, provider_config)
}

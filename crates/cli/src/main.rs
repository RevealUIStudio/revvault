mod commands;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "revvault", version, about = "Age-encrypted secret vault")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Decrypt and print a secret
    Get(commands::get::GetArgs),
    /// Encrypt a secret from stdin
    Set(commands::set::SetArgs),
    /// List secrets in the store
    List(commands::list::ListArgs),
    /// Fuzzy search for secrets
    Search(commands::search::SearchArgs),
    /// Output KEY=VALUE lines for shell eval
    ExportEnv(commands::export_env::ExportEnvArgs),
    /// Decrypt → $EDITOR → re-encrypt
    Edit(commands::edit::EditArgs),
    /// Delete a secret
    Delete(commands::delete::DeleteArgs),
    /// Generate shell completions
    Completions(commands::completions::CompletionsArgs),
    /// Migrate secrets from external sources
    Migrate(commands::migrate::MigrateArgs),
    /// Rotate API keys for a provider
    Rotate(commands::rotate::RotateArgs),
    /// Show rotation status
    RotationStatus,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Get(args) => commands::get::run(args)?,
        Commands::Set(args) => commands::set::run(args)?,
        Commands::List(args) => commands::list::run(args)?,
        Commands::Search(args) => commands::search::run(args)?,
        Commands::ExportEnv(args) => commands::export_env::run(args)?,
        Commands::Edit(args) => commands::edit::run(args)?,
        Commands::Delete(args) => commands::delete::run(args)?,
        Commands::Completions(args) => commands::completions::run(args),
        Commands::Migrate(args) => commands::migrate::run(args)?,
        Commands::Rotate(args) => commands::rotate::run(args).await?,
        Commands::RotationStatus => commands::rotate::status()?,
    }

    Ok(())
}

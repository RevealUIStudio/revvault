mod commands;
pub mod tui_editor;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "revvault", version, about = "Age-encrypted secret vault")]
struct Cli {
    /// Output structured JSON instead of human-readable text
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new vault (create store directory and age identity)
    Init(commands::init::InitArgs),
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
    /// [PLANNED] Rotate API keys for a provider
    Rotate(commands::rotate::RotateArgs),
    /// Show rotation status
    RotationStatus,
    /// Sync vault secrets with external services (e.g., Vercel env vars)
    Sync(commands::sync::SyncArgs),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let json = cli.json;

    let result = match cli.command {
        Commands::Init(args) => commands::init::run(args, json),
        Commands::Get(args) => commands::get::run(args, json),
        Commands::Set(args) => commands::set::run(args, json),
        Commands::List(args) => commands::list::run(args, json),
        Commands::Search(args) => commands::search::run(args, json),
        Commands::ExportEnv(args) => commands::export_env::run(args, json),
        Commands::Edit(args) => commands::edit::run(args),
        Commands::Delete(args) => commands::delete::run(args, json),
        Commands::Completions(args) => {
            commands::completions::run(args);
            Ok(())
        }
        Commands::Migrate(args) => commands::migrate::run(args),
        Commands::Rotate(args) => commands::rotate::run(args).await,
        Commands::RotationStatus => commands::rotate::status(),
        Commands::Sync(args) => commands::sync::run(args, json).await,
    };

    if let Err(ref e) = result {
        if json {
            println!("{}", serde_json::json!({"error": e.to_string()}));
            std::process::exit(1);
        }
    }

    result
}

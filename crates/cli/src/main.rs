mod commands;
pub mod tui_editor;

use clap::{Parser, Subcommand};

const AFTER_HELP: &str = "\
Examples:
  revvault init                                  create the store and age identity
  revvault set revealui/prod/stripe/secret-key   store a secret (hidden prompt)
  revvault get revealui/prod/stripe/secret-key   decrypt and print a secret
  revvault list --tree                           browse the whole store
  revvault export-env revealui/dev/electric      KEY=VALUE lines for shell eval

Secret paths follow <project>/<subsystem>/<name>, all lower-kebab.
Scripts can pipe instead of prompting:  printf %s \"$VALUE\" | revvault set <path>";

#[derive(Parser)]
#[command(
    name = "revvault",
    version,
    about = "Age-encrypted secret vault",
    arg_required_else_help = true,
    after_help = AFTER_HELP
)]
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
    /// Store a secret (hidden prompt on a terminal, or piped stdin)
    Set(commands::set::SetArgs),
    /// Generate a strong random password (optionally store under a path)
    Generate(commands::generate::GenerateArgs),
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
    /// Promote dual-slot next → live for a rotation.toml provider (GAP-261)
    RotationPromote(commands::rotation_promote::RotationPromoteArgs),
    /// Show rotation status
    RotationStatus,
    /// Sync vault secrets with external services (e.g., Vercel env vars)
    Sync(commands::sync::SyncArgs),
    /// Vault-only health check: read every manifest entry, validate shape
    Doctor(commands::doctor::DoctorArgs),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let json = cli.json;

    let result = match cli.command {
        Commands::Init(args) => commands::init::run(args, json),
        Commands::Get(args) => commands::get::run(args, json),
        Commands::Set(args) => commands::set::run(args, json),
        Commands::Generate(args) => commands::generate::run(args, json),
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
        Commands::RotationPromote(args) => commands::rotation_promote::run(args),
        Commands::RotationStatus => commands::rotate::status(),
        Commands::Sync(args) => commands::sync::run(args, json).await,
        Commands::Doctor(args) => commands::doctor::run(args),
    };

    if let Err(ref e) = result {
        if json {
            println!("{}", serde_json::json!({"error": e.to_string()}));
            std::process::exit(1);
        }
    }

    result
}

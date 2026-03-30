use clap::Args;
use secrecy::ExposeSecret;
use serde_json::json;

use revvault_core::Config;
use revvault_core::PassageStore;

#[derive(Args)]
pub struct ExportEnvArgs {
    /// Secret path (multiline secrets become KEY=VALUE lines)
    pub path: String,
}

/// Shell-quote a value using single quotes, escaping any embedded single quotes.
/// Output is safe for use with `eval` regardless of special characters in the value.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Parse the secret into key-value pairs, used by both output modes.
fn parse_env_vars(path: &str, value: &str) -> Vec<(String, String)> {
    let has_kv_lines = value
        .lines()
        .any(|line| line.contains('=') && !line.starts_with('#'));

    if has_kv_lines {
        value
            .lines()
            .filter_map(|line| {
                let trimmed = line.trim();
                if !trimmed.is_empty() && !trimmed.starts_with('#') {
                    trimmed.split_once('=').map(|(k, v)| (k.to_string(), v.to_string()))
                } else {
                    None
                }
            })
            .collect()
    } else {
        let var_name = path
            .rsplit('/')
            .next()
            .unwrap_or(path)
            .to_uppercase()
            .replace('-', "_");
        vec![(var_name, value.to_string())]
    }
}

pub fn run(args: ExportEnvArgs, json_output: bool) -> anyhow::Result<()> {
    let config = Config::resolve()?;
    let store = PassageStore::open(config)?;
    let secret = store.get(&args.path)?;
    let value = secret.expose_secret();

    let vars = parse_env_vars(&args.path, value);

    if json_output {
        let items: Vec<serde_json::Value> = vars
            .iter()
            .map(|(k, v)| json!({"key": k, "value": v}))
            .collect();
        println!("{}", serde_json::to_string(&json!({"variables": items}))?);
        return Ok(());
    }

    for (key, val) in &vars {
        println!("export {}={}", key, shell_quote(val));
    }

    Ok(())
}

use clap::Args;
use revvault_core::sync::shape;
use secrecy::ExposeSecret;
use serde_json::json;

#[derive(Args)]
pub struct ExportEnvArgs {
    /// Secret path (multiline secrets become KEY=VALUE lines)
    pub path: String,

    /// Refuse to export any value that classifies as a PKCS#8 private key
    /// (GAP-260 P2-2). Use for verify-only namespaces such as
    /// `revealui/env/license`. When a private key is present in the secret
    /// payload, exit nonzero instead of emitting it.
    #[arg(long = "public-only")]
    pub public_only: bool,
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
                    trimmed
                        .split_once('=')
                        .map(|(k, v)| (k.to_string(), v.to_string()))
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

/// True when `value` is (or contains) a PEM private key.
///
/// For multiline PEMs stored as a single env value, `shape::classify` sees the
/// full block. For KEY=VALUE bundles, each value is classified independently.
fn is_private_key_value(value: &str) -> bool {
    // Restore literal newlines that vault bundles often store as \n sequences
    // so classify sees a real PEM block (no authored regex).
    let normalized = value.split("\\n").collect::<Vec<_>>().join("\n");
    shape::classify(&normalized) == "pem-private-key"
        || (normalized.contains("BEGIN") && normalized.contains("PRIVATE KEY"))
}

fn refuse_private_keys(vars: &[(String, String)]) -> anyhow::Result<()> {
    let mut offenders: Vec<String> = Vec::new();
    for (key, val) in vars {
        if is_private_key_value(val) {
            offenders.push(key.clone());
        }
    }
    if offenders.is_empty() {
        return Ok(());
    }
    anyhow::bail!(
        "export-env --public-only refused private-key value(s) for: {}. \
         Use a public-only vault path (e.g. revealui/env/license with SPKI only) \
         or load signing material via with-secrets license-signing \
         (requires REVVAULT_ALLOW_PRIVATE=1).",
        offenders.join(", ")
    );
}

pub fn run(args: ExportEnvArgs, json_output: bool) -> anyhow::Result<()> {
    let store = super::open_store()?;
    let secret = store.get(&args.path)?;
    let value = secret.expose_secret();

    let vars = parse_env_vars(&args.path, value);

    if args.public_only {
        refuse_private_keys(&vars)?;
    }

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

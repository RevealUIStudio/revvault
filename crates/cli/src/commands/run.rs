//! `revvault run` — load secrets into the child environment only, then exec.
//!
//! Paths appear on the command line; values never do. Prefer this (or
//! with-secrets) over `$(revvault get …)` in flags so pnpm/ps/OBS never show
//! secrets.

use std::collections::HashMap;
use std::env;
use std::process::{Command, Stdio};

use clap::Args;
use secrecy::ExposeSecret;

use super::export_env;

#[derive(Args, Debug)]
pub struct RunArgs {
    /// Map ENV_VAR=vault/path (repeatable). Value is loaded into the child only.
    #[arg(long = "env", value_name = "KEY=path", action = clap::ArgAction::Append)]
    pub env_maps: Vec<String>,

    /// Load `revealui/env/<ns>` via export-env (same namespaces as with-secrets).
    #[arg(long = "namespace", value_name = "ns", action = clap::ArgAction::Append)]
    pub namespaces: Vec<String>,

    /// Refuse private PEM values when loading namespaces (license public-only).
    #[arg(long = "public-only")]
    pub public_only: bool,

    /// Command and args after `--`
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
    pub command: Vec<String>,
}

fn parse_env_map(spec: &str) -> anyhow::Result<(String, String)> {
    let (key, path) = spec
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("--env expects KEY=vault/path, got {spec:?}"))?;
    let key = key.trim();
    let path = path.trim();
    if key.is_empty() || path.is_empty() {
        anyhow::bail!("--env expects KEY=vault/path, got {spec:?}");
    }
    if key.contains('=') {
        anyhow::bail!("invalid env key in {spec:?}");
    }
    Ok((key.to_string(), path.to_string()))
}

fn load_namespace(ns: &str, public_only: bool) -> anyhow::Result<HashMap<String, String>> {
    let path = match ns {
        "license-signing" => {
            if env::var("REVVAULT_ALLOW_PRIVATE").ok().as_deref() != Some("1") {
                anyhow::bail!(
                    "namespace license-signing requires REVVAULT_ALLOW_PRIVATE=1 (GAP-260)"
                );
            }
            "revealui/env/license-signing".to_string()
        }
        "license" => "revealui/env/license".to_string(),
        other => format!("revealui/env/{other}"),
    };

    let force_public = public_only || ns == "license";
    let args = export_env::ExportEnvArgs {
        path,
        public_only: force_public,
    };
    let vars = export_env::load_env_vars(&args)?;
    Ok(vars.into_iter().collect())
}

pub fn run(args: RunArgs) -> anyhow::Result<()> {
    let mut cmd_parts = args.command;
    // Allow accidental leading "--" from shells
    if cmd_parts.first().map(String::as_str) == Some("--") {
        cmd_parts.remove(0);
    }
    if cmd_parts.is_empty() {
        anyhow::bail!(
            "revvault run: missing command after options (use: revvault run --env K=path -- cmd…)"
        );
    }

    let mut child_env: HashMap<String, String> = HashMap::new();

    for spec in &args.env_maps {
        let (key, path) = parse_env_map(spec)?;
        let store = super::open_store()?;
        let secret = store.get(&path)?;
        child_env.insert(key, secret.expose_secret().to_string());
    }

    for ns in &args.namespaces {
        let map = load_namespace(ns, args.public_only)?;
        child_env.extend(map);
    }

    if child_env.is_empty() {
        anyhow::bail!(
            "revvault run: no secrets loaded (pass --env KEY=path and/or --namespace <ns>)"
        );
    }

    let program = &cmd_parts[0];
    let cmd_args = &cmd_parts[1..];

    let mut command = Command::new(program);
    command.args(cmd_args);
    command.envs(&child_env);
    command.stdin(Stdio::inherit());
    command.stdout(Stdio::inherit());
    command.stderr(Stdio::inherit());

    // Never log values — only program + that env keys were set.
    eprintln!(
        "revvault run: exec {} ({} secret env var(s))",
        program,
        child_env.len()
    );

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = command.exec();
        anyhow::bail!("revvault run: exec failed: {err}");
    }

    #[cfg(not(unix))]
    {
        let status = command.status()?;
        if status.success() {
            Ok(())
        } else {
            std::process::exit(status.code().unwrap_or(1));
        }
    }
}

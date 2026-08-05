//! Stream-safe secret output gates (YouTube / OBS / shared screen).
//!
//! When `STREAM_SAFE=1` or `REVVAULT_STREAM_SAFE=1`, human-facing output of
//! secret *values* (TTY print, clipboard) requires `REVVAULT_ALLOW_PRINT=1`
//! (vault-private / break-glass terminal). Piped / non-TTY consumers
//! (passenv, scripts, `$(revvault get --full)` into env) still work so
//! automation does not break under a stream-safe shell.
//!
//! Paths and error messages stay printable either way.

use std::env;
use std::io::{self, IsTerminal};

/// True when the operator (or Stream shell profile) opted into stream-safe mode.
pub fn stream_safe_enabled() -> bool {
    env_flag("STREAM_SAFE") || env_flag("REVVAULT_STREAM_SAFE")
}

/// Break-glass: vault-private terminal may print or clip full secret values.
pub fn allow_print() -> bool {
    env_flag("REVVAULT_ALLOW_PRINT")
}

fn env_flag(name: &str) -> bool {
    match env::var(name) {
        Ok(v) => v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes"),
        Err(_) => false,
    }
}

/// Whether writing a secret value to stdout would hit a human terminal.
pub fn stdout_is_tty() -> bool {
    io::stdout().is_terminal()
}

/// Block human-visible secret disclosure under stream-safe unless allow-print.
pub fn refuse_sensitive_human_output(action: &str) -> anyhow::Result<()> {
    if !stream_safe_enabled() {
        return Ok(());
    }
    if allow_print() {
        return Ok(());
    }
    anyhow::bail!(
        "stream-safe: refused to {action} without REVVAULT_ALLOW_PRINT=1.\n\
         \n\
         On stream / shared screen use paths only:\n\
           revvault run --env KEY=path -- <cmd>\n\
           with-secrets <ns…> -- <cmd>\n\
         \n\
         For a full key or clipboard paste, open a vault-private terminal\n\
         (OBS window capture excluded), then:\n\
           export REVVAULT_ALLOW_PRINT=1\n\
           revvault get --full <path>   # or --clip\n\
         \n\
         Piped/script use (stdout not a TTY) is still allowed under STREAM_SAFE."
    );
}

/// Gate TTY print or clipboard. Non-TTY stdout skips the gate (scripting).
pub fn gate_human_disclosure(clip: bool, json_to_tty: bool) -> anyhow::Result<()> {
    if clip {
        return refuse_sensitive_human_output("copy a secret to the clipboard");
    }
    if json_to_tty || stdout_is_tty() {
        return refuse_sensitive_human_output("print a secret value to the terminal");
    }
    Ok(())
}

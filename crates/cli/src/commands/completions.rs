use clap::{Args, CommandFactory};
use clap_complete::{generate, Shell};

#[derive(Args)]
pub struct CompletionsArgs {
    /// Shell to generate completions for
    pub shell: Shell,
}

pub fn run(args: CompletionsArgs) {
    let mut cmd = crate::Cli::command();
    generate(args.shell, &mut cmd, "revault", &mut std::io::stdout());
}

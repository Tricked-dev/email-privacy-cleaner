//! `email-privacy-milter` — the milter daemon.
//!
//! Listens on a TCP socket (default `127.0.0.1:11333`) speaking the milter
//! protocol, suitable for Stalwart's milter integration at the SMTP DATA stage.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use email_privacy_cleaner::config::CleanerConfig;
use email_privacy_cleaner::milter;

#[derive(Parser)]
#[command(
    name = "email-privacy-milter",
    version,
    about = "Email privacy sanitizer milter daemon for Stalwart Mail Server."
)]
struct Cli {
    /// Path to a TOML config file.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Override the listen address from the config (e.g. 127.0.0.1:11333).
    #[arg(long)]
    listen: Option<String>,

    /// Additional ClearURLs-format rule pack to load (repeatable). Merged on top
    /// of the config's `rule_packs`, so it works alongside `--config` too.
    #[arg(long = "rule-pack", value_name = "PATH")]
    rule_pack: Vec<PathBuf>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let mut cfg = match &cli.config {
        Some(p) => match CleanerConfig::from_toml_file(p) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("error loading config {p:?}: {e}");
                return ExitCode::FAILURE;
            }
        },
        None => CleanerConfig::default(),
    };

    if let Some(listen) = cli.listen {
        cfg.listen = listen;
    }

    // CLI-supplied packs augment whatever the config already lists. `run`
    // finalizes the config (compiling the combined ruleset), so this works
    // whether the config came from --config, defaults, or nothing.
    cfg.rule_packs.extend(
        cli.rule_pack
            .iter()
            .map(|p| p.to_string_lossy().into_owned()),
    );

    match milter::run(cfg) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("milter error: {e}");
            ExitCode::FAILURE
        }
    }
}

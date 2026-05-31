//! `email-privacy-cleaner` — command-line interface to the cleaner library.
//!
//! Subcommands:
//! * `clean-message --config config.toml < raw.eml > cleaned.eml`
//! * `clean-html    --config config.toml < input.html > output.html`
//! * `explain-url   "https://..."`
//! * `test-rules    fixtures/`

use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use email_privacy_cleaner::config::CleanerConfig;
use email_privacy_cleaner::{clean_html, clean_message_fail_open, clean_url, unwrap_redirect_url};
use url::Url;

#[derive(Parser)]
#[command(
    name = "email-privacy-cleaner",
    version,
    about = "Email privacy sanitizer: strip trackers, clean URLs, unwrap ESP redirects."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Clean a full RFC 5322 message read from stdin, writing the result to stdout.
    CleanMessage {
        /// Path to a TOML config file.
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Clean an HTML fragment read from stdin, writing the result to stdout.
    CleanHtml {
        #[arg(long)]
        config: Option<PathBuf>,
        /// Optional base URL used to resolve relative links.
        #[arg(long)]
        base_url: Option<String>,
    },
    /// Explain how a single URL would be cleaned / unwrapped.
    ExplainUrl {
        /// The URL to analyse.
        url: String,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Run the cleaner over every `*.eml` fixture in a directory and report.
    TestRules {
        /// Directory containing fixture `*.eml` files.
        dir: PathBuf,
        #[arg(long)]
        config: Option<PathBuf>,
    },
}

fn load_config(path: &Option<PathBuf>) -> Result<CleanerConfig, String> {
    match path {
        Some(p) => CleanerConfig::from_toml_file(p).map_err(|e| e.to_string()),
        None => {
            let mut c = CleanerConfig::default();
            c.finalize();
            Ok(c)
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::CleanMessage { config } => {
            let cfg = load_config(&config)?;
            let mut raw = Vec::new();
            io::stdin()
                .read_to_end(&mut raw)
                .map_err(|e| e.to_string())?;
            let result = clean_message_fail_open(&raw, &cfg).map_err(|e| e.to_string())?;
            io::stdout()
                .write_all(&result.cleaned)
                .map_err(|e| e.to_string())?;
            eprintln!(
                "html_parts={} urls_cleaned={} redirects_unwrapped={} pixels_removed={} modified={}{}",
                result.stats.html_parts,
                result.stats.urls_cleaned,
                result.stats.redirects_unwrapped,
                result.stats.pixels_removed,
                result.modified,
                result
                    .error
                    .as_ref()
                    .map(|e| format!(" error={e}"))
                    .unwrap_or_default(),
            );
            Ok(())
        }
        Command::CleanHtml { config, base_url } => {
            let cfg = load_config(&config)?;
            let mut html = String::new();
            io::stdin()
                .read_to_string(&mut html)
                .map_err(|e| e.to_string())?;
            let base = match base_url {
                Some(b) => Some(Url::parse(&b).map_err(|e| e.to_string())?),
                None => None,
            };
            let result = clean_html(&html, base.as_ref(), &cfg).map_err(|e| e.to_string())?;
            io::stdout()
                .write_all(result.html.as_bytes())
                .map_err(|e| e.to_string())?;
            eprintln!(
                "urls_cleaned={} redirects_unwrapped={} pixels_removed={}",
                result.urls_cleaned, result.redirects_unwrapped, result.pixels_removed
            );
            Ok(())
        }
        Command::ExplainUrl { url, config } => {
            let cfg = load_config(&config)?;
            let parsed = Url::parse(&url).map_err(|e| format!("invalid URL: {e}"))?;
            explain_url(&parsed, &cfg);
            Ok(())
        }
        Command::TestRules { dir, config } => {
            let cfg = load_config(&config)?;
            test_rules(&dir, &cfg)
        }
    }
}

fn explain_url(url: &Url, cfg: &CleanerConfig) {
    println!("input:    {url}");
    let provider = email_privacy_cleaner::redirect::detect_provider(url);
    println!("provider: {}", provider.unwrap_or("(none recognised)"));

    let unwrap = unwrap_redirect_url(url, cfg);
    if unwrap.unwrapped {
        println!("unwrapped: yes -> {}", unwrap.url);
    } else {
        println!("unwrapped: no");
        if let Some(reason) = &unwrap.rejected {
            println!("  destination candidate rejected: {}", reason.label());
        }
    }

    let cleaned = clean_url(url, cfg);
    if cleaned.changed {
        println!("query-clean: removed {:?}", cleaned.removed_params);
    } else {
        println!("query-clean: no tracking params");
    }

    println!("final:    {}", unwrap.url);
}

fn test_rules(dir: &PathBuf, cfg: &CleanerConfig) -> Result<(), String> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| format!("reading {dir:?}: {e}"))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().map(|x| x == "eml").unwrap_or(false))
        .collect();
    entries.sort();

    if entries.is_empty() {
        return Err(format!("no *.eml fixtures found in {dir:?}"));
    }

    let mut total = 0;
    let mut failures = 0;
    for path in entries {
        total += 1;
        let raw = std::fs::read(&path).map_err(|e| e.to_string())?;
        match clean_message_fail_open(&raw, cfg) {
            Ok(r) => {
                let name = path.file_name().unwrap().to_string_lossy();
                let status = if r.error.is_some() { "FAIL-OPEN" } else { "ok" };
                println!(
                    "[{status}] {name}: html_parts={} urls_cleaned={} redirects_unwrapped={} pixels_removed={} modified={}",
                    r.stats.html_parts,
                    r.stats.urls_cleaned,
                    r.stats.redirects_unwrapped,
                    r.stats.pixels_removed,
                    r.modified
                );
                if r.error.is_some() {
                    failures += 1;
                }
            }
            Err(e) => {
                failures += 1;
                println!("[ERROR] {:?}: {e}", path.file_name().unwrap());
            }
        }
    }

    println!("\n{total} fixtures processed, {failures} fail-open/error");
    Ok(())
}

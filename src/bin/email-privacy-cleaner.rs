//! `email-privacy-cleaner` — command-line interface to the cleaner library.
//!
//! Subcommands:
//! * `clean-message   --config config.toml < raw.eml > cleaned.eml`
//! * `clean-html      --config config.toml < input.html > output.html`
//! * `explain-url     "https://..."`
//! * `explain-message --config config.toml < raw.eml`
//! * `print-trackers  < raw.eml`
//! * `diff-message    < raw.eml`
//! * `test-rules      fixtures/`

use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use email_privacy_cleaner::config::CleanerConfig;
use email_privacy_cleaner::{
    clean_html, clean_message_fail_open, clean_url, unwrap_redirect_url, Mode,
};
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
    /// Explain how a full message (stdin) would be cleaned: sender policy,
    /// per-link treatment, pixels, unsubscribe target, and audit headers.
    ExplainMessage {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// List the trackers detected in a message read from stdin (tracking
    /// params, ESP redirect wrappers, and pixels).
    PrintTrackers {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Show a line diff between the original message (stdin) and the cleaned
    /// output.
    DiffMessage {
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
        Command::ExplainMessage { config } => {
            let cfg = load_config(&config)?;
            let raw = read_stdin_bytes()?;
            explain_message(&raw, &cfg)
        }
        Command::PrintTrackers { config } => {
            let cfg = load_config(&config)?;
            let raw = read_stdin_bytes()?;
            print_trackers(&raw, &cfg)
        }
        Command::DiffMessage { config } => {
            let cfg = load_config(&config)?;
            let raw = read_stdin_bytes()?;
            diff_message(&raw, &cfg)
        }
        Command::TestRules { dir, config } => {
            let cfg = load_config(&config)?;
            test_rules(&dir, &cfg)
        }
    }
}

fn read_stdin_bytes() -> Result<Vec<u8>, String> {
    let mut raw = Vec::new();
    io::stdin()
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    Ok(raw)
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

/// Pull the sender domain (lower-cased) out of a parsed message's `From:`.
fn message_sender_domain(message: &mail_parser::Message<'_>) -> Option<String> {
    let addr = message.from().and_then(|a| a.first())?.address()?;
    let (_, domain) = addr.rsplit_once('@')?;
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    (!domain.is_empty()).then_some(domain)
}

/// Collect the http(s) unsubscribe targets as a lookup set.
fn unsubscribe_http_set(
    message: &mail_parser::Message<'_>,
) -> std::collections::HashSet<String> {
    email_privacy_cleaner::mime::extract_unsubscribe_urls(message)
        .into_iter()
        .filter(|u| u.starts_with("http://") || u.starts_with("https://"))
        .filter_map(|u| Url::parse(&u).ok().map(|p| p.to_string()))
        .collect()
}

/// Iterate the HTML body parts of a message, yielding each part's HTML.
fn html_parts<'a>(message: &'a mail_parser::Message<'a>) -> Vec<&'a str> {
    let mut out = Vec::new();
    for &id in &message.html_body {
        if let Some(part) = message.part(id) {
            if let mail_parser::PartType::Html(s) = &part.body {
                out.push(s.as_ref());
            }
        }
    }
    out
}

fn parse_message(raw: &[u8]) -> Result<mail_parser::Message<'_>, String> {
    mail_parser::MessageParser::default()
        .parse(raw)
        .ok_or_else(|| "could not parse MIME message".to_string())
}

fn explain_message(raw: &[u8], cfg: &CleanerConfig) -> Result<(), String> {
    let message = parse_message(raw)?;
    let sender = message_sender_domain(&message);
    let (eff, policy) = cfg.effective_for_sender(sender.as_deref());

    println!("sender:   {}", sender.as_deref().unwrap_or("(unknown)"));
    println!("policy:   {}", policy.as_header());
    println!(
        "effective: clean_query_params={} unwrap_redirects={} vendor_rules={} remove_pixels={} mode={}",
        eff.clean_query_params,
        eff.unwrap_known_redirects,
        eff.apply_vendor_rules,
        eff.remove_pixels,
        eff.mode.as_str()
    );

    let unsub = email_privacy_cleaner::mime::extract_unsubscribe_urls(&message);
    if unsub.is_empty() {
        println!("unsubscribe: (none)");
    } else {
        println!("unsubscribe: {}", unsub.join(", "));
    }

    let sensitive = unsubscribe_http_set(&message);

    let parts = html_parts(&message);
    println!("html-parts: {}", parts.len());
    let mut idx = 0;
    for html in parts.iter().copied() {
        for href in email_privacy_cleaner::html::extract_links(html) {
            idx += 1;
            println!("  [{idx}] {href}");
            println!("      -> {}", classify_link(&href, &eff, &sensitive));
        }
    }

    // Report-only pass for the aggregate audit headers / counts.
    let mut report_cfg = (*eff).clone();
    report_cfg.mode = Mode::ReportOnly;
    if let Ok(r) = clean_message_fail_open(raw, &report_cfg) {
        println!(
            "\nwould-clean: urls_cleaned={} redirects_unwrapped={} pixels_removed={}",
            r.stats.urls_cleaned, r.stats.redirects_unwrapped, r.stats.pixels_removed
        );
        println!("audit headers:");
        for (n, v) in &r.audit_headers {
            println!("  {n}: {v}");
        }
    }
    Ok(())
}

/// Produce a one-line description of how a link would be treated.
fn classify_link(
    href: &str,
    cfg: &CleanerConfig,
    sensitive: &std::collections::HashSet<String>,
) -> String {
    let trimmed = href.trim();
    let url = match Url::parse(trimmed) {
        Ok(u) => u,
        Err(_) => return "skip (unparseable / relative)".into(),
    };
    if !matches!(url.scheme(), "http" | "https") {
        return format!("skip (scheme {})", url.scheme());
    }
    if sensitive.contains(url.as_str()) || sensitive.contains(trimmed) {
        return "SENSITIVE (List-Unsubscribe) — left untouched".into();
    }
    if let Some(host) = url.host_str() {
        if cfg.is_blocked_domain(host) {
            return "BLOCKED -> about:blank".into();
        }
    }
    let unwrap = unwrap_redirect_url(&url, cfg);
    if unwrap.unwrapped {
        return format!(
            "UNWRAP [{}] -> {}",
            unwrap.provider.unwrap_or("?"),
            unwrap.url
        );
    }
    if let Some(reason) = &unwrap.rejected {
        return format!(
            "redirect candidate rejected ({}); kept {}",
            reason.label(),
            unwrap.url
        );
    }
    let cleaned = clean_url(&url, cfg);
    if cleaned.changed {
        return format!("CLEAN (stripped {:?}) -> {}", cleaned.removed_params, cleaned.url);
    }
    "unchanged".into()
}

fn print_trackers(raw: &[u8], cfg: &CleanerConfig) -> Result<(), String> {
    let message = parse_message(raw)?;
    let sender = message_sender_domain(&message);
    let (eff, _policy) = cfg.effective_for_sender(sender.as_deref());
    let sensitive = unsubscribe_http_set(&message);

    let mut param_trackers = 0usize;
    let mut wrappers = 0usize;

    for html in html_parts(&message) {
        for href in email_privacy_cleaner::html::extract_links(html) {
            let url = match Url::parse(href.trim()) {
                Ok(u) if matches!(u.scheme(), "http" | "https") => u,
                _ => continue,
            };
            if sensitive.contains(url.as_str()) {
                continue;
            }
            if let Some(p) = email_privacy_cleaner::redirect::detect_provider(&url) {
                wrappers += 1;
                println!("[redirect:{p}] {url}");
            }
            let cleaned = clean_url(&url, &eff);
            if cleaned.changed {
                param_trackers += 1;
                println!("[params] {url}");
                println!("         strips: {:?}", cleaned.removed_params);
            }
        }
    }

    // Pixel detection via a report-only HTML pass count.
    let mut report_cfg = (*eff).clone();
    report_cfg.mode = Mode::ReportOnly;
    let pixels = clean_message_fail_open(raw, &report_cfg)
        .map(|r| r.stats.pixels_removed)
        .unwrap_or(0);

    println!(
        "\nsummary: redirect_wrappers={wrappers} param_tracking_links={param_trackers} tracking_pixels={pixels}"
    );
    Ok(())
}

fn diff_message(raw: &[u8], cfg: &CleanerConfig) -> Result<(), String> {
    let result = clean_message_fail_open(raw, cfg).map_err(|e| e.to_string())?;
    let before = String::from_utf8_lossy(raw);
    let after = String::from_utf8_lossy(&result.cleaned);
    let diff = line_diff(&before, &after);
    if diff.is_empty() {
        println!("(no textual differences)");
    } else {
        print!("{diff}");
    }
    Ok(())
}

/// A minimal, dependency-free line diff: trim the common prefix and suffix of
/// lines, then print the differing middle region as `-`/`+` blocks. Adequate
/// for a debug tool; not a full Myers diff.
fn line_diff(before: &str, after: &str) -> String {
    let a: Vec<&str> = before.lines().collect();
    let b: Vec<&str> = after.lines().collect();

    let mut start = 0;
    while start < a.len() && start < b.len() && a[start] == b[start] {
        start += 1;
    }
    let mut end_a = a.len();
    let mut end_b = b.len();
    while end_a > start && end_b > start && a[end_a - 1] == b[end_b - 1] {
        end_a -= 1;
        end_b -= 1;
    }

    if start == end_a && start == end_b {
        return String::new();
    }

    let mut out = String::new();
    out.push_str(&format!(
        "@@ lines {}..{} (orig) -> {}..{} (cleaned) @@\n",
        start + 1,
        end_a,
        start + 1,
        end_b
    ));
    for line in &a[start..end_a] {
        out.push_str(&format!("- {line}\n"));
    }
    for line in &b[start..end_b] {
        out.push_str(&format!("+ {line}\n"));
    }
    out
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

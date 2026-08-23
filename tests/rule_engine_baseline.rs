//! Deterministic rule-engine baseline diagnostics.
//!
//! This is intentionally an ignored integration test rather than a Criterion
//! benchmark: it adds no dependency or Cargo target, and it keeps the numbers
//! comparable across Rust 1.75 and stable. Run with `--nocapture` to see the
//! three timings. The timings are diagnostic only; correctness assertions make
//! the corpus useful even when wall-clock noise is high.
//!
//! Corpus shape (generated from `SEED`, without random crates):
//! * 48 ClearURLs providers, each with 16 parameter rules;
//! * 2,048 URLs, each queried with one matching and one non-matching name;
//! * one 128-link HTML message for the end-to-end message baseline.
//!
//! Nix invocation from the repository root:
//!
//! ```text
//! nix develop -c cargo test --test rule_engine_baseline -- --ignored --nocapture --test-threads=1
//! ```

use std::hint::black_box;
use std::time::{Duration, Instant};

use email_privacy_cleaner::ruleset::Ruleset;
use email_privacy_cleaner::{clean_message, CleanerConfig};

const SEED: u64 = 0xE11A_2026_0818;
const PROVIDERS: usize = 48;
const RULES_PER_PROVIDER: usize = 16;
const URLS: usize = 2_048;
const MESSAGE_LINKS: usize = 128;

#[derive(Debug)]
struct Lcg(u64);

impl Lcg {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
}

fn synthetic_pack() -> String {
    let mut json = String::from(r#"{"providers":{"#);
    for provider in 0..PROVIDERS {
        if provider != 0 {
            json.push(',');
        }
        json.push_str(&format!(
            r#""provider_{provider:02}":{{"urlPattern":"^https?://site{provider:02}\\.example/","rules":["#
        ));
        for rule in 0..RULES_PER_PROVIDER {
            if rule != 0 {
                json.push(',');
            }
            json.push_str(&format!(r#""trk_{provider:02}_{rule:02}""#));
        }
        json.push_str("]}");
    }
    json.push_str("}}");
    json
}

fn synthetic_urls() -> Vec<(String, String, String)> {
    let mut rng = Lcg::new(SEED);
    (0..URLS)
        .map(|index| {
            let provider = (rng.next() as usize) % PROVIDERS;
            let rule = (rng.next() as usize) % RULES_PER_PROVIDER;
            let path = rng.next() % 10_000;
            (
                format!("https://site{provider:02}.example/path/{path}/{index}"),
                format!("trk_{provider:02}_{rule:02}"),
                format!("ordinary_{index}"),
            )
        })
        .collect()
}

fn baseline_message() -> Vec<u8> {
    let mut html = String::from("<html><body>");
    for index in 0..MESSAGE_LINKS {
        html.push_str(&format!(
            r#"<a href="https://news.example/item/{index}?utm_source=baseline&id={index}">item</a>"#
        ));
    }
    html.push_str("</body></html>");
    format!(
        "From: baseline@example.test\r\nTo: recipient@example.test\r\nContent-Type: text/html; charset=utf-8\r\n\r\n{html}"
    )
    .into_bytes()
}

fn print_timing(label: &str, elapsed: Duration, work: usize) {
    println!(
        "rule_engine_baseline {label} elapsed_us={} work={work}",
        elapsed.as_micros()
    );
}

#[test]
#[ignore = "diagnostic baseline; run explicitly with --ignored --nocapture"]
fn deterministic_build_match_message_baseline() {
    let pack = synthetic_pack();
    let urls = synthetic_urls();

    let started = Instant::now();
    let ruleset = Ruleset::from_clearurls_str(black_box(&pack)).expect("synthetic pack parses");
    let build_time = started.elapsed();
    assert_eq!(ruleset.provider_count(), PROVIDERS);
    print_timing(
        "build",
        build_time,
        ruleset.provider_count() * RULES_PER_PROVIDER,
    );

    let started = Instant::now();
    let mut matches = 0;
    for (url, matching_name, ordinary_name) in &urls {
        matches += usize::from(ruleset.param_is_tracking(url, matching_name, true, false));
        matches += if !ruleset.param_is_tracking(url, ordinary_name, true, false) {
            1
        } else {
            0
        };
    }
    let match_time = started.elapsed();
    assert_eq!(matches, URLS * 2);
    print_timing("match", match_time, matches);

    let mut config = CleanerConfig::default();
    config.preserve_original_href = false;
    config.finalize();
    let message = baseline_message();
    let started = Instant::now();
    let result = clean_message(black_box(&message), &config).expect("baseline message cleans");
    let message_time = started.elapsed();
    assert_eq!(result.stats.html_parts, 1);
    assert_eq!(result.stats.urls_cleaned, MESSAGE_LINKS);
    assert!(result.modified);
    print_timing("message", message_time, result.stats.urls_cleaned);
}

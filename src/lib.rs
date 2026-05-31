//! # email_privacy_cleaner
//!
//! A reusable library for sanitising the privacy-invasive parts of email
//! messages, designed to run as a pre-queue milter for the
//! [Stalwart](https://stalw.art) mail server (but usable standalone).
//!
//! It performs three independent, deterministic, **offline** transformations:
//!
//! 1. **Tracking-pixel removal** from HTML bodies (1×1 / hidden / known beacon
//!    hosts).
//! 2. **Tracking query-parameter stripping** (`utm_*`, `fbclid`, `gclid`, …).
//! 3. **First-stage ESP redirect unwrapping** (SendGrid, Mailchimp, HubSpot, …)
//!    — only when the destination is explicitly embedded and validates.
//!
//! An optional, opt-in network redirect resolver exists behind the `network`
//! cargo feature; it is disabled by default and heavily SSRF-guarded.
//!
//! ## Public API
//!
//! * [`clean_message`] — sanitise a full RFC 5322 message.
//! * [`clean_html`] — sanitise a single HTML fragment/body.
//! * [`clean_url`] — strip tracking query params from one URL.
//! * [`unwrap_redirect_url`] — offline ESP redirect unwrapping for one URL.

pub mod config;
pub mod encoding;
pub mod error;
pub mod html;
pub mod milter;
pub mod mime;
pub mod network;
pub mod redirect;
pub mod ruleset;
pub mod url_clean;
pub mod validate;

// ---- Primary public surface (as specified) ----
pub use config::{CleanerConfig, Mode, PolicyLabel, SenderPolicy};
pub use error::{CleanerError, Result};
pub use html::{clean_html, HtmlCleanResult};
pub use mime::{clean_message, CleanStats, CleanerResult};
pub use redirect::{unwrap_redirect_url, RedirectUnwrapResult};
pub use ruleset::Ruleset;
pub use url_clean::{clean_url, UrlCleanResult};
pub use validate::RejectReason;

/// Crate version string, e.g. `"0.1.0"`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Clean a message, applying fail-open semantics from the config.
///
/// On a hard parser/internal error:
/// * if `config.fail_open` is `true`, returns the **original** message with an
///   `X-Privacy-Cleaner-Error` (and a minimal set of audit headers) added, and
///   `Ok(result)` with `result.error = Some(_)`;
/// * if `config.fail_open` is `false`, propagates the `Err` so the caller can
///   tempfail.
pub fn clean_message_fail_open(raw: &[u8], config: &CleanerConfig) -> Result<CleanerResult> {
    match clean_message(raw, config) {
        Ok(r) => Ok(r),
        Err(e) => {
            if config.fail_open {
                Ok(fail_open_result(raw, config, &e))
            } else {
                Err(e)
            }
        }
    }
}

/// Build a passthrough result that returns the original message untouched, plus
/// the audit headers and an `X-Privacy-Cleaner-Error` header.
pub fn fail_open_result(raw: &[u8], config: &CleanerConfig, err: &CleanerError) -> CleanerResult {
    let line_ending: Vec<u8> = if raw
        .iter()
        .position(|&b| b == b'\n')
        .map(|p| p > 0 && raw[p - 1] == b'\r')
        .unwrap_or(true)
    {
        b"\r\n".to_vec()
    } else {
        b"\n".to_vec()
    };

    let mut audit_headers = mime::build_audit_headers(&CleanStats::default(), config.mode, false);
    audit_headers.push((
        "X-Privacy-Cleaner-Error".into(),
        short_error(&err.to_string()),
    ));
    // Defensive: strip control bytes from every value before they're written
    // into the header block.
    for (_, v) in audit_headers.iter_mut() {
        if v.chars().any(|c| c.is_control()) {
            *v = v
                .chars()
                .map(|c| if c.is_control() { ' ' } else { c })
                .collect();
        }
    }

    // For passthrough we keep the body as-is and emit the original message with
    // headers appended (best-effort). We don't attempt MIME surgery here.
    let split = header_body_split(raw, &line_ending);
    let body = raw[split.min(raw.len())..].to_vec();
    let cleaned = insert_headers_simple(raw, split, &audit_headers, &line_ending);

    CleanerResult {
        cleaned,
        body,
        audit_headers,
        stats: CleanStats::default(),
        modified: false,
        mode: config.mode,
        error: Some(short_error(&err.to_string())),
    }
}

/// Sanitise an error string into a short, header-safe value.
fn short_error(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let cleaned = cleaned.trim();
    if cleaned.len() > 120 {
        cleaned.chars().take(120).collect()
    } else {
        cleaned.to_string()
    }
}

/// Find the byte offset where the body begins (just after the header block's
/// terminating blank line). Falls back to `raw.len()` for header-only input.
fn header_body_split(raw: &[u8], line_ending: &[u8]) -> usize {
    let sep: Vec<u8> = [line_ending, line_ending].concat();
    if let Some(pos) = find_subslice(raw, &sep) {
        pos + sep.len()
    } else if let Some(pos) = find_subslice(raw, b"\n\n") {
        pos + 2
    } else {
        raw.len()
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn insert_headers_simple(
    raw: &[u8],
    split: usize,
    headers: &[(String, String)],
    line_ending: &[u8],
) -> Vec<u8> {
    let le_len = line_ending.len();
    let mut block = Vec::new();
    for (name, value) in headers {
        block.extend_from_slice(name.as_bytes());
        block.extend_from_slice(b": ");
        block.extend_from_slice(value.as_bytes());
        block.extend_from_slice(line_ending);
    }
    let insert_at = if split >= le_len && &raw[split - le_len..split] == line_ending {
        split - le_len
    } else {
        split.min(raw.len())
    };
    let mut out = Vec::with_capacity(raw.len() + block.len());
    out.extend_from_slice(&raw[..insert_at]);
    out.extend_from_slice(&block);
    out.extend_from_slice(&raw[insert_at..]);
    out
}

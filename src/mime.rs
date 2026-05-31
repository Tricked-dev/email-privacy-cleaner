//! MIME message traversal and surgical body rewriting.
//!
//! Strategy: parse with `mail-parser`, then perform **byte-surgical**
//! replacement of only the body bytes of the `text/html` (and optionally
//! `text/plain`) body parts, using the byte offsets `mail-parser` records for
//! each part. Everything else — headers, boundaries, attachments, nested
//! parts — is preserved verbatim. This keeps the change minimal and avoids
//! re-serialising (and thus mangling) the whole message.

use std::collections::HashSet;

use mail_parser::{Message, MessageParser, MimeHeaders, PartType};
use url::Url;

use crate::config::{CleanerConfig, Mode};
use crate::encoding::{encode_body, reencode_charset};
use crate::error::{CleanerError, Result};
use crate::html::{clean_html_ctx, LinkContext};
use crate::url_clean::clean_url;

/// Per-message statistics gathered while cleaning.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CleanStats {
    /// Number of HTML body parts examined.
    pub html_parts: usize,
    /// Total tracking-cleaned URLs across all parts.
    pub urls_cleaned: usize,
    /// Total redirect links unwrapped.
    pub redirects_unwrapped: usize,
    /// Total tracking pixels removed (including CSS background beacons).
    pub pixels_removed: usize,
    /// Total hyperlink-auditing `ping` attributes stripped.
    pub pings_stripped: usize,
}

/// Result of [`clean_message`](crate::clean_message).
#[derive(Debug, Clone)]
pub struct CleanerResult {
    /// The full cleaned message, including the injected audit headers. Suitable
    /// for the CLI `clean-message` output.
    pub cleaned: Vec<u8>,
    /// Just the body region (everything after the top-level header block),
    /// reflecting any body modifications but **without** the audit headers.
    /// Used by the milter for `SMFIR_REPLBODY`.
    pub body: Vec<u8>,
    /// The audit headers added (name, value), in order. Used by the milter for
    /// `SMFIR_ADDHEADER`.
    pub audit_headers: Vec<(String, String)>,
    /// Statistics.
    pub stats: CleanStats,
    /// Whether the body was actually modified (always `false` in report-only).
    pub modified: bool,
    /// Effective mode.
    pub mode: Mode,
    /// Set only on fail-open; surfaced as `X-Privacy-Cleaner-Error`.
    pub error: Option<String>,
}

struct Replacement {
    start: usize,
    end: usize,
    bytes: Vec<u8>,
}

/// Clean a raw RFC 5322 message.
pub fn clean_message(raw: &[u8], config: &CleanerConfig) -> Result<CleanerResult> {
    if raw.len() > config.max_message_size {
        return Err(CleanerError::MessageTooLarge {
            size: raw.len(),
            limit: config.max_message_size,
        });
    }

    let message = MessageParser::default()
        .parse(raw)
        .ok_or(CleanerError::MimeParse)?;

    // Resolve the effective configuration for this sender (per-sender policy +
    // built-in sensitive-sender protection).
    let sender_domain = sender_domain(&message);
    let (eff, policy) = config.effective_for_sender(sender_domain.as_deref());
    let eff: &CleanerConfig = &eff;

    // Links that must never be rewritten (List-Unsubscribe targets carry
    // recipient-specific tokens).
    let unsubscribe_urls = extract_unsubscribe_urls(&message);
    let sensitive: HashSet<String> = unsubscribe_urls
        .iter()
        .filter(|u| u.starts_with("http://") || u.starts_with("https://"))
        .filter_map(|u| Url::parse(u).ok().map(|p| p.to_string()))
        .collect();
    let link_ctx = LinkContext {
        sensitive_urls: if sensitive.is_empty() {
            None
        } else {
            Some(&sensitive)
        },
    };

    let line_ending = detect_line_ending(raw);
    let mut stats = CleanStats::default();
    let mut replacements: Vec<Replacement> = Vec::new();
    // Parts we silently skipped because they exceeded `max_html_part_size`. We
    // surface this in an audit header so a deployment can tell "I saw nothing
    // to clean" apart from "I saw a giant part I refused to touch".
    let mut skipped_oversized_parts: usize = 0;
    // mail-parser can list the same part id in both `html_body` and
    // `text_body` (e.g. a single text/html part used as the only body). Track
    // ids we've already produced a replacement for so we never queue two
    // overlapping splices for the same byte range.
    let mut processed_parts: HashSet<u32> = HashSet::new();

    // ---- HTML body parts ----
    if eff.clean_html {
        for &part_id in &message.html_body {
            let part = match message.part(part_id) {
                Some(p) => p,
                None => continue,
            };
            let html = match &part.body {
                PartType::Html(s) => s.as_ref(),
                // text_body fallback may list a Text part as the "html" body;
                // only treat genuine HTML here.
                _ => continue,
            };
            stats.html_parts += 1;

            if html.len() > eff.max_html_part_size {
                skipped_oversized_parts += 1;
                continue;
            }

            let res = clean_html_ctx(html, None, eff, &link_ctx)?;
            stats.urls_cleaned += res.urls_cleaned;
            stats.redirects_unwrapped += res.redirects_unwrapped;
            stats.pixels_removed += res.pixels_removed;
            stats.pings_stripped += res.pings_stripped;

            if eff.mode.is_enforce() && res.changed {
                if let Some(rep) = build_replacement(raw, part, res.html.as_bytes(), &line_ending) {
                    processed_parts.insert(part_id);
                    replacements.push(rep);
                }
            }
        }
    }

    // ---- text/plain parts (query-param cleaning only) ----
    if eff.clean_text_plain {
        for &part_id in &message.text_body {
            if processed_parts.contains(&part_id) {
                continue;
            }
            let part = match message.part(part_id) {
                Some(p) => p,
                None => continue,
            };
            let text = match &part.body {
                PartType::Text(s) => s.as_ref(),
                _ => continue,
            };
            let (new_text, n) = clean_text_urls(text, eff);
            stats.urls_cleaned += n;
            if eff.mode.is_enforce() && n > 0 {
                if let Some(rep) = build_replacement(raw, part, new_text.as_bytes(), &line_ending) {
                    processed_parts.insert(part_id);
                    replacements.push(rep);
                }
            }
        }
    }

    // ---- Apply body replacements (descending offset) ----
    let modified = !replacements.is_empty();
    let mut full = raw.to_vec();
    replacements.sort_by_key(|r| std::cmp::Reverse(r.start));
    for rep in &replacements {
        if rep.start <= rep.end && rep.end <= full.len() {
            full.splice(rep.start..rep.end, rep.bytes.iter().copied());
        }
    }

    // Top-level header/body split (unchanged by body edits, which all occur at
    // offsets >= split).
    let split = message.root_part().offset_body as usize;
    let split = split.min(full.len());

    let body = full[split..].to_vec();

    // ---- Audit headers ----
    let mut audit_headers = build_audit_headers(&stats, eff.mode, modified);
    audit_headers.push(("X-Privacy-Cleaner-Policy".into(), policy.as_header()));
    if skipped_oversized_parts > 0 {
        audit_headers.push((
            "X-Privacy-Cleaner-Skipped-Oversized-Parts".into(),
            skipped_oversized_parts.to_string(),
        ));
    }
    if eff.surface_unsubscribe {
        if let Some(url) = preferred_unsubscribe(&unsubscribe_urls) {
            // Canonicalise through Url::parse so an attacker-supplied (or
            // unusually-folded) value can't smuggle CR/LF or other control
            // bytes into the emitted header. A value that doesn't round-trip
            // cleanly through Url::parse is silently dropped.
            if let Some(safe) = canonicalize_unsubscribe(&url) {
                audit_headers.push(("X-Privacy-Cleaner-Unsubscribe".into(), safe));
            }
        }
    }
    // Final hardening: strip any control characters that could otherwise let an
    // arbitrary header value (e.g. a future audit field) split into multiple
    // headers when serialised.
    for (_, v) in audit_headers.iter_mut() {
        sanitize_header_value_in_place(v);
    }

    // ---- Full cleaned message with audit headers inserted ----
    let cleaned = insert_headers(&full, split, &audit_headers, &line_ending);

    Ok(CleanerResult {
        cleaned,
        body,
        audit_headers,
        stats,
        modified,
        mode: eff.mode,
        error: None,
    })
}

/// Extract the sender domain (lower-cased) from the message `From:` header.
fn sender_domain(message: &Message<'_>) -> Option<String> {
    let addr = message.from().and_then(|a| a.first())?.address()?;
    let (_, domain) = addr.rsplit_once('@')?;
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty() {
        None
    } else {
        Some(domain)
    }
}

/// Extract the bracketed targets of the `List-Unsubscribe` header, in order.
/// Returns the raw `<...>` contents (e.g. `https://…`, `mailto:…`).
pub fn extract_unsubscribe_urls(message: &Message<'_>) -> Vec<String> {
    let raw = match message.header_raw("List-Unsubscribe") {
        Some(s) => s,
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    let mut rest = raw;
    while let Some(open) = rest.find('<') {
        let after = &rest[open + 1..];
        match after.find('>') {
            Some(close) => {
                let url = after[..close].trim();
                if !url.is_empty() {
                    out.push(url.to_string());
                }
                rest = &after[close + 1..];
            }
            None => break,
        }
    }
    out
}

/// Pick the unsubscribe URL to surface: prefer an HTTP(S) one, else the first.
fn preferred_unsubscribe(urls: &[String]) -> Option<String> {
    urls.iter()
        .find(|u| u.starts_with("http://") || u.starts_with("https://"))
        .or_else(|| urls.first())
        .cloned()
}

/// Build the standard audit headers.
pub fn build_audit_headers(
    stats: &CleanStats,
    mode: Mode,
    modified: bool,
) -> Vec<(String, String)> {
    vec![
        (
            "X-Privacy-Cleaner".into(),
            format!("email-privacy-cleaner/{}", env!("CARGO_PKG_VERSION")),
        ),
        ("X-Privacy-Cleaner-Mode".into(), mode.as_str().into()),
        (
            "X-Privacy-Cleaner-HTML-Parts".into(),
            stats.html_parts.to_string(),
        ),
        (
            "X-Privacy-Cleaner-URLs-Cleaned".into(),
            stats.urls_cleaned.to_string(),
        ),
        (
            "X-Privacy-Cleaner-Redirects-Unwrapped".into(),
            stats.redirects_unwrapped.to_string(),
        ),
        (
            "X-Privacy-Cleaner-Pixels-Removed".into(),
            stats.pixels_removed.to_string(),
        ),
        (
            "X-Privacy-Cleaner-Link-Pings-Stripped".into(),
            stats.pings_stripped.to_string(),
        ),
        (
            "X-Privacy-Cleaner-Body-Modified".into(),
            if modified { "yes" } else { "no" }.into(),
        ),
    ]
}

/// Construct a body-byte replacement for `part`, re-encoding `new_content`
/// (UTF-8) into the part's declared charset + content-transfer-encoding, and
/// preserving the part's original trailing newline(s) so MIME boundaries stay
/// aligned.
fn build_replacement(
    raw: &[u8],
    part: &mail_parser::MessagePart,
    new_content: &[u8],
    line_ending: &[u8],
) -> Option<Replacement> {
    let start = part.offset_body as usize;
    let end = part.offset_end as usize;
    if start > end || end > raw.len() {
        return None;
    }
    let original_slice = &raw[start..end];

    // Charset of the part (defaults to utf-8).
    let charset: Option<String> = part
        .content_type()
        .and_then(|ct| ct.attribute("charset"))
        .map(|s| s.to_string());

    // new_content is UTF-8 (from clean_html / text cleaning). Re-encode to the
    // declared charset first.
    let charset_bytes = match std::str::from_utf8(new_content) {
        Ok(s) => reencode_charset(s, charset.as_deref())?,
        Err(_) => new_content.to_vec(),
    };

    let encoded = encode_body(&charset_bytes, part.encoding, line_ending);

    // When the part's Content-Transfer-Encoding is none (i.e. it was declared
    // 7bit/8bit/binary, which `mail-parser` collapses into `Encoding::None`),
    // we cannot upgrade the declaration. Refuse to introduce high bytes into a
    // part that originally had none — the resulting message would advertise
    // 7bit and contain non-7bit bytes, breaking strict downstream parsers and
    // DKIM expectations. If the original slice already contained high bytes,
    // the message was already 8bit-in-7bit-clothing and we're not making it
    // worse.
    if matches!(part.encoding, mail_parser::Encoding::None) {
        let original_has_high = original_slice.iter().any(|&b| b >= 0x80);
        let encoded_has_high = encoded.iter().any(|&b| b >= 0x80);
        if encoded_has_high && !original_has_high {
            return None;
        }
    }

    // Preserve the original trailing newline sequence.
    let trailing = trailing_newlines(original_slice);
    let mut bytes = strip_trailing_newlines(&encoded);
    bytes.extend_from_slice(trailing);

    Some(Replacement { start, end, bytes })
}

/// Returns the trailing run of CR/LF bytes of `slice`.
fn trailing_newlines(slice: &[u8]) -> &[u8] {
    let mut i = slice.len();
    while i > 0 && (slice[i - 1] == b'\n' || slice[i - 1] == b'\r') {
        i -= 1;
    }
    &slice[i..]
}

fn strip_trailing_newlines(slice: &[u8]) -> Vec<u8> {
    let t = trailing_newlines(slice);
    slice[..slice.len() - t.len()].to_vec()
}

/// Detect whether the message uses CRLF or bare LF line endings.
fn detect_line_ending(raw: &[u8]) -> Vec<u8> {
    if let Some(pos) = raw.iter().position(|&b| b == b'\n') {
        if pos > 0 && raw[pos - 1] == b'\r' {
            return b"\r\n".to_vec();
        }
        return b"\n".to_vec();
    }
    b"\r\n".to_vec()
}

/// Insert header lines into the message's top-level header block, immediately
/// before the terminating blank line.
fn insert_headers(
    full: &[u8],
    split: usize,
    headers: &[(String, String)],
    line_ending: &[u8],
) -> Vec<u8> {
    let le = line_ending;
    let le_len = le.len();

    let mut block = Vec::new();
    for (name, value) in headers {
        block.extend_from_slice(name.as_bytes());
        block.extend_from_slice(b": ");
        block.extend_from_slice(value.as_bytes());
        block.extend_from_slice(le);
    }

    // The header block normally ends with a blank line: ...lastheader<le><le>.
    // Insert our headers right before that final <le> (the empty line).
    let insert_at = if split >= le_len && &full[split - le_len..split] == le {
        split - le_len
    } else {
        // No recognisable terminator (e.g. headers-only message): just put our
        // headers at the split point.
        split.min(full.len())
    };

    let mut out = Vec::with_capacity(full.len() + block.len());
    out.extend_from_slice(&full[..insert_at]);
    out.extend_from_slice(&block);
    out.extend_from_slice(&full[insert_at..]);
    out
}

/// Conservative URL query-param cleaning inside a plain-text body.
///
/// Only obvious `http(s)://` tokens are touched; everything else is preserved.
fn clean_text_urls(text: &str, config: &CleanerConfig) -> (String, usize) {
    let mut out = String::with_capacity(text.len());
    let mut count = 0usize;
    let bytes = text.as_bytes();
    let mut i = 0;

    while i < text.len() {
        let rest = &text[i..];
        if rest.starts_with("http://") || rest.starts_with("https://") {
            // Capture up to the first whitespace or URL-terminating char.
            let end = rest
                .find(|c: char| {
                    c.is_whitespace() || matches!(c, '<' | '>' | '"' | '\'' | ')' | ']')
                })
                .unwrap_or(rest.len());
            // Trim common trailing punctuation.
            let mut token = &rest[..end];
            while let Some(last) = token.chars().last() {
                if matches!(last, '.' | ',' | ';' | ':' | '!' | '?') {
                    token = &token[..token.len() - last.len_utf8()];
                } else {
                    break;
                }
            }
            if let Ok(url) = Url::parse(token) {
                let r = clean_url(&url, config);
                if r.changed {
                    out.push_str(r.url.as_str());
                    count += 1;
                } else {
                    out.push_str(token);
                }
            } else {
                out.push_str(token);
            }
            i += token.len();
        } else {
            // Advance one char.
            let ch_len = utf8_char_len(bytes[i]);
            out.push_str(&text[i..i + ch_len]);
            i += ch_len;
        }
    }
    (out, count)
}

/// Strip any CR/LF/NUL/other control bytes from a header value in place. The
/// SMTP/MIME header grammar forbids these inside a field-body, so removing
/// them is always safe and cannot affect a legitimate value.
fn sanitize_header_value_in_place(v: &mut String) {
    if !v.chars().any(|c| c.is_control()) {
        return;
    }
    let cleaned: String = v
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    *v = cleaned;
}

/// Canonicalise an unsubscribe URL through `Url::parse`. Returns `None` if the
/// value isn't a valid http(s) URL — we don't want to surface arbitrary
/// non-URL content (or unfolded raw bytes) in an `X-Privacy-Cleaner-*` header.
fn canonicalize_unsubscribe(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let parsed = Url::parse(trimmed).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }
    let s = parsed.to_string();
    if s.chars().any(|c| c.is_control()) {
        return None;
    }
    Some(s)
}

fn utf8_char_len(b: u8) -> usize {
    if b < 0x80 {
        1
    } else if b >> 5 == 0b110 {
        2
    } else if b >> 4 == 0b1110 {
        3
    } else if b >> 3 == 0b11110 {
        4
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> CleanerConfig {
        let mut c = CleanerConfig::default();
        c.finalize();
        c
    }

    #[test]
    fn clean_text_urls_strips_params() {
        let (out, n) = clean_text_urls("Visit https://e.com/p?utm_source=x&id=1 today.", &cfg());
        assert_eq!(n, 1);
        assert!(out.contains("https://e.com/p?id=1"));
        assert!(!out.contains("utm_source"));
        assert!(out.ends_with("today."));
    }

    #[test]
    fn detect_line_ending_works() {
        assert_eq!(detect_line_ending(b"a: b\r\n\r\nbody"), b"\r\n");
        assert_eq!(detect_line_ending(b"a: b\n\nbody"), b"\n");
    }

    #[test]
    fn canonicalize_unsubscribe_drops_bad_inputs() {
        assert!(canonicalize_unsubscribe("not a url").is_none());
        assert!(canonicalize_unsubscribe("mailto:abuse@x.example").is_none());
        // Embedded CR/LF in a value that would otherwise parse — the URL
        // parser may or may not accept it depending on placement, but a CR/LF
        // in the output is always rejected by the control-char check.
        let evil = "https://x.example/u?id=1\r\nX-Injected: yes";
        if let Some(s) = canonicalize_unsubscribe(evil) {
            assert!(!s.contains('\r') && !s.contains('\n'));
        }
    }

    #[test]
    fn sanitize_header_value_replaces_controls() {
        let mut v = String::from("ok value\r\nX-Injected: yes");
        sanitize_header_value_in_place(&mut v);
        assert!(!v.contains('\r'));
        assert!(!v.contains('\n'));
        assert!(v.contains("X-Injected: yes"));
    }
}

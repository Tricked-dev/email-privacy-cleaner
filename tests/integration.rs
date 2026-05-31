//! Fixture- and scenario-based integration tests for `clean_message`.
//!
//! File fixtures live under `tests/fixtures/*.eml`. Encoding-sensitive cases
//! (quoted-printable, base64, non-UTF-8 charset, nested URL-encoding, malicious
//! and private-IP redirects) are constructed inline so the test has byte-exact
//! control over the input.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use email_privacy_cleaner::{clean_message, CleanerConfig, Mode};
use mail_parser::{MessageParser, PartType};

/// Default test config. We turn *off* `preserve_original_href` so that
/// "tracker is gone" assertions can simply check the whole HTML body; the
/// preservation feature is covered separately by
/// [`preserve_original_href_keeps_source`].
fn cfg() -> CleanerConfig {
    let mut c = CleanerConfig::default();
    c.preserve_original_href = false;
    c.finalize();
    c
}

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(path).unwrap_or_else(|e| panic!("reading fixture {name}: {e}"))
}

/// Re-parse cleaned output and return the first HTML body as a decoded string.
fn html_body_of(raw: &[u8]) -> String {
    let msg = MessageParser::default().parse(raw).expect("re-parse");
    for &id in &msg.html_body {
        if let Some(p) = msg.part(id) {
            if let PartType::Html(s) = &p.body {
                return s.to_string();
            }
        }
    }
    String::new()
}

fn as_str(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw).into_owned()
}

#[test]
fn multipart_alternative_cleans_html_keeps_structure() {
    let raw = fixture("multipart_alternative.eml");
    let r = clean_message(&raw, &cfg()).unwrap();

    // One HTML part examined, pixel removed, link cleaned.
    assert_eq!(r.stats.html_parts, 1);
    assert_eq!(r.stats.pixels_removed, 1, "1x1 open.gif should be removed");
    assert!(r.stats.urls_cleaned >= 1);
    assert!(r.modified);

    let html = html_body_of(&r.cleaned);
    assert!(!html.contains("open.gif"), "tracking pixel must be gone");
    assert!(html.contains("logo.png"), "legit logo must remain");
    // utm params stripped from the live href (original preserved separately).
    assert!(html.contains(r#"href="https://shop.acme.example/article?id=5""#));

    // Structure preserved: boundary + both parts still present.
    let full = as_str(&r.cleaned);
    assert!(full.contains("--=_boundary_alt_42--"));
    assert!(full.contains("text/plain"));
    // text/plain untouched by default (clean_text_plain = false).
    assert!(full.contains("utm_source=newsletter"));

    // Top-level headers preserved.
    assert!(full.contains("Subject: Your weekly digest"));
    assert!(full.contains("Message-ID: <abc123@acme.example>"));

    // Audit headers present.
    assert!(full.contains("X-Privacy-Cleaner: email-privacy-cleaner/"));
    assert!(full.contains("X-Privacy-Cleaner-Pixels-Removed: 1"));
    assert!(full.contains("X-Privacy-Cleaner-Mode: enforce"));
    assert!(full.contains("X-Privacy-Cleaner-Body-Modified: yes"));
}

#[test]
fn sendgrid_links_are_unwrapped() {
    let raw = fixture("sendgrid.eml");
    let r = clean_message(&raw, &cfg()).unwrap();
    assert_eq!(r.stats.redirects_unwrapped, 1);
    let html = html_body_of(&r.cleaned);
    assert!(
        html.contains(r#"href="https://www.example.com/deals""#),
        "got: {html}"
    );
    assert!(!html.contains("ct.sendgrid.net"));
    assert!(!html.contains("utm_source"));
}

#[test]
fn hubspot_links_unwrapped_and_params_cleaned() {
    let raw = fixture("hubspot.eml");
    let r = clean_message(&raw, &cfg()).unwrap();
    let html = html_body_of(&r.cleaned);
    // Wrapped link unwrapped to the blog post with _hsenc/_hsmi stripped.
    assert!(html.contains("https://blog.brand.example/post"));
    assert!(!html.contains("_hsenc"));
    assert!(!html.contains("_hsmi"));
    // The direct link keeps its non-tracking id but loses _hsenc/_hsmi.
    assert!(html.contains("id=7"));
    assert!(r.stats.redirects_unwrapped >= 1);
}

#[test]
fn mailchimp_without_destination_only_strips_params() {
    let raw = fixture("mailchimp.eml");
    let r = clean_message(&raw, &cfg()).unwrap();
    // No destination embedded -> not unwrapped, but mc_cid/mc_eid removed.
    assert_eq!(r.stats.redirects_unwrapped, 0);
    let html = html_body_of(&r.cleaned);
    assert!(!html.contains("mc_cid"));
    assert!(!html.contains("mc_eid"));
    assert!(html.contains("list-manage.com/track/click"));
    assert!(html.contains("u=abc123"));
}

#[test]
fn tracking_pixels_removed_logo_kept() {
    let raw = fixture("tracking_pixel.eml");
    let r = clean_message(&raw, &cfg()).unwrap();
    // o.gif (1x1) + beacon (display:none) + doubleclick (known host) = 3.
    assert_eq!(r.stats.pixels_removed, 3);
    let html = html_body_of(&r.cleaned);
    assert!(!html.contains("o.gif"));
    assert!(!html.contains("beacon.example.com"));
    assert!(!html.contains("doubleclick.net"));
    assert!(html.contains("hero.jpg"), "600x200 hero must remain");
}

#[test]
fn legit_logo_not_removed() {
    let raw = fixture("logo.eml");
    let r = clean_message(&raw, &cfg()).unwrap();
    assert_eq!(r.stats.pixels_removed, 0);
    let html = html_body_of(&r.cleaned);
    assert!(html.contains("logo.png"));
    assert!(html.contains("avatar.png"));
}

#[test]
fn magic_login_link_not_broken() {
    let raw = fixture("magic_login.eml");
    let r = clean_message(&raw, &cfg()).unwrap();
    assert_eq!(r.stats.urls_cleaned, 0);
    assert_eq!(r.stats.redirects_unwrapped, 0);
    assert!(!r.modified, "no tracking content -> body unchanged");
    let html = html_body_of(&r.cleaned);
    assert!(html.contains("token=eyJhbGciOiJIUzI1NiationABC.DEF.GHI"));
    assert!(html.contains("expires=1748700000"));
    assert!(!html.contains("data-original-href"));
}

#[test]
fn malformed_html_is_handled() {
    let raw = fixture("malformed_html.eml");
    let r = clean_message(&raw, &cfg()).unwrap();
    // Should not error; tolerant parser still strips the tracker + tiny pixel.
    let html = html_body_of(&r.cleaned);
    assert!(html.contains(r#"href="https://e.example/?keep=1""#) || html.contains("keep=1"));
    assert!(!html.contains("x.gif"));
}

#[test]
fn quoted_printable_html_part() {
    let html = r#"<html><body><a href="https://e.example/p?id=1&utm_id=9">x</a><img src="https://t.example.net/o.gif" width="1" height="1" alt=""></body></html>"#;
    let qp = quoted_printable::encode(html.as_bytes());
    let mut raw = Vec::new();
    raw.extend_from_slice(
        b"From: a@b.example\r\nTo: c@d.example\r\nSubject: qp\r\nMIME-Version: 1.0\r\n",
    );
    raw.extend_from_slice(b"Content-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n");
    raw.extend_from_slice(&qp);
    raw.extend_from_slice(b"\r\n");

    let r = clean_message(&raw, &cfg()).unwrap();
    assert!(r.modified);
    assert_eq!(r.stats.pixels_removed, 1);

    // The cleaned part must still be quoted-printable-decodable to clean HTML.
    let html_out = html_body_of(&r.cleaned);
    assert!(!html_out.contains("o.gif"));
    assert!(!html_out.contains("utm_id"));
    assert!(html_out.contains("href=\"https://e.example/p?id=1\""));
    // CTE header preserved.
    assert!(as_str(&r.cleaned).contains("quoted-printable"));
}

#[test]
fn base64_html_part() {
    let html = r#"<html><body><img src="https://t.example.net/o.gif" width="1" height="1" alt=""><a href="https://e.example/?utm_source=x&y=2">go</a></body></html>"#;
    let b64 = STANDARD.encode(html.as_bytes());
    let mut raw = Vec::new();
    raw.extend_from_slice(b"From: a@b.example\r\nSubject: b64\r\nMIME-Version: 1.0\r\n");
    raw.extend_from_slice(
        b"Content-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n",
    );
    raw.extend_from_slice(b64.as_bytes());
    raw.extend_from_slice(b"\r\n");

    let r = clean_message(&raw, &cfg()).unwrap();
    assert!(r.modified);
    assert_eq!(r.stats.pixels_removed, 1);
    let html_out = html_body_of(&r.cleaned);
    assert!(!html_out.contains("o.gif"));
    assert!(!html_out.contains("utm_source"));
    assert!(html_out.contains("y=2"));
    assert!(as_str(&r.cleaned).contains("base64"));
}

#[test]
fn non_utf8_charset_iso_8859_1() {
    // Body is ISO-8859-1: 0xE9 is 'é'. Includes a tracking link to strip.
    let mut body = Vec::new();
    body.extend_from_slice(b"<html><body><p>Caf");
    body.push(0xE9); // é in latin-1
    body.extend_from_slice(
        br#"</p><a href="https://e.example/p?id=1&utm_source=news">x</a></body></html>"#,
    );

    let mut raw = Vec::new();
    raw.extend_from_slice(b"From: a@b.example\r\nSubject: latin1\r\nMIME-Version: 1.0\r\n");
    raw.extend_from_slice(
        b"Content-Type: text/html; charset=iso-8859-1\r\nContent-Transfer-Encoding: 7bit\r\n\r\n",
    );
    raw.extend_from_slice(&body);
    raw.extend_from_slice(b"\r\n");

    let r = clean_message(&raw, &cfg()).unwrap();
    assert!(r.modified);
    // The é byte must still be a single 0xE9 latin-1 byte (not UTF-8 0xC3 0xA9).
    assert!(r.cleaned.windows(1).any(|w| w == [0xE9]));
    assert!(!r.cleaned.windows(2).any(|w| w == [0xC3, 0xA9]));
    // Tracking param removed.
    assert!(!as_str(&r.cleaned).contains("utm_source"));
    // charset header preserved.
    assert!(as_str(&r.cleaned).contains("iso-8859-1"));
}

#[test]
fn nested_url_encoding_in_html() {
    // SparkPost-style link with a double-encoded destination inside HTML.
    let html = r#"<html><body><a href="https://links.spgo.io/x?url=https%253A%252F%252Fexample.com%252Fp%253Futm_id%253D5">link</a></body></html>"#;
    let mut raw = Vec::new();
    raw.extend_from_slice(b"From: a@b.example\r\nSubject: nested\r\nMIME-Version: 1.0\r\n");
    raw.extend_from_slice(b"Content-Type: text/html; charset=utf-8\r\n\r\n");
    raw.extend_from_slice(html.as_bytes());
    raw.extend_from_slice(b"\r\n");

    let r = clean_message(&raw, &cfg()).unwrap();
    assert_eq!(r.stats.redirects_unwrapped, 1);
    let html_out = html_body_of(&r.cleaned);
    assert!(
        html_out.contains(r#"href="https://example.com/p""#),
        "got: {html_out}"
    );
    assert!(!html_out.contains("utm_id"));
}

#[test]
fn malicious_javascript_and_file_redirects_rejected() {
    for evil in [
        "javascript%3Aalert(document.cookie)",
        "file%3A%2F%2F%2Fetc%2Fpasswd",
    ] {
        let html = format!(
            r#"<html><body><a href="https://u1.ct.sendgrid.net/ls/click?url={evil}">x</a></body></html>"#
        );
        let mut raw = Vec::new();
        raw.extend_from_slice(b"From: a@b.example\r\nSubject: evil\r\nMIME-Version: 1.0\r\n");
        raw.extend_from_slice(b"Content-Type: text/html; charset=utf-8\r\n\r\n");
        raw.extend_from_slice(html.as_bytes());
        raw.extend_from_slice(b"\r\n");

        let r = clean_message(&raw, &cfg()).unwrap();
        // Never unwrapped to a dangerous scheme.
        assert_eq!(r.stats.redirects_unwrapped, 0, "evil={evil}");
        let html_out = html_body_of(&r.cleaned);
        assert!(!html_out.contains("javascript:"));
        assert!(!html_out.contains("file:"));
    }
}

#[test]
fn private_ip_redirect_destination_is_not_unwrapped() {
    let html = r#"<html><body><a href="https://u1.ct.sendgrid.net/ls/click?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F">x</a></body></html>"#;
    let mut raw = Vec::new();
    raw.extend_from_slice(b"From: a@b.example\r\nSubject: ssrf\r\nMIME-Version: 1.0\r\n");
    raw.extend_from_slice(b"Content-Type: text/html; charset=utf-8\r\n\r\n");
    raw.extend_from_slice(html.as_bytes());
    raw.extend_from_slice(b"\r\n");

    let r = clean_message(&raw, &cfg()).unwrap();
    assert_eq!(r.stats.redirects_unwrapped, 0);
    let html_out = html_body_of(&r.cleaned);
    // Must not rewrite the *href* to point directly at the metadata service.
    // (The encoded URL may still appear inside the original tracking link's
    // query string; what matters is we never made it the destination.)
    assert!(!html_out.contains(r#"href="http://169.254"#));
}

#[test]
fn preserve_original_href_keeps_source() {
    let mut c = CleanerConfig::default();
    c.preserve_original_href = true;
    c.finalize();

    let mut raw = Vec::new();
    raw.extend_from_slice(b"From: a@b.example\r\nSubject: keep\r\nMIME-Version: 1.0\r\n");
    raw.extend_from_slice(b"Content-Type: text/html; charset=utf-8\r\n\r\n");
    raw.extend_from_slice(br#"<a href="https://e.example/?id=1&utm_source=x">y</a>"#);
    raw.extend_from_slice(b"\r\n");

    let r = clean_message(&raw, &c).unwrap();
    let html = html_body_of(&r.cleaned);
    assert!(html.contains(r#"href="https://e.example/?id=1""#));
    assert!(html.contains(r#"data-original-href="https://e.example/?id=1&utm_source=x""#));
}

#[test]
fn report_only_mode_adds_headers_but_does_not_modify_body() {
    let mut c = CleanerConfig::default();
    c.mode = Mode::ReportOnly;
    c.finalize();

    let raw = fixture("tracking_pixel.eml");
    let r = clean_message(&raw, &c).unwrap();
    assert!(!r.modified, "report-only must not modify the body");
    // Stats still computed.
    assert_eq!(r.stats.pixels_removed, 3);
    let full = as_str(&r.cleaned);
    assert!(full.contains("X-Privacy-Cleaner-Mode: report-only"));
    assert!(full.contains("X-Privacy-Cleaner-Body-Modified: no"));
    // Original pixel still present (body untouched).
    assert!(full.contains("o.gif"));
}

#[test]
fn attachments_are_not_altered() {
    // multipart/mixed: an HTML part + a base64 "attachment" that must be left
    // byte-for-byte intact.
    let attachment_data = STANDARD.encode(b"\x00\x01\x02PRIVATE-BINARY\xff\xfe");
    let mut raw = Vec::new();
    raw.extend_from_slice(b"From: a@b.example\r\nSubject: mixed\r\nMIME-Version: 1.0\r\n");
    raw.extend_from_slice(b"Content-Type: multipart/mixed; boundary=\"BND\"\r\n\r\n");
    raw.extend_from_slice(b"--BND\r\nContent-Type: text/html; charset=utf-8\r\n\r\n");
    raw.extend_from_slice(br#"<a href="https://e.example/?utm_source=x">y</a>"#);
    raw.extend_from_slice(b"\r\n--BND\r\n");
    raw.extend_from_slice(b"Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"data.bin\"\r\nContent-Transfer-Encoding: base64\r\n\r\n");
    raw.extend_from_slice(attachment_data.as_bytes());
    raw.extend_from_slice(b"\r\n--BND--\r\n");

    let r = clean_message(&raw, &cfg()).unwrap();
    assert!(r.modified);
    // Attachment payload preserved verbatim.
    assert!(as_str(&r.cleaned).contains(&attachment_data));
    // HTML cleaned.
    assert!(!as_str(&r.cleaned).contains("utm_source"));
}

#[test]
fn oversized_message_is_rejected() {
    let mut c = CleanerConfig::default();
    c.max_message_size = 10;
    c.finalize();
    let raw = fixture("logo.eml");
    assert!(clean_message(&raw, &c).is_err());
}

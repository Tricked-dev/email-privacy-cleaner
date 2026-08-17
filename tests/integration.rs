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
fn css_beacons_neutralized_and_link_pings_stripped() {
    let raw = fixture("css_beacon.eml");
    let r = clean_message(&raw, &cfg()).unwrap();
    assert!(r.modified);

    // A hidden background-image beacon + a legacy `background=` beacon = 2 CSS
    // beacons, counted alongside any pixels removed.
    assert_eq!(r.stats.pixels_removed, 2);
    // The hyperlink-auditing ping attribute is stripped.
    assert_eq!(r.stats.pings_stripped, 1);

    let html = html_body_of(&r.cleaned);
    assert!(
        !html.contains("google-analytics.com"),
        "hidden CSS beacon gone"
    );
    assert!(
        !html.contains("doubleclick.net"),
        "legacy background beacon gone"
    );
    assert!(!html.contains("track.example.net"), "ping target gone");
    assert!(!html.contains("ping="), "ping attribute removed");
    // The legitimate, visible hero background survives untouched.
    assert!(html.contains("https://cdn.example.com/hero.jpg"));
    // The normal tracking param on the visible link is still cleaned.
    assert!(!html.contains("utm_source"));
    assert!(html.contains("id=1"));

    // Surfaced as an audit header.
    let full = as_str(&r.cleaned);
    assert!(full.contains("X-Privacy-Cleaner-Link-Pings-Stripped: 1"));
    assert!(full.contains("X-Privacy-Cleaner-Pixels-Removed: 2"));
}

#[test]
fn css_beacons_respect_report_only_mode() {
    let mut c = CleanerConfig::default();
    c.mode = Mode::ReportOnly;
    c.finalize();
    let raw = fixture("css_beacon.eml");
    let r = clean_message(&raw, &c).unwrap();
    assert!(!r.modified, "report-only must not modify the body");
    // Counts are still computed.
    assert_eq!(r.stats.pixels_removed, 2);
    assert_eq!(r.stats.pings_stripped, 1);
    // Body untouched: the beacons and ping are still present.
    let full = as_str(&r.cleaned);
    assert!(full.contains("google-analytics.com"));
    assert!(full.contains("ping="));
}

#[test]
fn css_beacon_neutralization_can_be_disabled() {
    let mut c = cfg();
    c.neutralize_css_beacons = false;
    c.strip_link_ping = false;
    c.finalize();
    let raw = fixture("css_beacon.eml");
    let r = clean_message(&raw, &c).unwrap();
    // With both off, only the <img>-style pixel logic and link cleaning run; no
    // CSS beacons or pings are touched.
    assert_eq!(r.stats.pixels_removed, 0);
    assert_eq!(r.stats.pings_stripped, 0);
    let html = html_body_of(&r.cleaned);
    assert!(html.contains("google-analytics.com"));
    assert!(html.contains("ping="));
    // The ordinary tracking param is still stripped (link cleaning is separate).
    assert!(!html.contains("utm_source"));
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

#[test]
fn vendor_specific_params_stripped_from_amazon_and_youtube() {
    let raw = fixture("amazon.eml");
    let r = clean_message(&raw, &cfg()).unwrap();
    assert!(r.modified);
    let html = html_body_of(&r.cleaned);
    // Amazon tracking params gone, functional ones kept.
    assert!(!html.contains("pf_rd_r"), "amazon pf_rd_r must be stripped");
    assert!(!html.contains("pd_rd_w"), "amazon pd_rd_w must be stripped");
    assert!(
        !html.contains("tag=aff-20"),
        "amazon affiliate tag must be stripped"
    );
    assert!(
        html.contains("th=1"),
        "amazon variation selector must survive"
    );
    assert!(
        html.contains("keywords=usb"),
        "search keywords must survive"
    );
    // YouTube tracking gone, video id kept.
    assert!(
        !html.contains("si=TRACKINGID"),
        "youtube si must be stripped"
    );
    assert!(
        html.contains("v=dQw4w9WgXcQ"),
        "youtube video id must survive"
    );
}

#[test]
fn vendor_rules_disabled_leaves_amazon_link_untouched() {
    let mut c = cfg();
    c.apply_vendor_rules = false;
    c.finalize();
    let raw = fixture("amazon.eml");
    let r = clean_message(&raw, &c).unwrap();
    let html = html_body_of(&r.cleaned);
    // pf_rd_r is vendor-only and not a global param, so it survives.
    assert!(html.contains("pf_rd_r=ABC123"));
}

#[test]
fn unsubscribe_link_preserved_and_surfaced() {
    let raw = fixture("unsubscribe.eml");
    let r = clean_message(&raw, &cfg()).unwrap();
    assert!(r.modified);
    let html = html_body_of(&r.cleaned);

    // The List-Unsubscribe link keeps its token AND its utm param (sensitive).
    assert!(
        html.contains("tok=SECRET-TOKEN"),
        "unsub token must survive"
    );
    assert!(
        html.contains("https://news.example.com/u?uid=42&utm_source=footer&tok=SECRET-TOKEN"),
        "the unsubscribe link must be left byte-for-byte intact"
    );
    // The ordinary tracked link IS cleaned.
    assert!(!html.contains("utm_campaign=spring"));
    assert!(html.contains("id=1"));
    // Pixel removed.
    assert_eq!(r.stats.pixels_removed, 1);

    // The unsubscribe target is surfaced in an audit header.
    let unsub = r
        .audit_headers
        .iter()
        .find(|(n, _)| n == "X-Privacy-Cleaner-Unsubscribe");
    assert!(unsub.is_some(), "unsubscribe header should be present");
    assert!(unsub.unwrap().1.contains("news.example.com/u"));

    // The original List-Unsubscribe headers are preserved verbatim.
    let full = as_str(&r.cleaned);
    assert!(full.contains("List-Unsubscribe-Post: List-Unsubscribe=One-Click"));
}

#[test]
fn sensitive_sender_skips_link_rewriting_but_removes_pixels() {
    // Build a message from a built-in sensitive sender (paypal.com) with a
    // tracked link and a tracking pixel.
    let raw = concat!(
        "From: PayPal <service@paypal.com>\r\n",
        "To: User <user@example.org>\r\n",
        "Subject: Receipt\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: text/html; charset=utf-8\r\n",
        "Content-Transfer-Encoding: 7bit\r\n",
        "\r\n",
        "<html><body>",
        "<a href=\"https://www.paypal.com/activate?token=MAGIC&utm_source=email\">Confirm</a>",
        "<img src=\"https://track.example.net/o.gif\" width=\"1\" height=\"1\" alt=\"\">",
        "</body></html>\r\n",
    )
    .as_bytes()
    .to_vec();

    let r = clean_message(&raw, &cfg()).unwrap();
    let html = html_body_of(&r.cleaned);

    // Query-param cleaning is disabled for sensitive senders: the magic token
    // AND the utm param survive (we won't risk breaking the flow).
    assert!(html.contains("token=MAGIC"));
    assert!(html.contains("utm_source=email"));
    assert_eq!(r.stats.urls_cleaned, 0);
    // Pixel removal is always safe, so it still happens.
    assert_eq!(r.stats.pixels_removed, 1);

    let policy = r
        .audit_headers
        .iter()
        .find(|(n, _)| n == "X-Privacy-Cleaner-Policy")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    assert_eq!(policy, "sensitive-sender");
}

#[test]
fn external_rule_pack_file_is_loaded_and_applied() {
    // Write a tiny ClearURLs-format pack to a temp file and point the config at it.
    let path = std::env::temp_dir().join(format!(
        "epc_pack_{}_{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::write(
        &path,
        r#"{"providers":{"acme":{"urlPattern":"^https?://acme\\.test","rules":["sid","trk_.*"]}}}"#,
    )
    .unwrap();

    let toml = format!(
        "preserve_original_href = false\nrule_packs = [{:?}]\n",
        path.to_string_lossy()
    );
    let cfg = CleanerConfig::from_toml_str(&toml).unwrap();

    let html = r#"<html><body><a href="https://acme.test/p?sid=1&trk_x=2&keep=3&utm_source=z">x</a></body></html>"#;
    let mut raw = Vec::new();
    raw.extend_from_slice(b"From: a@b.example\r\nSubject: pack\r\nMIME-Version: 1.0\r\n");
    raw.extend_from_slice(b"Content-Type: text/html; charset=utf-8\r\n\r\n");
    raw.extend_from_slice(html.as_bytes());
    raw.extend_from_slice(b"\r\n");

    let r = clean_message(&raw, &cfg).unwrap();
    let out = html_body_of(&r.cleaned);
    // Pack rules (sid, trk_*) AND the built-in global (utm_source) are stripped.
    assert!(!out.contains("sid=1"), "got: {out}");
    assert!(!out.contains("trk_x=2"));
    assert!(!out.contains("utm_source"));
    // Functional param survives.
    assert!(out.contains("keep=3"));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn rule_pack_url_accepts_file_scheme_offline() {
    // Nix prefetch scenario: a remote pack is fetched into a local path and
    // referenced via a file:// URL — must load with NO `network` feature.
    let path = std::env::temp_dir().join(format!(
        "epc_filepack_{}_{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::write(
        &path,
        r#"{"providers":{"acme":{"urlPattern":"^https?://acme\\.test","rules":["sid"]}}}"#,
    )
    .unwrap();

    let toml = format!(
        "preserve_original_href = false\nrule_pack_urls = [\"file://{}\"]\n",
        path.to_string_lossy()
    );
    let cfg = CleanerConfig::from_toml_str(&toml).unwrap();

    let html = r#"<html><body><a href="https://acme.test/p?sid=1&keep=2">x</a></body></html>"#;
    let mut raw = Vec::new();
    raw.extend_from_slice(b"From: a@b.example\r\nSubject: filepack\r\nMIME-Version: 1.0\r\n");
    raw.extend_from_slice(b"Content-Type: text/html; charset=utf-8\r\n\r\n");
    raw.extend_from_slice(html.as_bytes());
    raw.extend_from_slice(b"\r\n");

    let r = clean_message(&raw, &cfg).unwrap();
    let out = html_body_of(&r.cleaned);
    assert!(!out.contains("sid=1"), "got: {out}");
    assert!(out.contains("keep=2"));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn keep_params_exclusion_protects_a_param_and_domain() {
    let cfg = CleanerConfig::from_toml_str(
        "preserve_original_href = false\nkeep_params = [\"utm_source\"]\nexclude_domains = [\"trusted.example\"]\n",
    )
    .unwrap();

    let html = concat!(
        "<html><body>",
        // utm_source kept (on the keep-list), utm_medium still stripped.
        "<a href=\"https://shop.example/a?utm_source=news&utm_medium=email&id=1\">a</a>",
        // whole host excluded -> untouched.
        "<a href=\"https://trusted.example/b?utm_source=x&fbclid=y\">b</a>",
        "</body></html>"
    );
    let mut raw = Vec::new();
    raw.extend_from_slice(b"From: a@b.example\r\nSubject: keep\r\nMIME-Version: 1.0\r\n");
    raw.extend_from_slice(b"Content-Type: text/html; charset=utf-8\r\n\r\n");
    raw.extend_from_slice(html.as_bytes());
    raw.extend_from_slice(b"\r\n");

    let r = clean_message(&raw, &cfg).unwrap();
    let out = html_body_of(&r.cleaned);
    assert!(
        out.contains("utm_source=news"),
        "kept param survives: {out}"
    );
    assert!(
        !out.contains("utm_medium=email"),
        "other tracker still stripped"
    );
    // Excluded domain: everything survives.
    assert!(out.contains("https://trusted.example/b?utm_source=x&fbclid=y"));
}

/// Regression: when an ESP-formatted newsletter encodes query separators as
/// `&amp;` inside `href` attributes, every link must be cleaned for every
/// tracker, not just the first parameter. The original bug parsed
/// `?utm_source=x&amp;utm_medium=y` as one literal `utm_source` and a
/// surviving `amp;utm_medium=y`.
///
/// We reconstruct the *shape* of the offending real-world message
/// (multipart/alternative with QP-encoded body parts and 28 entity-escaped
/// links) using synthetic content so no real recipient data lives in-tree.
#[test]
fn html_entity_escaped_query_params_in_multipart_alternative_are_cleaned() {
    let mut html = String::from("<html><body>\n");
    // 28 links each carrying utm_source + utm_medium + a recipient token that
    // must survive (modelled on the real-world `cctw=` recipient/click token).
    for i in 0..28 {
        html.push_str(&format!(
            "<p><a href=\"https://shop.example.com/p/{i}?id={i}&amp;utm_source=news&amp;utm_medium=email&amp;cctw=tok{i}\">item {i}</a></p>\n",
        ));
    }
    html.push_str("</body></html>\n");

    let html_qp = qp_encode(html.as_bytes());
    let text_part = "See the offers in HTML.\r\n";
    let raw = build_multipart_alternative(text_part, &html_qp);

    let r = clean_message(&raw, &cfg()).unwrap();
    assert_eq!(r.stats.urls_cleaned, 28, "every link must be cleaned");
    let out = html_body_of(&r.cleaned);
    assert!(!out.contains("utm_source"), "got: {out}");
    assert!(!out.contains("utm_medium"), "got: {out}");
    assert!(
        !out.contains("amp;utm_"),
        "amp; prefix tracker must not survive: {out}"
    );
    assert!(
        out.contains("cctw=tok0") && out.contains("cctw=tok27"),
        "non-tracking recipient/link token must survive across all links"
    );
}

/// Regression: one-dimensional layout spacer GIFs (e.g. `10x1`, `1x10`,
/// `130x5`) used by older HTML mail templates for column layout must not be
/// flagged as tracking pixels just because one dimension is `1`.
#[test]
fn layout_spacer_images_are_not_removed_as_pixels() {
    // Synthesised analogue of a real ESP newsletter (the original message
    // used contactlab.it). The host name doesn't matter; the rule under test
    // is the dimension heuristic.
    let html = concat!(
        "<html><body>",
        "<table><tr>",
        "<td><img src=\"https://static.shop.example/img/spacer.gif\" width=\"10\" height=\"1\" alt=\"\"></td>",
        "<td><img src=\"https://static.shop.example/spacer.gif\" width=\"130\" height=\"5\" alt=\"\"></td>",
        "<td><img src=\"https://static.shop.example/img/spacer.gif\" width=\"1\" height=\"10\" alt=\"\"></td>",
        "</tr></table>",
        "</body></html>\r\n",
    );
    let html_qp = qp_encode(html.as_bytes());
    let text_part = "layout-only spacers\r\n";
    let raw = build_multipart_alternative(text_part, &html_qp);

    let r = clean_message(&raw, &cfg()).unwrap();
    assert_eq!(r.stats.pixels_removed, 0);
    assert!(!r.modified);
    let out = html_body_of(&r.cleaned);
    assert!(out.contains("static.shop.example/img/spacer.gif"));
    assert!(out.contains("static.shop.example/spacer.gif"));
}

/// Build a multipart/alternative message whose body parts are the given
/// text/plain and quoted-printable text/html payloads. Mirrors the shape of
/// the real-world fixture this synthetic test replaces.
fn build_multipart_alternative(text_plain: &str, html_qp: &str) -> Vec<u8> {
    let boundary = "=-test_boundary_alt";
    let mut raw = Vec::new();
    raw.extend_from_slice(b"From: news@example.com\r\n");
    raw.extend_from_slice(b"To: recipient@example.com\r\n");
    raw.extend_from_slice(b"Subject: synthetic test\r\n");
    raw.extend_from_slice(b"MIME-Version: 1.0\r\n");
    raw.extend_from_slice(
        format!("Content-Type: multipart/alternative; boundary=\"{boundary}\"\r\n\r\n").as_bytes(),
    );
    raw.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    raw.extend_from_slice(b"Content-Type: text/plain; charset=utf-8\r\n");
    raw.extend_from_slice(b"Content-Transfer-Encoding: quoted-printable\r\n\r\n");
    raw.extend_from_slice(text_plain.as_bytes());
    raw.extend_from_slice(b"\r\n");
    raw.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    raw.extend_from_slice(b"Content-Type: text/html; charset=utf-8\r\n");
    raw.extend_from_slice(b"Content-Transfer-Encoding: quoted-printable\r\n\r\n");
    raw.extend_from_slice(html_qp.as_bytes());
    raw.extend_from_slice(b"\r\n");
    raw.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    raw
}

/// Minimal quoted-printable encoder for test fixtures (lines <= 76 chars,
/// soft-break with `=`).
fn qp_encode(content: &[u8]) -> String {
    let mut out = String::new();
    let mut line_len = 0usize;
    let push = |out: &mut String, line_len: &mut usize, s: &str, takes: usize| {
        if *line_len + takes > 75 {
            out.push('=');
            out.push_str("\r\n");
            *line_len = 0;
        }
        out.push_str(s);
        *line_len += takes;
    };
    for &b in content {
        match b {
            b'\n' => {
                out.push_str("\r\n");
                line_len = 0;
            }
            b'\r' => { /* skip; we emit CRLF on the LF */ }
            b'=' => push(&mut out, &mut line_len, "=3D", 3),
            0x21..=0x7E => push(&mut out, &mut line_len, &(b as char).to_string(), 1),
            b' ' | b'\t' => push(&mut out, &mut line_len, &(b as char).to_string(), 1),
            _ => {
                let enc = format!("={b:02X}");
                push(&mut out, &mut line_len, &enc, 3);
            }
        }
    }
    out
}

/// Returns the value of an audit header from a cleaner result, if present.
fn audit<'a>(r: &'a email_privacy_cleaner::CleanerResult, name: &str) -> Option<&'a str> {
    r.audit_headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Build a single-part text/html message declaring `cte`, with `body` used as
/// the body bytes verbatim.
fn singlepart_html(cte: &str, charset: &str, body: &[u8]) -> Vec<u8> {
    let mut raw = Vec::new();
    raw.extend_from_slice(b"From: a@b.example\r\nSubject: s\r\nMIME-Version: 1.0\r\n");
    raw.extend_from_slice(format!("Content-Type: text/html; charset=\"{charset}\"\r\n").as_bytes());
    raw.extend_from_slice(format!("Content-Transfer-Encoding: {cte}\r\n\r\n").as_bytes());
    raw.extend_from_slice(body);
    raw.extend_from_slice(b"\r\n");
    raw
}

const PIXEL_HTML: &str = r#"<html><body><p>hi</p><a href="https://e.example/p?id=1&utm_source=news">x</a><img src="https://t.example/open.gif" width="1" height="1" alt=""></body></html>"#;

/// An MTA that hands us an already-decoded body while still advertising the
/// original CTE must not cause the message to be passed through untouched.
#[test]
fn cte_mismatch_quoted_printable_html_is_still_cleaned() {
    let raw = singlepart_html("quoted-printable", "UTF-8", PIXEL_HTML.as_bytes());
    let r = clean_message(&raw, &cfg()).unwrap();

    assert_eq!(r.stats.html_parts, 1, "the html part must be counted");
    assert_eq!(r.stats.pixels_removed, 1);
    assert!(r.modified, "body must actually be rewritten");
    assert_eq!(audit(&r, "X-Privacy-Cleaner-Cte-Mismatch-Parts"), Some("1"));

    let out = as_str(&r.cleaned);
    assert!(!out.contains("open.gif"), "pixel survived: {out}");
    assert!(!out.contains("utm_source"));
    // Written back verbatim: we must not QP-encode a body that arrived decoded.
    assert!(!out.contains("=3D"), "body was double-encoded: {out}");
}

#[test]
fn cte_mismatch_base64_html_is_still_cleaned() {
    let raw = singlepart_html("base64", "UTF-8", PIXEL_HTML.as_bytes());
    let r = clean_message(&raw, &cfg()).unwrap();

    assert_eq!(r.stats.html_parts, 1);
    assert_eq!(r.stats.pixels_removed, 1);
    assert!(r.modified);
    assert_eq!(audit(&r, "X-Privacy-Cleaner-Cte-Mismatch-Parts"), Some("1"));
    assert!(!as_str(&r.cleaned).contains("open.gif"));
}

/// The recovery path must not hijack a correctly-encoded part: a real QP body
/// still goes through the normal decode path and stays QP on the way out.
#[test]
fn correctly_encoded_part_does_not_use_cte_mismatch_path() {
    let encoded = PIXEL_HTML.replace('=', "=3D");
    let raw = singlepart_html("quoted-printable", "UTF-8", encoded.as_bytes());
    let r = clean_message(&raw, &cfg()).unwrap();

    assert_eq!(r.stats.html_parts, 1);
    assert_eq!(r.stats.pixels_removed, 1);
    assert!(r.modified);
    assert_eq!(
        audit(&r, "X-Privacy-Cleaner-Cte-Mismatch-Parts"),
        None,
        "healthy QP part must not be treated as a CTE mismatch"
    );
    let out = as_str(&r.cleaned);
    assert!(!out.contains("open.gif"));
    assert!(out.contains("=3D"), "output should remain QP-encoded");
}

/// A part whose body is not markup (e.g. a genuinely broken base64 payload)
/// must be left alone rather than parsed as HTML.
#[test]
fn cte_mismatch_path_ignores_non_markup_bodies() {
    let raw = singlepart_html("base64", "UTF-8", b"plain text, not base64!");
    let r = clean_message(&raw, &cfg()).unwrap();
    assert_eq!(r.stats.html_parts, 0);
    assert!(!r.modified);
    assert_eq!(audit(&r, "X-Privacy-Cleaner-Cte-Mismatch-Parts"), None);
}

/// windows-1256 used to fall through `reencode_charset` and silently disable
/// the rewrite, while the stats still reported a removal.
#[test]
fn windows_1256_part_is_cleaned_and_reencoded() {
    let mut body = Vec::new();
    body.extend_from_slice(b"<html><body><p>");
    body.extend_from_slice(&[0xE3, 0xD1, 0xCD, 0xC8, 0xC7]); // مرحبا in cp1256
    body.extend_from_slice(
        br#"</p><a href="https://e.example/p?id=1&utm_source=news">x</a></body></html>"#,
    );
    let raw = singlepart_html("7bit", "windows-1256", &body);

    let r = clean_message(&raw, &cfg()).unwrap();
    assert!(r.modified, "windows-1256 part must be rewritten");
    assert_eq!(audit(&r, "X-Privacy-Cleaner-Unencodable-Parts"), None);
    assert!(!as_str(&r.cleaned).contains("utm_source"));
    // Still cp1256 single bytes, not UTF-8 two-byte sequences.
    assert!(r.cleaned.windows(1).any(|w| w == [0xE3]));
    assert!(!r.cleaned.windows(2).any(|w| w == [0xD9, 0x85]));
    assert!(as_str(&r.cleaned).contains("windows-1256"));
}

/// Where a rewrite genuinely cannot be written back, that must be surfaced
/// rather than reported as a clean pass.
#[test]
fn unencodable_charset_is_surfaced_not_silent() {
    let html = r#"<html><body><p>caf\u{e9}</p><a href="https://e.example/p?utm_source=news">x</a></body></html>"#
        .replace("\\u{e9}", "\u{e9}");
    let utf16: Vec<u8> = html.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    let b64 = STANDARD.encode(&utf16);
    let raw = singlepart_html("base64", "utf-16", b64.as_bytes());

    let r = clean_message(&raw, &cfg()).unwrap();
    // utf-16 output is not representable, so the rewrite cannot be applied.
    assert_eq!(r.stats.urls_cleaned, 1, "the tracker is still detected");
    assert!(!r.modified, "but the body must be left byte-identical");
    assert_eq!(
        audit(&r, "X-Privacy-Cleaner-Unencodable-Parts"),
        Some("1"),
        "a computed-but-undeliverable rewrite must be reported, not silent"
    );
}

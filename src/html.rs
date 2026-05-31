//! Tolerant HTML5 sanitization: href cleaning/unwrapping and tracking-pixel
//! removal.
//!
//! Built on `lol_html`, a streaming rewriter, so memory use stays bounded and
//! no network fetching ever happens — we only ever *read* `src` to decide
//! whether to drop an element.

use std::cell::RefCell;
use std::collections::HashSet;

use lol_html::html_content::ContentType;
use lol_html::{element, rewrite_str, RewriteStrSettings};
use url::Url;

use crate::config::CleanerConfig;
use crate::redirect::unwrap_redirect_url;

/// Per-message context for HTML cleaning that isn't part of the static config.
///
/// Currently carries the set of "sensitive" links (e.g. `List-Unsubscribe`
/// targets) whose `href` must be left untouched so recipient-specific tokens
/// survive.
#[derive(Debug, Clone, Default)]
pub struct LinkContext<'a> {
    /// Normalised URLs (serialized `Url` form) that must not be rewritten.
    pub sensitive_urls: Option<&'a HashSet<String>>,
}

impl LinkContext<'_> {
    fn is_sensitive(&self, raw_href: &str, parsed: &Url) -> bool {
        match self.sensitive_urls {
            Some(set) if !set.is_empty() => {
                set.contains(parsed.as_str()) || set.contains(raw_href.trim())
            }
            _ => false,
        }
    }
}

/// Outcome of [`clean_html`](crate::clean_html).
#[derive(Debug, Clone, Default)]
pub struct HtmlCleanResult {
    /// The (possibly) rewritten HTML.
    pub html: String,
    /// Whether anything changed.
    pub changed: bool,
    /// Links whose href was cleaned (tracking params stripped / blocked).
    pub urls_cleaned: usize,
    /// Links whose redirect was unwrapped to its destination.
    pub redirects_unwrapped: usize,
    /// Tracking pixels / beacon images removed (including CSS background
    /// beacons when `neutralize_css_beacons` is enabled).
    pub pixels_removed: usize,
    /// Hyperlink-auditing `ping` attributes stripped from `<a>`/`<area>`.
    pub pings_stripped: usize,
}

#[derive(Default)]
struct Stats {
    urls_cleaned: usize,
    redirects_unwrapped: usize,
    pixels_removed: usize,
    pings_stripped: usize,
}

/// Clean an HTML email body.
///
/// * `base_url` is used to resolve relative `href`s (rare in email but
///   supported); relative links are left untouched when no base is available.
pub fn clean_html(
    html: &str,
    base_url: Option<&Url>,
    config: &CleanerConfig,
) -> crate::error::Result<HtmlCleanResult> {
    clean_html_ctx(html, base_url, config, &LinkContext::default())
}

/// Like [`clean_html`], but with a [`LinkContext`] carrying per-message state
/// (e.g. sensitive links that must not be rewritten).
pub fn clean_html_ctx(
    html: &str,
    base_url: Option<&Url>,
    config: &CleanerConfig,
    ctx: &LinkContext<'_>,
) -> crate::error::Result<HtmlCleanResult> {
    if html.len() > config.max_html_part_size {
        // Too large to process safely; leave untouched.
        return Ok(HtmlCleanResult {
            html: html.to_string(),
            changed: false,
            ..Default::default()
        });
    }

    let stats = RefCell::new(Stats::default());

    let mut handlers = Vec::new();

    // ---- href rewriting on <a> and <area> ----
    if config.clean_query_params
        || config.unwrap_known_redirects
        || !config.blocked_domains.is_empty()
    {
        handlers.push(element!("a[href], area[href]", |el| {
            if let Some(href) = el.get_attribute("href") {
                if let Some((new_href, kind)) = process_href(&href, base_url, config, ctx) {
                    if config.preserve_original_href {
                        let _ = el.set_attribute("data-original-href", &href);
                    }
                    let _ = el.set_attribute("href", &new_href);
                    let mut s = stats.borrow_mut();
                    match kind {
                        HrefChange::Unwrapped => s.redirects_unwrapped += 1,
                        HrefChange::Cleaned => s.urls_cleaned += 1,
                    }
                }
            }
            Ok(())
        }));
    }

    // ---- tracking-pixel removal on <img> ----
    if config.remove_pixels {
        handlers.push(element!("img", |el| {
            if is_tracking_pixel(el, config) {
                if config.debug_preserve_removed {
                    let comment = format!(
                        "<!-- email-privacy-cleaner removed tracking pixel: src={} -->",
                        el.get_attribute("src").unwrap_or_default()
                    );
                    el.before(&comment, ContentType::Html);
                }
                el.remove();
                stats.borrow_mut().pixels_removed += 1;
            }
            Ok(())
        }));
    }

    // ---- CSS background beacons (inline style + legacy `background` attr) ----
    if config.remove_pixels && config.neutralize_css_beacons {
        handlers.push(element!("[style]", |el| {
            if let Some(style) = el.get_attribute("style") {
                if let Some((new_style, n)) = neutralize_style_beacons(&style, config) {
                    let _ = el.set_attribute("style", &new_style);
                    stats.borrow_mut().pixels_removed += n;
                }
            }
            Ok(())
        }));
        handlers.push(element!("[background]", |el| {
            if let Some(bg) = el.get_attribute("background") {
                if is_remote_beacon_url(&bg, config) {
                    el.remove_attribute("background");
                    stats.borrow_mut().pixels_removed += 1;
                }
            }
            Ok(())
        }));
    }

    // ---- hyperlink-auditing `ping` attribute removal ----
    if config.strip_link_ping {
        handlers.push(element!("a[ping], area[ping]", |el| {
            if el.get_attribute("ping").is_some() {
                el.remove_attribute("ping");
                stats.borrow_mut().pings_stripped += 1;
            }
            Ok(())
        }));
    }

    let output = rewrite_str(
        html,
        RewriteStrSettings {
            element_content_handlers: handlers,
            ..RewriteStrSettings::new()
        },
    )
    .map_err(|e| crate::error::CleanerError::Html(e.to_string()))?;

    let s = stats.into_inner();
    let changed = s.urls_cleaned > 0
        || s.redirects_unwrapped > 0
        || s.pixels_removed > 0
        || s.pings_stripped > 0;

    Ok(HtmlCleanResult {
        html: output,
        changed,
        urls_cleaned: s.urls_cleaned,
        redirects_unwrapped: s.redirects_unwrapped,
        pixels_removed: s.pixels_removed,
        pings_stripped: s.pings_stripped,
    })
}

/// Extract every `<a>`/`<area>` `href` from an HTML fragment, in document
/// order (duplicates included). Used by the CLI `explain-message` /
/// `print-trackers` commands; performs no rewriting or network access.
pub fn extract_links(html: &str) -> Vec<String> {
    let links: RefCell<Vec<String>> = RefCell::new(Vec::new());
    let _ = rewrite_str(
        html,
        RewriteStrSettings {
            element_content_handlers: vec![element!("a[href], area[href]", |el| {
                if let Some(h) = el.get_attribute("href") {
                    links.borrow_mut().push(h);
                }
                Ok(())
            })],
            ..RewriteStrSettings::new()
        },
    );
    links.into_inner()
}

enum HrefChange {
    Unwrapped,
    Cleaned,
}

/// Decide how (if at all) an `href` should be rewritten. Returns the new href
/// and what kind of change it was, or `None` to leave it unchanged.
fn process_href(
    href: &str,
    base_url: Option<&Url>,
    config: &CleanerConfig,
    ctx: &LinkContext<'_>,
) -> Option<(String, HrefChange)> {
    let trimmed = href.trim();
    // Skip anchors, mailto:, tel:, cid:, data:, etc.
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }

    let url = match Url::parse(trimmed) {
        Ok(u) => u,
        Err(url::ParseError::RelativeUrlWithoutBase) => match base_url {
            Some(base) => base.join(trimmed).ok()?,
            None => return None,
        },
        Err(_) => return None,
    };

    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }

    // Sensitive links (e.g. List-Unsubscribe targets) carry recipient tokens —
    // never rewrite them.
    if ctx.is_sensitive(href, &url) {
        return None;
    }

    // Block-listed destination → neutralise.
    if let Some(host) = url.host_str() {
        if config.is_blocked_domain(host) {
            return Some(("about:blank".to_string(), HrefChange::Cleaned));
        }
    }

    let result = unwrap_redirect_url(&url, config);
    let final_url = &result.url;

    // If, after unwrapping, the destination is blocked, neutralise it.
    if let Some(host) = final_url.host_str() {
        if config.is_blocked_domain(host) {
            return Some(("about:blank".to_string(), HrefChange::Cleaned));
        }
    }

    if result.unwrapped {
        Some((final_url.to_string(), HrefChange::Unwrapped))
    } else if final_url.as_str() != url.as_str() {
        Some((final_url.to_string(), HrefChange::Cleaned))
    } else {
        None
    }
}

/// Heuristically decide whether an `<img>` is a tracking pixel / beacon.
fn is_tracking_pixel(el: &lol_html::html_content::Element, config: &CleanerConfig) -> bool {
    let src = el.get_attribute("src").unwrap_or_default();
    let src = src.trim();

    // Only consider remote images (http/https). cid: (inline attachments) and
    // data: URIs are never network beacons.
    let remote_host = match Url::parse(src) {
        Ok(u) if matches!(u.scheme(), "http" | "https") => u.host_str().map(|h| h.to_string()),
        _ => None,
    };
    let is_remote = remote_host.is_some();

    // Known beacon/tracking host (rule-pack completeProvider or extra_pixel_domains)
    // → always drop.
    if let Some(host) = &remote_host {
        if config.is_beacon(src, host) {
            return true;
        }
    }

    // Dimensions from attributes.
    let attr_w = el.get_attribute("width").and_then(|s| parse_dim(&s));
    let attr_h = el.get_attribute("height").and_then(|s| parse_dim(&s));

    // Dimensions / hidden flags from inline style.
    let style = el.get_attribute("style").unwrap_or_default();
    let (hidden, style_w, style_h) = parse_style(&style);

    let w = attr_w.or(style_w);
    let h = attr_h.or(style_h);

    let zero_or_one = |d: Option<u32>| matches!(d, Some(0) | Some(1));
    let le2 = |d: Option<u32>| matches!(d, Some(x) if x <= 2);

    // width/height 0 or 1, or both <= 2x2.
    let tiny =
        zero_or_one(w) || zero_or_one(h) || (le2(w) && le2(h) && (w.is_some() || h.is_some()));

    if tiny {
        return true;
    }

    // Hidden via CSS, on a remote image → beacon.
    if hidden && is_remote {
        return true;
    }

    // Empty alt + remote + (any explicit small dimension) → beacon.
    let alt_empty = el
        .get_attribute("alt")
        .map(|a| a.trim().is_empty())
        .unwrap_or(true);
    if alt_empty && is_remote && (le2(w) || le2(h)) {
        return true;
    }

    false
}

/// Returns `true` when `url_str` is a remote http(s) URL whose host is a known
/// tracking-beacon host (rule-pack `completeProvider` or `extra_pixel_domains`).
fn is_remote_beacon_url(url_str: &str, config: &CleanerConfig) -> bool {
    match Url::parse(url_str.trim()) {
        Ok(u) if matches!(u.scheme(), "http" | "https") => u
            .host_str()
            .map(|h| config.is_beacon(u.as_str(), h))
            .unwrap_or(false),
        _ => false,
    }
}

/// Neutralise tracking beacons referenced from an inline `style` attribute.
///
/// Each `url(...)` is replaced with `none` when it points at a known beacon
/// host, or when the element carrying the style is itself hidden or 1×1 (a CSS
/// tracking pixel) and the URL is remote. Legitimate, visible background images
/// on normal-sized elements are left untouched. Returns the rewritten style and
/// the number of beacons neutralised, or `None` when nothing changed.
fn neutralize_style_beacons(style: &str, config: &CleanerConfig) -> Option<(String, usize)> {
    let lower_all = style.to_ascii_lowercase();
    if !lower_all.contains("url(") {
        return None;
    }

    let (hidden, w, h) = parse_style(style);
    let le2 = |d: Option<u32>| matches!(d, Some(x) if x <= 2);
    // An element that is invisible or tiny has no legitimate reason to fetch a
    // remote background — treat any remote url() it carries as a beacon.
    let invisible = hidden || ((le2(w) || le2(h)) && (w.is_some() || h.is_some()));

    let mut out = String::with_capacity(style.len());
    let mut count = 0usize;
    let mut idx = 0usize; // byte offset into `style` / `lower_all` (ASCII-aligned)

    while let Some(rel) = lower_all[idx..].find("url(") {
        let open = idx + rel; // start of `url(`
        let after = open + 4; // first byte inside the parens
        let close = match style[after..].find(')') {
            Some(c) => after + c, // byte offset of the closing `)`
            None => break,        // unterminated url(): copy the remainder below
        };
        // Copy everything before this `url(...)` token verbatim.
        out.push_str(&style[idx..open]);
        let inner = style[after..close]
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .trim();
        let remote = matches!(Url::parse(inner), Ok(u) if matches!(u.scheme(), "http" | "https"));
        if is_remote_beacon_url(inner, config) || (invisible && remote) {
            // Replace the whole `url(...)` with the `none` keyword so the
            // element keeps its other declarations but fetches nothing.
            out.push_str("none");
            count += 1;
        } else {
            out.push_str(&style[open..=close]);
        }
        idx = close + 1;
    }
    out.push_str(&style[idx..]);

    (count > 0).then_some((out, count))
}

/// Parse an HTML dimension attribute (`"1"`, `"0"`, `"1px"`, `" 2 "`).
/// Returns `None` for percentages, `auto`, or anything non-numeric.
fn parse_dim(s: &str) -> Option<u32> {
    let t = s.trim();
    if t.ends_with('%') {
        return None;
    }
    let digits: String = t.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse().ok()
}

/// Inspect an inline `style` attribute. Returns `(hidden, width, height)`.
fn parse_style(style: &str) -> (bool, Option<u32>, Option<u32>) {
    let normalized: String = style.to_ascii_lowercase().split_whitespace().collect();
    let mut hidden = false;
    let mut width = None;
    let mut height = None;

    for decl in normalized.split(';') {
        let mut it = decl.splitn(2, ':');
        let prop = it.next().unwrap_or("").trim();
        let val = it.next().unwrap_or("").trim();
        match prop {
            "display" if val == "none" => hidden = true,
            "visibility" if val == "hidden" => hidden = true,
            "opacity" => {
                if let Ok(o) = val.parse::<f32>() {
                    if o <= 0.0 {
                        hidden = true;
                    }
                }
            }
            "width" => width = parse_dim(val),
            "height" => height = parse_dim(val),
            _ => {}
        }
    }
    (hidden, width, height)
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
    fn removes_1x1_pixel() {
        let html =
            r#"<p>Hi</p><img src="https://track.example.net/o.gif" width="1" height="1" alt="">"#;
        let r = clean_html(html, None, &cfg()).unwrap();
        assert_eq!(r.pixels_removed, 1);
        assert!(!r.html.contains("o.gif"));
    }

    #[test]
    fn keeps_legitimate_logo() {
        let html = r#"<img src="https://cdn.example.com/logo.png" width="200" height="60" alt="Acme logo">"#;
        let r = clean_html(html, None, &cfg()).unwrap();
        assert_eq!(r.pixels_removed, 0);
        assert!(r.html.contains("logo.png"));
    }

    #[test]
    fn removes_hidden_remote_image() {
        let html = r#"<img src="https://beacon.example.com/p" style="display:none">"#;
        let r = clean_html(html, None, &cfg()).unwrap();
        assert_eq!(r.pixels_removed, 1);
    }

    #[test]
    fn cleans_link_query_params() {
        let html = r#"<a href="https://shop.example.com/x?id=1&utm_source=news">buy</a>"#;
        let r = clean_html(html, None, &cfg()).unwrap();
        assert_eq!(r.urls_cleaned, 1);
        // The live href is cleaned...
        assert!(r.html.contains(r#"href="https://shop.example.com/x?id=1""#));
        // ...while the original (with the tracker) is preserved for reference.
        assert!(r
            .html
            .contains(r#"data-original-href="https://shop.example.com/x?id=1&utm_source=news""#));
    }

    #[test]
    fn does_not_break_magic_login_link() {
        // No tracking params, unknown host: must be left exactly as-is.
        let html =
            r#"<a href="https://app.example.com/login?token=SECRET-abc123&expires=999">Log in</a>"#;
        let r = clean_html(html, None, &cfg()).unwrap();
        assert_eq!(r.urls_cleaned, 0);
        assert_eq!(r.redirects_unwrapped, 0);
        assert!(r.html.contains("token=SECRET-abc123"));
        assert!(r.html.contains("expires=999"));
        assert!(!r.html.contains("data-original-href"));
    }

    #[test]
    fn sensitive_link_is_left_untouched() {
        let unsub = "https://news.example.com/unsub?uid=42&utm_source=footer&tok=SECRET";
        let mut set = std::collections::HashSet::new();
        // The context stores the normalised (parsed) form.
        set.insert(Url::parse(unsub).unwrap().to_string());
        let html = format!(r#"<a href="{unsub}">Unsubscribe</a>"#);
        let ctx = LinkContext {
            sensitive_urls: Some(&set),
        };
        let r = clean_html_ctx(&html, None, &cfg(), &ctx).unwrap();
        assert_eq!(r.urls_cleaned, 0);
        // utm_source would normally be stripped, but the token-bearing link survives.
        assert!(r.html.contains("utm_source=footer"));
        assert!(r.html.contains("tok=SECRET"));
        assert!(!r.html.contains("data-original-href"));
    }

    #[test]
    fn neutralizes_css_background_beacon_on_known_host() {
        // A div whose background-image points at a known beacon host
        // (doubleclick.net is a built-in completeProvider) must be neutralised,
        // while a legitimate background on a normal element survives.
        let html = concat!(
            r#"<div style="width:600px;height:80px;background-image:url('https://doubleclick.net/px.gif');color:#000">hi</div>"#,
            r#"<div style="background:url(https://cdn.example.com/hero.jpg) no-repeat">ok</div>"#,
        );
        let r = clean_html(html, None, &cfg()).unwrap();
        assert_eq!(r.pixels_removed, 1);
        assert!(!r.html.contains("doubleclick.net"));
        assert!(r.html.contains("background-image:none"));
        // Colour and the legit hero background are preserved.
        assert!(r.html.contains("color:#000"));
        assert!(r.html.contains("https://cdn.example.com/hero.jpg"));
    }

    #[test]
    fn neutralizes_remote_background_on_hidden_element() {
        // A hidden element with a remote background on an *unknown* host is still
        // a CSS tracking pixel.
        let html = r#"<span style="display:none;background-image:url(https://track.unknown.example/p)"></span>"#;
        let r = clean_html(html, None, &cfg()).unwrap();
        assert_eq!(r.pixels_removed, 1);
        assert!(!r.html.contains("track.unknown.example"));
    }

    #[test]
    fn keeps_legit_visible_background() {
        // A visible, normal-sized element with a remote background on an unknown
        // (non-beacon) host must be left untouched.
        let html = r#"<div style="width:600px;height:300px;background:url(https://cdn.example.com/banner.jpg)">x</div>"#;
        let r = clean_html(html, None, &cfg()).unwrap();
        assert_eq!(r.pixels_removed, 0);
        assert!(r.html.contains("https://cdn.example.com/banner.jpg"));
    }

    #[test]
    fn removes_legacy_background_attribute_beacon() {
        let html = r#"<table background="https://google-analytics.com/collect"><tr><td>x</td></tr></table>"#;
        let r = clean_html(html, None, &cfg()).unwrap();
        assert_eq!(r.pixels_removed, 1);
        assert!(!r.html.contains("google-analytics.com"));
    }

    #[test]
    fn strips_hyperlink_ping_attribute() {
        let html = r#"<a href="https://shop.example.com/x" ping="https://track.example.net/click">buy</a>"#;
        let r = clean_html(html, None, &cfg()).unwrap();
        assert_eq!(r.pings_stripped, 1);
        assert!(!r.html.contains("ping="));
        assert!(!r.html.contains("track.example.net"));
        // The visible destination is untouched.
        assert!(r.html.contains(r#"href="https://shop.example.com/x""#));
    }

    #[test]
    fn handles_malformed_html() {
        let html = "<p>unclosed <a href='https://e.com/?utm_id=1'>link<img src=https://x";
        let r = clean_html(html, None, &cfg()).unwrap();
        // Should not panic and should strip the tracking param from the live href.
        assert_eq!(r.urls_cleaned, 1);
        assert!(r.html.contains(r#"href="https://e.com/""#));
    }
}

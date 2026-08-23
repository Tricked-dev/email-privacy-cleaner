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
use percent_encoding::percent_decode_str;
use url::Url;

use crate::config::CleanerConfig;
use crate::redirect::unwrap_redirect_url;

/// Per-message context for HTML cleaning that isn't part of the static config.
///
/// Carries the set of "sensitive" links (e.g. `List-Unsubscribe`
/// targets) whose `href` must be left untouched so recipient-specific tokens
/// survive.
#[derive(Debug, Clone, Default)]
pub struct LinkContext<'a> {
    /// Normalised URLs (serialized `Url` form) that must not be rewritten.
    pub sensitive_urls: Option<&'a HashSet<String>>,
}

impl LinkContext<'_> {
    fn is_sensitive(&self, raw_href: &str, parsed: &Url) -> bool {
        let set = match self.sensitive_urls {
            Some(s) if !s.is_empty() => s,
            _ => return false,
        };
        // Fast path: exact match on either parsed or raw form.
        if set.contains(parsed.as_str()) || set.contains(raw_href.trim()) {
            return true;
        }
        // Robustness path: percent-encoding and parameter-order differences must
        // not break sensitive-link protection. Compare the canonical
        // scheme+host+path+sorted-query form for both sides.
        let our_canon = canonical_link_form(parsed);
        for sensitive in set.iter() {
            if let Ok(s) = Url::parse(sensitive) {
                if canonical_link_form(&s) == our_canon {
                    return true;
                }
            }
        }
        false
    }
}

/// Build a canonical comparison key for a URL: lowercased host, original path
/// (decoded), sorted query parameters. Fragment is dropped.
fn canonical_link_form(u: &Url) -> String {
    let mut q: Vec<(String, String)> = u
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    q.sort();
    let qs: String = q
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");
    let host = u.host_str().unwrap_or("").to_ascii_lowercase();
    format!(
        "{}://{}{}?{}",
        u.scheme(),
        host,
        percent_decode_str(u.path()).decode_utf8_lossy(),
        qs
    )
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
                    // Escape the src so a hostile value can't close the comment
                    // (`-->`) and emit live markup. `--` is also disallowed
                    // inside a comment per HTML spec, so neutralise that too.
                    let src = el.get_attribute("src").unwrap_or_default();
                    let safe = escape_for_html_comment(&src);
                    let comment = format!(
                        "<!-- email-privacy-cleaner removed tracking pixel: src={safe} -->"
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
    let parse_input = normalize_html_attr_url(trimmed);

    let url = match Url::parse(&parse_input) {
        Ok(u) => u,
        Err(url::ParseError::RelativeUrlWithoutBase) => {
            let base = base_url?;
            base.join(&parse_input).ok()?
        }
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

/// HTML mail often serializes query separators in attributes as `&amp;`.
/// `lol_html` gives us the literal attribute text, so normalize the separator
/// before parsing; otherwise `utm_medium` becomes a bogus `amp;utm_medium`
/// parameter and survives cleaning.
pub fn normalize_html_attr_url(href: &str) -> std::borrow::Cow<'_, str> {
    if href.contains("&amp;")
        || href.contains("&AMP;")
        || href.contains("&#38;")
        || href.contains("&#x26;")
        || href.contains("&#X26;")
    {
        std::borrow::Cow::Owned(
            href.replace("&amp;", "&")
                .replace("&AMP;", "&")
                .replace("&#38;", "&")
                .replace("&#x26;", "&")
                .replace("&#X26;", "&"),
        )
    } else {
        std::borrow::Cow::Borrowed(href)
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

    let le2 = |d: Option<u32>| matches!(d, Some(x) if x <= 2);

    // Hidden via CSS, on a remote image → beacon.
    if hidden && is_remote {
        return true;
    }

    // A genuine tracking pixel is normally 1x1 (or at most 2x2). Do not remove
    // one-dimensional layout shims such as 10x1 or 130x5 spacer GIFs.
    let alt = el.get_attribute("alt");
    let alt_empty = alt.as_deref().map(|a| a.trim().is_empty()).unwrap_or(true);
    let both_tiny = le2(w) && le2(h);
    let single_tiny = (le2(w) && h.is_none()) || (le2(h) && w.is_none());
    if alt_empty && is_remote && (both_tiny || single_tiny) {
        return true;
    }

    // No dimensions specified at all + empty/missing alt + remote URL with a
    // tracking-pixel-shaped filename or path is a beacon. This catches the
    // common case `<img src="https://tracker/p.gif">` (no width/height) that
    // the dimension-based heuristic misses.
    if alt_empty && is_remote && w.is_none() && h.is_none() && !has_layout_hint(el) {
        let src_lower = src.to_ascii_lowercase();
        if looks_like_pixel_path(&src_lower) {
            return true;
        }
    }

    false
}

/// Returns `true` if the element carries an attribute that strongly suggests
/// it's a layout/decorative image (a class/id naming an icon/logo/spacer, or
/// `role="presentation"`). Used as a conservative carve-out so we don't drop
/// legit visuals that happen to share a path shape with a beacon.
fn has_layout_hint(el: &lol_html::html_content::Element) -> bool {
    if el
        .get_attribute("role")
        .map(|r| r.eq_ignore_ascii_case("presentation"))
        .unwrap_or(false)
    {
        return true;
    }
    let classy = el
        .get_attribute("class")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let id = el
        .get_attribute("id")
        .unwrap_or_default()
        .to_ascii_lowercase();
    const HINTS: &[&str] = &[
        "logo", "icon", "avatar", "header", "footer", "banner", "hero",
    ];
    HINTS.iter().any(|h| classy.contains(h) || id.contains(h))
}

/// Heuristic: does the URL path/filename look like a tracking pixel?
///
/// Beacons typically have very short, opaque paths or filenames containing
/// words like "open", "pixel", "track", "beacon", or one-letter filenames
/// (`/p.gif`, `/o.gif`, `/t.png`). Legitimate inline images tend to have
/// descriptive filenames (`/logo.png`, `/header-banner.jpg`).
fn looks_like_pixel_path(src_lower: &str) -> bool {
    // Parse out the path component (everything after the host, before `?` / `#`).
    let path = match Url::parse(src_lower) {
        Ok(u) => u.path().to_string(),
        Err(_) => return false,
    };
    let filename = path.rsplit('/').next().unwrap_or("");
    // Single-letter filename stem (`/p.gif`, `/o.gif`, `/t.png`) — a textbook
    // beacon shape.
    if let Some((stem, ext)) = filename.rsplit_once('.') {
        if stem.len() <= 2
            && stem.chars().all(|c| c.is_ascii_alphanumeric())
            && matches!(ext, "gif" | "png" | "jpg" | "jpeg" | "webp" | "bmp")
        {
            return true;
        }
    }
    // Words in the path that almost always indicate a tracker.
    const NEEDLES: &[&str] = &[
        "/open",
        "/pixel",
        "/track",
        "/beacon",
        "/spy",
        "/o.gif",
        "/open.gif",
        "/wf/open",
        "/wf/o",
        "/email-open",
        "/openrate",
    ];
    NEEDLES.iter().any(|n| path.contains(n))
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
                              // Find the matching closing `)`. When the value is quoted, look for the
                              // closing quote first so an unescaped `)` inside the URL doesn't
                              // truncate the token (CSS Spec §4.3.6 — URLs containing `(`/`)` must
                              // be quoted).
        let close = match find_url_close(&style[after..]) {
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

/// Neutralise sequences that would close or invalidate an HTML comment.
fn escape_for_html_comment(s: &str) -> String {
    s.replace("--", "&#45;&#45;").replace('>', "&gt;")
}

/// Find the byte offset of the closing `)` of a CSS `url(...)` token.
///
/// `inner` is the slice starting *just after* the opening `(`. We:
/// 1. Skip leading whitespace.
/// 2. If the value is quoted, scan for the matching close quote, then the next
///    `)` after it.
/// 3. Otherwise, find the first `)`.
///
/// Returns `None` for an unterminated token.
fn find_url_close(inner: &str) -> Option<usize> {
    let bytes = inner.as_bytes();
    let mut i = 0;
    // 1. Skip whitespace.
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\n' | b'\r') {
        i += 1;
    }
    // 2. Quoted form: jump past the matching quote first.
    if i < bytes.len() && (bytes[i] == b'"' || bytes[i] == b'\'') {
        let quote = bytes[i];
        let mut j = i + 1;
        while j < bytes.len() && bytes[j] != quote {
            // Tolerate (but don't honour) CSS escapes — we just need the closing
            // quote, not the actual decoded value.
            if bytes[j] == b'\\' && j + 1 < bytes.len() {
                j += 2;
            } else {
                j += 1;
            }
        }
        if j >= bytes.len() {
            return None; // unterminated quoted url(
        }
        // Now find the `)` after the close quote.
        let mut k = j + 1;
        while k < bytes.len() && bytes[k] != b')' {
            k += 1;
        }
        if k >= bytes.len() {
            return None;
        }
        return Some(k);
    }
    // 3. Unquoted form: stop at the first `)`. Spec forbids `(`/`)` here.
    inner.find(')')
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
    fn keeps_one_dimensional_layout_spacers() {
        let html = concat!(
            r#"<img src="https://static.example.com/spacer.gif" width="10" height="1" alt="">"#,
            r#"<img src="https://static.example.com/spacer.gif" width="1" height="10" alt="">"#,
            r#"<img src="https://static.example.com/spacer.gif" width="130" height="5" alt="">"#
        );
        let r = clean_html(html, None, &cfg()).unwrap();
        assert_eq!(r.pixels_removed, 0);
        assert_eq!(r.html.matches("spacer.gif").count(), 3);
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
        // The live href is cleaned and no breadcrumb is added to the body
        // (`preserve_original_href` defaults to false so we don't leak the
        // tracker into reply quoting).
        assert!(r.html.contains(r#"href="https://shop.example.com/x?id=1""#));
        assert!(!r.html.contains("data-original-href"));
        assert!(!r.html.contains("utm_source"));
    }

    #[test]
    fn preserve_original_href_opt_in_adds_breadcrumb() {
        let mut cfg = cfg();
        cfg.preserve_original_href = true;
        let html = r#"<a href="https://shop.example.com/x?id=1&utm_source=news">buy</a>"#;
        let r = clean_html(html, None, &cfg).unwrap();
        assert_eq!(r.urls_cleaned, 1);
        assert!(r.html.contains(r#"href="https://shop.example.com/x?id=1""#));
        assert!(r
            .html
            .contains(r#"data-original-href="https://shop.example.com/x?id=1&utm_source=news""#));
    }

    #[test]
    fn cleans_html_entity_escaped_query_params() {
        let mut cfg = cfg();
        cfg.preserve_original_href = false;
        let html = r#"<a href="https://shop.example.com/x?id=1&amp;utm_source=news&amp;utm_medium=email&amp;keep=2">buy</a>"#;
        let r = clean_html(html, None, &cfg).unwrap();
        assert_eq!(r.urls_cleaned, 1);
        assert!(r.html.contains("id=1"));
        assert!(r.html.contains("keep=2"));
        assert!(!r.html.contains("utm_source"));
        assert!(!r.html.contains("utm_medium"));
        assert!(!r.html.contains("amp;utm"));
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
    fn pixel_path_heuristic_removes_no_dim_beacons() {
        let cases = [
            r#"<img src="https://tracker.unknown.example/o.gif" alt="">"#,
            r#"<img src="https://tracker.unknown.example/p.png" alt="">"#,
            r#"<img src="https://news.unknown.example/wf/open?a=1" alt="">"#,
            r#"<img src="https://news.unknown.example/open?u=abc" alt="">"#,
            r#"<img src="https://t.unknown.example/track/abc">"#,
        ];
        for html in cases {
            let r = clean_html(html, None, &cfg()).unwrap();
            assert_eq!(
                r.pixels_removed, 1,
                "expected pixel removal for {html} -> {}",
                r.html
            );
        }
    }

    #[test]
    fn pixel_heuristic_spares_descriptive_logos_without_dims() {
        // Descriptive filename, no dims, no alt → keep. The path doesn't match
        // our beacon heuristics, so the image survives.
        let html = r#"<img src="https://cdn.unknown.example/images/banner-summer-sale.jpg">"#;
        let r = clean_html(html, None, &cfg()).unwrap();
        assert_eq!(r.pixels_removed, 0);
        assert!(r.html.contains("banner-summer-sale.jpg"));
    }

    #[test]
    fn pixel_heuristic_spares_logos_with_layout_class() {
        // Short filename but the element carries a layout-y class — keep.
        let html = r#"<img class="logo" src="https://cdn.unknown.example/p.png" alt="">"#;
        let r = clean_html(html, None, &cfg()).unwrap();
        assert_eq!(r.pixels_removed, 0);
    }

    #[test]
    fn pixel_heuristic_spares_images_with_meaningful_alt() {
        let html = r#"<img src="https://tracker.unknown.example/o.gif" alt="Company logo">"#;
        let r = clean_html(html, None, &cfg()).unwrap();
        assert_eq!(r.pixels_removed, 0);
    }

    #[test]
    fn sensitive_link_matches_across_encoding_differences() {
        // Sensitive set stores the percent-encoded variant; HTML carries the
        // partially-decoded form. Both must be treated as sensitive.
        let stored = "https://news.example.com/unsub?uid=42&tok=SECRET";
        let mut set = std::collections::HashSet::new();
        set.insert(Url::parse(stored).unwrap().to_string());
        // Same URL but with query parameters reordered. Without normalization,
        // the old `contains()` check would let utm_source on the unsub link
        // through (we don't add utm here, just verify the match works).
        let html = r#"<a href="https://news.example.com/unsub?tok=SECRET&uid=42">u</a>"#;
        let ctx = LinkContext {
            sensitive_urls: Some(&set),
        };
        let r = clean_html_ctx(html, None, &cfg(), &ctx).unwrap();
        assert_eq!(r.urls_cleaned, 0);
        assert!(r.html.contains("tok=SECRET"));
        assert!(r.html.contains("uid=42"));
    }

    #[test]
    fn css_url_with_quoted_value_containing_paren_is_handled_cleanly() {
        // Quoted form: the `)` inside the URL must NOT close the url() token.
        let html = r#"<div style="background-image:url('https://doubleclick.net/p(1).gif');color:#000"></div>"#;
        let r = clean_html(html, None, &cfg()).unwrap();
        assert_eq!(r.pixels_removed, 1);
        // No leaked tail; the rest of the declaration block is intact.
        assert!(!r.html.contains("doubleclick.net"));
        assert!(!r.html.contains(".gif)"));
        assert!(r.html.contains("color:#000"));
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

//! Tolerant HTML5 sanitization: href cleaning/unwrapping and tracking-pixel
//! removal.
//!
//! Built on `lol_html`, a streaming rewriter, so memory use stays bounded and
//! no network fetching ever happens — we only ever *read* `src` to decide
//! whether to drop an element.

use std::cell::RefCell;

use lol_html::html_content::ContentType;
use lol_html::{element, rewrite_str, RewriteStrSettings};
use url::Url;

use crate::config::CleanerConfig;
use crate::redirect::unwrap_redirect_url;

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
    /// Tracking pixels / beacon images removed.
    pub pixels_removed: usize,
}

#[derive(Default)]
struct Stats {
    urls_cleaned: usize,
    redirects_unwrapped: usize,
    pixels_removed: usize,
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
                if let Some((new_href, kind)) = process_href(&href, base_url, config) {
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

    let output = rewrite_str(
        html,
        RewriteStrSettings {
            element_content_handlers: handlers,
            ..RewriteStrSettings::new()
        },
    )
    .map_err(|e| crate::error::CleanerError::Html(e.to_string()))?;

    let s = stats.into_inner();
    let changed = s.urls_cleaned > 0 || s.redirects_unwrapped > 0 || s.pixels_removed > 0;

    Ok(HtmlCleanResult {
        html: output,
        changed,
        urls_cleaned: s.urls_cleaned,
        redirects_unwrapped: s.redirects_unwrapped,
        pixels_removed: s.pixels_removed,
    })
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

    // Known beacon/tracking host → always drop.
    if let Some(host) = &remote_host {
        if config.is_pixel_domain(host) {
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
    fn handles_malformed_html() {
        let html = "<p>unclosed <a href='https://e.com/?utm_id=1'>link<img src=https://x";
        let r = clean_html(html, None, &cfg()).unwrap();
        // Should not panic and should strip the tracking param from the live href.
        assert_eq!(r.urls_cleaned, 1);
        assert!(r.html.contains(r#"href="https://e.com/""#));
    }
}

//! Stage-1 (offline, deterministic) ESP redirect unwrapping.
//!
//! No network access is ever performed here. A tracking/redirect URL is only
//! unwrapped when the *destination* is explicitly embedded in the URL (usually
//! a query parameter), the destination decodes to a valid `http(s)` URL, and it
//! passes [`validate_destination`](crate::validate::validate_destination).
//!
//! When unwrapping confidence is low (unknown provider, or no valid embedded
//! destination) we keep the original URL but still strip known tracking query
//! parameters.

use percent_encoding::percent_decode_str;
use url::Url;

use crate::config::CleanerConfig;
use crate::url_clean::clean_url;
use crate::validate::{validate_destination, RejectReason};

/// Maximum number of nested URL-decode passes applied to a candidate
/// destination value.
pub const MAX_DECODE_DEPTH: usize = 3;

/// Outcome of [`unwrap_redirect_url`](crate::unwrap_redirect_url).
#[derive(Debug, Clone)]
pub struct RedirectUnwrapResult {
    /// Final URL: the unwrapped destination (query-cleaned) when unwrapping
    /// succeeded, otherwise the original URL with tracking params removed.
    pub url: Url,
    /// The original input URL.
    pub original: Url,
    /// `true` when a destination was successfully extracted and validated.
    pub unwrapped: bool,
    /// The recognised provider, if any (from the rule pack).
    pub provider: Option<String>,
    /// If a candidate destination was found but rejected, why.
    pub rejected: Option<RejectReason>,
}

/// Attempt to unwrap a tracking/redirect URL offline using the rule pack's
/// `redirections` (the destination is extracted from the URL itself — no
/// network access). The extracted destination is always validated before use.
pub fn unwrap_redirect_url(url: &Url, config: &CleanerConfig) -> RedirectUnwrapResult {
    // An excluded host is left entirely untouched (no unwrap, no param strip).
    if let Some(host) = url.host_str() {
        if config.is_excluded_domain(host) {
            return RedirectUnwrapResult {
                url: url.clone(),
                original: url.clone(),
                unwrapped: false,
                provider: None,
                rejected: None,
            };
        }
    }

    let ruleset = config.ruleset();
    let url_str = url.as_str();
    let provider = ruleset.detect_provider(url_str).map(|s| s.to_string());

    if config.unwrap_known_redirects {
        if let Some(raw) = ruleset.redirect_target(url_str) {
            if let Some(candidate) = decode_candidate(&raw) {
                match validate_destination(&candidate) {
                    Ok(()) => {
                        // Clean tracking params off the *destination* too.
                        let cleaned = clean_url(&candidate, config).url;
                        return RedirectUnwrapResult {
                            url: cleaned,
                            original: url.clone(),
                            unwrapped: true,
                            provider,
                            rejected: None,
                        };
                    }
                    Err(reason) => {
                        // A candidate was present but failed validation: keep the
                        // original (query-cleaned) and record why.
                        let cleaned = clean_url(url, config).url;
                        return RedirectUnwrapResult {
                            url: cleaned,
                            original: url.clone(),
                            unwrapped: false,
                            provider,
                            rejected: Some(reason),
                        };
                    }
                }
            }
        }
    }

    // No embedded destination (or unwrapping disabled): keep original but strip
    // tracking params.
    let cleaned = clean_url(url, config).url;
    RedirectUnwrapResult {
        url: cleaned,
        original: url.clone(),
        unwrapped: false,
        provider,
        rejected: None,
    }
}

/// Decode a candidate destination value, peeling up to [`MAX_DECODE_DEPTH`]
/// layers of percent-encoding. Returns the first layer that parses as an
/// absolute `http(s)` URL.
fn decode_candidate(raw: &str) -> Option<Url> {
    let mut current = raw.to_string();

    for _ in 0..=MAX_DECODE_DEPTH {
        if let Ok(u) = Url::parse(&current) {
            if matches!(u.scheme(), "http" | "https") {
                return Some(u);
            }
            // A non-http absolute URL (e.g. javascript:) is a definitive
            // candidate; stop decoding and let validation reject it.
            if u.cannot_be_a_base() || u.scheme() != "" {
                return Some(u);
            }
        }
        let decoded = percent_decode_str(&current)
            .decode_utf8_lossy()
            .into_owned();
        if decoded == current {
            break;
        }
        current = decoded;
    }
    None
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
    fn unwraps_sendgrid_ls_click() {
        let u = Url::parse(
            "https://u1234.ct.sendgrid.net/ls/click?upn=abc&url=https%3A%2F%2Fexample.com%2Farticle%3Futm_source%3Dnews",
        )
        .unwrap();
        let r = unwrap_redirect_url(&u, &cfg());
        assert!(r.unwrapped);
        assert_eq!(r.provider.as_deref(), Some("sendgrid"));
        // utm_source must also be stripped from the destination.
        assert_eq!(r.url.as_str(), "https://example.com/article");
    }

    #[test]
    fn unwraps_nested_encoding() {
        // Double-encoded destination.
        let u = Url::parse("https://links.spgo.io/x?url=https%253A%252F%252Fexample.com%252Fp")
            .unwrap();
        let r = unwrap_redirect_url(&u, &cfg());
        assert!(r.unwrapped);
        assert_eq!(r.url.as_str(), "https://example.com/p");
    }

    #[test]
    fn mailchimp_without_destination_only_cleans_params() {
        // list-manage click links don't embed the destination; we must keep the
        // original but strip mc_cid / mc_eid.
        let u = Url::parse(
            "https://ex.us1.list-manage.com/track/click?u=abc&id=def&e=ghi&mc_cid=111&mc_eid=222",
        )
        .unwrap();
        let r = unwrap_redirect_url(&u, &cfg());
        assert!(!r.unwrapped);
        assert_eq!(r.provider.as_deref(), Some("mailchimp"));
        assert!(!r.url.as_str().contains("mc_cid"));
        assert!(!r.url.as_str().contains("mc_eid"));
        // The non-tracking params survive.
        assert!(r.url.as_str().contains("u=abc"));
    }

    #[test]
    fn rejects_javascript_destination() {
        let u =
            Url::parse("https://u1.ct.sendgrid.net/ls/click?url=javascript%3Aalert(1)").unwrap();
        let r = unwrap_redirect_url(&u, &cfg());
        assert!(!r.unwrapped);
        assert!(matches!(r.rejected, Some(RejectReason::BadScheme(_))));
        // We keep the original (it has no tracking params to strip here).
        assert_eq!(r.provider.as_deref(), Some("sendgrid"));
    }

    #[test]
    fn unknown_host_is_not_unwrapped() {
        // A perfectly normal site that happens to use ?url=
        let u = Url::parse("https://example.com/share?url=https%3A%2F%2Fother.com").unwrap();
        let r = unwrap_redirect_url(&u, &cfg());
        assert!(!r.unwrapped);
        assert_eq!(r.provider, None);
        assert_eq!(r.url.as_str(), u.as_str());
    }
}

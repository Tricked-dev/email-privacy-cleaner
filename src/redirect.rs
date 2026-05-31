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

/// Query parameter names that commonly hold the embedded destination URL.
/// Matched case-insensitively. A candidate is only accepted if its value
/// decodes to a valid `http(s)` URL, so generic-looking names (`u`, `r`) are
/// safe to include — non-URL values are simply ignored.
const DESTINATION_PARAMS: &[&str] = &[
    "url",
    "redirect",
    "redirect_url",
    "target",
    "destination",
    "dest",
    "ru",
    "link",
    "u",
    "r",
];

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
    /// The recognised ESP provider, if any.
    pub provider: Option<&'static str>,
    /// If a candidate destination was found but rejected, why.
    pub rejected: Option<RejectReason>,
}

/// Detect which ESP a tracking URL belongs to, if any.
///
/// Returns a static provider label used both to gate unwrapping (we only unwrap
/// known providers) and for audit/debug output.
pub fn detect_provider(url: &Url) -> Option<&'static str> {
    let host = url.host_str()?.to_ascii_lowercase();
    let path = url.path().to_ascii_lowercase();

    let host_ends = |suffix: &str| host == suffix || host.ends_with(&format!(".{suffix}"));

    // SendGrid: branded click domains, the *.sendgrid.net hosts, or the
    // distinctive /ls/click path.
    if host_ends("sendgrid.net") || host.contains("sendgrid") || path.starts_with("/ls/click") {
        return Some("sendgrid");
    }
    // Mailchimp list-manage click tracking.
    if host_ends("list-manage.com") && path.contains("/track/click") {
        return Some("mailchimp");
    }
    // Mandrill / Mailchimp transactional.
    if host_ends("mandrillapp.com") && path.contains("/track/click") {
        return Some("mandrill");
    }
    // Constant Contact.
    if host_ends("rs6.net") && path.starts_with("/tn.jsp") {
        return Some("constantcontact");
    }
    // HubSpot.
    if host_ends("hs-sites.com") || host_ends("hubspotemail.net") || host_ends("hubspotlinks.com") {
        return Some("hubspot");
    }
    // Customer.io.
    if host_ends("customer.io") && host.starts_with("track.") {
        return Some("customerio");
    }
    // Iterable.
    if host_ends("iterable.com") && host.starts_with("links.") {
        return Some("iterable");
    }
    // Klaviyo.
    if host_ends("klaviyo.com") && host.starts_with("click.") {
        return Some("klaviyo");
    }
    // Mailgun click tracking.
    if host.contains("mailgun") && host.starts_with("email.") {
        return Some("mailgun");
    }
    // Brevo / Sendinblue.
    if host_ends("sibautomation.com") || host.contains("sendibm") {
        return Some("brevo");
    }
    // Postmark.
    if host_ends("pstmrk.it") {
        return Some("postmark");
    }
    // SparkPost.
    if host_ends("spgo.io") || host.starts_with("links.") {
        return Some("sparkpost");
    }

    None
}

/// Attempt to unwrap a tracking/redirect URL offline.
pub fn unwrap_redirect_url(url: &Url, config: &CleanerConfig) -> RedirectUnwrapResult {
    let provider = detect_provider(url);

    // Only attempt extraction for recognised providers; otherwise we'd risk
    // "unwrapping" legitimate `?url=` style links on ordinary sites.
    if let Some(provider) = provider {
        match extract_destination(url) {
            Ok(Some(dest)) => {
                // Clean tracking params off the *destination* too.
                let cleaned = clean_url(&dest, config).url;
                return RedirectUnwrapResult {
                    url: cleaned,
                    original: url.clone(),
                    unwrapped: true,
                    provider: Some(provider),
                    rejected: None,
                };
            }
            Ok(None) => {}
            Err(reason) => {
                // A candidate was present but failed validation: keep original
                // (query-cleaned) and record why.
                let cleaned = clean_url(url, config).url;
                return RedirectUnwrapResult {
                    url: cleaned,
                    original: url.clone(),
                    unwrapped: false,
                    provider: Some(provider),
                    rejected: Some(reason),
                };
            }
        }
    }

    // Low confidence: keep original but strip tracking params.
    let cleaned = clean_url(url, config).url;
    RedirectUnwrapResult {
        url: cleaned,
        original: url.clone(),
        unwrapped: false,
        provider,
        rejected: None,
    }
}

/// Look through the candidate destination parameters and return the first one
/// that decodes to a valid destination.
///
/// * `Ok(Some(url))` — a valid destination was found.
/// * `Ok(None)` — no candidate parameter held a URL-like value.
/// * `Err(reason)` — a URL-like candidate was found but rejected by validation.
fn extract_destination(url: &Url) -> Result<Option<Url>, RejectReason> {
    let mut last_reject: Option<RejectReason> = None;

    for (key, value) in url.query_pairs() {
        let key_lc = key.to_ascii_lowercase();
        if !DESTINATION_PARAMS.iter().any(|p| *p == key_lc) {
            continue;
        }
        if value.is_empty() {
            continue;
        }
        match decode_candidate(&value) {
            Some(candidate) => match validate_destination(&candidate) {
                Ok(()) => return Ok(Some(candidate)),
                Err(reason) => last_reject = Some(reason),
            },
            None => continue,
        }
    }

    match last_reject {
        Some(r) => Err(r),
        None => Ok(None),
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
        assert_eq!(r.provider, Some("sendgrid"));
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
        assert_eq!(r.provider, Some("mailchimp"));
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
        assert_eq!(r.provider, Some("sendgrid"));
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

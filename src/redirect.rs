//! Stage-1 (offline, deterministic) ESP redirect unwrapping.
//!
//! No network access is ever performed here. A tracking/redirect URL is only
//! unwrapped when the *destination* is explicitly embedded in the URL (usually
//! a query parameter), the destination decodes to a valid `http(s)` URL, and it
//! passes [`validate_destination`](crate::validate::validate_destination).
//! Brave-derived rules additionally require a registrable destination host;
//! ClearURLs and built-in rules use the existing validator alone.
//!
//! When unwrapping confidence is low (unknown provider, or no valid embedded
//! destination) we keep the original URL but still strip known tracking query
//! parameters.

use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine;
use percent_encoding::percent_decode_str;
use psl::Psl;
use url::Url;

use crate::config::CleanerConfig;
use crate::ruleset::RedirectOrigin;
use crate::url_clean::clean_url;
use crate::validate::{validate_destination, RejectReason};

/// Maximum number of nested URL-decode passes applied to a candidate
/// destination value.
pub const MAX_DECODE_DEPTH: usize = 3;

/// Shortest candidate worth attempting a base64 decode on. The base64 of the
/// shortest imaginable absolute URL is longer than this, so anything below it
/// is noise.
const MIN_BASE64_LEN: usize = 16;

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
        if let Some(extracted) = ruleset.redirect_target_with_origin(url_str) {
            if let Some(candidate) = decode_candidate(&extracted.target) {
                match validate_destination(&candidate)
                    .and_then(|()| validate_origin_destination(&extracted.origin, url, &candidate))
                {
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

        let resolved = crate::network::resolve(url, config);
        if let Some(resolved_url) = resolved.url {
            let cleaned = clean_url(&resolved_url, config).url;
            return RedirectUnwrapResult {
                unwrapped: cleaned.as_str() != url.as_str(),
                url: cleaned,
                original: url.clone(),
                provider,
                rejected: None,
            };
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

/// Apply the additional safety boundary for Brave-derived redirects only.
///
/// Brave debounce rules intentionally support cross-site redirects, but never
/// same-site redirects.  This mirrors Brave's `IsSameETLDForDebounce` guard:
/// identical hosts and sibling subdomains under one registrable eTLD+1 are
/// rejected, while a destination such as `y2u.be -> youtube.com` is allowed.
/// The common destination validator still rejects unsafe schemes, userinfo,
/// malformed or suspicious hosts, and private IPs.
fn validate_origin_destination(
    origin: &RedirectOrigin,
    source: &Url,
    candidate: &Url,
) -> Result<(), RejectReason> {
    if *origin != RedirectOrigin::Brave {
        return Ok(());
    }

    // Brave's URLPattern/GURL pipeline compares the hostname it extracts from
    // the candidate URL with the parsed hostname before accepting a rewrite.
    // Keep this conservative check even though `url::Url` has already parsed
    // the candidate: it rejects ambiguous authority spellings instead of
    // allowing the two parsers to disagree about the destination host.
    let parsed_candidate_host = candidate.host_str().ok_or(RejectReason::InvalidHost)?;
    let naive_candidate_host =
        naive_hostname_from_url(candidate.as_str()).ok_or(RejectReason::BraveDestinationScope)?;
    if naive_candidate_host != parsed_candidate_host {
        return Err(RejectReason::BraveDestinationScope);
    }

    let source_host = source.host_str().ok_or(RejectReason::InvalidHost)?;
    let source_host = canonical_hostname(source_host);
    let candidate_host = canonical_hostname(parsed_candidate_host);
    if candidate_host.parse::<std::net::IpAddr>().is_ok() {
        return Err(RejectReason::BraveDestinationScope);
    }

    let candidate_domain = registrable_domain_without_private_suffix(candidate_host)
        .ok_or(RejectReason::BraveDestinationScope)?;
    let source_domain = registrable_domain_without_private_suffix(source_host);

    if source_host.eq_ignore_ascii_case(candidate_host)
        || source_domain.is_some_and(|domain| domain.eq_ignore_ascii_case(candidate_domain))
    {
        return Err(RejectReason::BraveDestinationScope);
    }

    Ok(())
}

/// Canonicalize the host spelling used for eTLD+1 comparisons.  URL hosts are
/// case-insensitive and a trailing root dot does not identify another site.
fn canonical_hostname(host: &str) -> &str {
    host.trim_end_matches('.')
}

/// Return the registrable eTLD+1 while following Brave's exclusion of private
/// registry suffixes from debounce same-site checks.
fn registrable_domain_without_private_suffix(host: &str) -> Option<&str> {
    let suffix = psl::List.suffix(host.as_bytes())?;
    if suffix.typ() == Some(psl::Type::Private) {
        return None;
    }
    let domain = psl::List.domain(host.as_bytes())?;
    std::str::from_utf8(domain.as_bytes()).ok()
}

/// Reproduce Brave's deliberately simple hostname extraction check.  This is
/// not a replacement URL parser; it is a mismatch detector for authority
/// spellings that `Url` and the debounce rule's hostname parser interpret
/// differently.
fn naive_hostname_from_url(url: &str) -> Option<&str> {
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    without_scheme
        .split([':', '/', '?'])
        .find(|part| !part.is_empty())
}

/// Decode a candidate destination value, peeling up to [`MAX_DECODE_DEPTH`]
/// layers of percent-encoding, then falling back to base64. Returns the first
/// layer that parses as an absolute URL.
///
/// We return the URL even when its scheme isn't http/https (e.g. `javascript:`,
/// `data:`) so the caller's `validate_destination` can produce a meaningful
/// rejection reason instead of silently swallowing the candidate.
fn decode_candidate(raw: &str) -> Option<Url> {
    let mut current = raw.to_string();

    for _ in 0..=MAX_DECODE_DEPTH {
        if let Ok(u) = Url::parse(&current) {
            // Any parseable absolute URL counts as a candidate: http/https get
            // unwrapped, anything else lets validation produce a BadScheme
            // rejection.
            return Some(u);
        }
        let decoded = percent_decode_str(&current)
            .decode_utf8_lossy()
            .into_owned();
        if decoded == current {
            break;
        }
        current = decoded;
    }
    decode_base64_candidate(&current)
}

/// Several ESPs base64 the destination instead of percent-encoding it: either
/// the URL on its own (Mailjet, Kit) or a small JSON envelope carrying it under
/// `href`/`url` (Customer.io, parcelLab). Both shapes are decoded here; the
/// result is still handed back to the caller for `validate_destination` like
/// any other candidate.
fn decode_base64_candidate(raw: &str) -> Option<Url> {
    let text = String::from_utf8(decode_base64_loose(raw)?).ok()?;
    let text = text.trim();

    if let Ok(u) = Url::parse(text) {
        return Some(u);
    }

    let envelope: serde_json::Value = serde_json::from_str(text).ok()?;
    ["href", "url"]
        .iter()
        .filter_map(|key| envelope.get(key).and_then(serde_json::Value::as_str))
        .find_map(|dest| Url::parse(dest).ok())
}

/// base64-decode accepting the URL-safe and standard alphabets, padded or not —
/// wrappers in the wild use every combination.
fn decode_base64_loose(raw: &str) -> Option<Vec<u8>> {
    let raw = raw.trim_end_matches('=');
    if raw.len() < MIN_BASE64_LEN {
        return None;
    }
    URL_SAFE_NO_PAD
        .decode(raw)
        .or_else(|_| STANDARD_NO_PAD.decode(raw))
        .ok()
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
    fn sendgrid_branded_unwraps_first_param_url() {
        // Regression: an earlier branded-sendgrid regex required `?` or `&`
        // immediately before `url=` AFTER consuming the query separator,
        // which meant `?url=` (url= as the first/only query param) never
        // matched.
        let u = Url::parse(
            "https://mailing.example.com/ls/click?url=https%3A%2F%2Fdest.example%2Fpath",
        )
        .unwrap();
        let r = unwrap_redirect_url(&u, &cfg());
        assert!(r.unwrapped);
        assert_eq!(r.provider.as_deref(), Some("sendgrid_branded"));
        assert_eq!(r.url.as_str(), "https://dest.example/path");
    }

    #[test]
    fn sendgrid_branded_does_not_false_positive_on_substring_url_param() {
        // A query like `?my_url_id=...` contains the substring `url=` but is
        // not a real `url` param. The tightened regex must NOT extract from
        // the substring.
        let u = Url::parse("https://mailing.example.com/ls/click?my_url_id=abc&token=xyz").unwrap();
        let r = unwrap_redirect_url(&u, &cfg());
        assert!(
            !r.unwrapped,
            "must not unwrap from a `my_url_id=` substring"
        );
    }

    #[test]
    fn unwraps_amazon_gp_r_html() {
        // Amazon marketing mail: the destination is the `U=` parameter, and the
        // wrapper carries the per-send `M=urn:rtn:msg:…` click identifier.
        let u = Url::parse(
            "https://www.amazon.co.uk/gp/r.html?C=AAAAAAAAAAAAA&K=BBBBBBBBBBB&M=urn:rtn:msg:00000000000000000000000000000000000000p0eu&R=CCCCCCCCCCCC&T=C&U=https%3A%2F%2Fwww.amazon.co.uk%2Fb%3Fnode%3D123456%26ref_%3Dpe_000000_0000000_TLH_00_01_BT_00&H=DDDDDDDDDDDDDDDDDDDDDDDDDDDD&ref_=pe_000000_0000000_TLH_00_01_BT_00",
        )
        .unwrap();
        let r = unwrap_redirect_url(&u, &cfg());
        assert!(r.unwrapped);
        assert_eq!(r.provider.as_deref(), Some("amazon"));
        // `ref_` is Amazon tracking and must come off the destination too.
        assert_eq!(r.url.as_str(), "https://www.amazon.co.uk/b?node=123456");
    }

    #[test]
    fn unwraps_cl0_path_destination() {
        let u = Url::parse(
            "https://c.example-esp.com/CL0/https:%2F%2Fexample.com%2Fp%3Futm_source=email/1/0000000000000000-00000000/AAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )
        .unwrap();
        let r = unwrap_redirect_url(&u, &cfg());
        assert!(r.unwrapped);
        assert_eq!(r.provider.as_deref(), Some("clicktrack-cl0"));
        assert_eq!(r.url.as_str(), "https://example.com/p");
    }

    #[test]
    fn unwraps_base64_url_in_path_segment() {
        // Mailjet-shaped wrapper: the last path segment is base64url("https://…").
        let u = Url::parse(
            "https://secure.example.com/lnk/AAAAAAAAAAAAAAAAAAAAAAAAAAAA/9/BBBBBBBBBBBBBBBBBBBBBB/aHR0cHM6Ly9leGFtcGxlLmNvbS9wP3V0bV9zb3VyY2U9ZW1haWw",
        )
        .unwrap();
        let r = unwrap_redirect_url(&u, &cfg());
        assert!(r.unwrapped);
        assert_eq!(r.provider.as_deref(), Some("clicktrack-b64-path"));
        assert_eq!(r.url.as_str(), "https://example.com/p");
    }

    #[test]
    fn unwraps_customerio_base64_json_envelope() {
        let u = Url::parse(
            "https://links.example.com/e/c/eyJlbWFpbF9pZCI6IkFBQUFBQUFBQUFBQUFBQUFBQUFBIiwiaHJlZiI6Imh0dHBzOi8vZXhhbXBsZS5jb20vcD91dG1fY2FtcGFpZ249eCIsImxpbmtfaWQiOjF9/00000000000000000000000000000000",
        )
        .unwrap();
        let r = unwrap_redirect_url(&u, &cfg());
        assert!(r.unwrapped);
        assert_eq!(r.provider.as_deref(), Some("customerio-click"));
        assert_eq!(r.url.as_str(), "https://example.com/p");
    }

    #[test]
    fn unwraps_parcellab_base64_json_param() {
        let u = Url::parse(
            "https://parcel-api.versand-status.de/click/000000000000000000000000/forward?to=eyJlbWFpbElkIjoiMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwidXJsIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9ubC8ifQ&sig=00000000000000000000000000000000",
        )
        .unwrap();
        let r = unwrap_redirect_url(&u, &cfg());
        assert!(r.unwrapped);
        assert_eq!(r.provider.as_deref(), Some("parcellab"));
        assert_eq!(r.url.as_str(), "https://example.com/nl/");
    }

    #[test]
    fn base64_segment_that_is_not_a_url_is_not_unwrapped() {
        // `aHR0c…` gates the rule, but a blob that decodes to something other
        // than an absolute URL must leave the link alone.
        let u = Url::parse(
            "https://links.example.com/e/c/eyJlbWFpbF9pZCI6IkFBQUFBQUFBQUFBQUFBQUFBQUFBIn0/abc",
        )
        .unwrap();
        let r = unwrap_redirect_url(&u, &cfg());
        assert!(!r.unwrapped);
        assert_eq!(r.provider.as_deref(), Some("customerio-click"));
    }

    #[test]
    fn unwraps_awstrack_l0_path_destination() {
        let u = Url::parse(
            "https://aaaaaaaa.r.us-east-1.awstrack.me/L0/https:%2F%2Fexample.com%2Fhome%3Futm_medium=crm/1/0000000000000000-00000000/AAAAAAAAAAAAAAAAAAAAAAAAAAA=000",
        )
        .unwrap();
        let r = unwrap_redirect_url(&u, &cfg());
        assert!(r.unwrapped);
        assert_eq!(r.provider.as_deref(), Some("awstrack"));
        assert_eq!(r.url.as_str(), "https://example.com/home");
    }

    #[test]
    fn awstrack_open_beacon_without_destination_is_not_unwrapped() {
        // Open-tracking beacons have no destination segment — the wrapper must
        // survive rather than be rewritten to something invented.
        let u = Url::parse(
            "https://aaaaaaaa.r.us-east-1.awstrack.me/I0/0000000000000000-00000000/AAAAAAAAAAAAAAAAAAAAAAAAAAA=000",
        )
        .unwrap();
        let r = unwrap_redirect_url(&u, &cfg());
        assert!(!r.unwrapped);
        assert_eq!(r.provider.as_deref(), Some("awstrack"));
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

//! Tracking query-parameter removal with source-specific matching semantics.
//!
//! The compiled rule store keeps the input format's query model intact:
//!
//! * ClearURLs rules match form/percent-decoded parameter names
//!   case-insensitively, including query segments without `=`.
//! * Brave Clean URLs rules compare the raw query key case-sensitively and
//!   remove it only when the segment contains `=`.
//! * AdGuard named `$removeparam=name` rules match a decoded name (with
//!   `$match-case` controlling the name comparison) and also apply to
//!   no-value segments; regex `$removeparam=/name=value/` rules match the
//!   decoded `name=value` pair and require `=`.
//!
//! These format-specific rules are evaluated alongside the user's global
//! tracking-parameter list. A source's exception only affects the compatible
//! action and scope; it does not suppress unrelated rules from another format.
//! The legacy [`Ruleset::param_is_tracking`](crate::ruleset::Ruleset::param_is_tracking)
//! helper accepts a bare name for compatibility, but this cleaner always
//! passes the original query segment so a Brave no-value segment is preserved.

use percent_encoding::percent_decode_str;
use url::Url;

use crate::config::CleanerConfig;

/// Outcome of [`clean_url`].
#[derive(Debug, Clone)]
pub struct UrlCleanResult {
    /// The cleaned URL (equal to the input when nothing changed).
    pub url: Url,
    /// Whether any parameter was removed.
    pub changed: bool,
    /// Names of the parameters that were removed.
    pub removed_params: Vec<String>,
}

/// Remove known tracking query parameters from `url`.
///
/// Removal combines the user-supplied global params (`extra_tracking_params`)
/// with the rule pack: global rules always apply, host-specific (vendor) rules
/// apply when `apply_vendor_rules` is set, and referral-marketing rules apply
/// when `strip_referral_marketing` is set. Rule-pack matching follows the
/// source-specific semantics documented at the top of this module; the
/// user-supplied global list uses the decoded parameter name. The raw encoding
/// of surviving parameters is preserved byte-for-byte so we don't accidentally
/// re-encode values (which could break signed/magic links).
pub fn clean_url(url: &Url, config: &CleanerConfig) -> UrlCleanResult {
    let query = match url.query() {
        Some(q) if !q.is_empty() => q,
        _ => {
            return UrlCleanResult {
                url: url.clone(),
                changed: false,
                removed_params: Vec::new(),
            }
        }
    };

    let ruleset = config.ruleset();
    let url_str = url.as_str();

    // An excluded host means "leave this URL as-is". Provider exceptions are
    // evaluated per action below; they must not suppress unrelated global,
    // Brave, or user-defined rules.
    let excluded = url
        .host_str()
        .map(|h| config.is_excluded_domain(h))
        .unwrap_or(false);
    if excluded {
        return UrlCleanResult {
            url: url.clone(),
            changed: false,
            removed_params: Vec::new(),
        };
    }

    // Scope matching is URL-level work. Keep one immutable context for every
    // query segment so source-specific raw/decoded semantics and exceptions
    // are applied consistently without rescanning provider scopes.
    let context = ruleset.context_for(url_str, url);

    let mut kept: Vec<&str> = Vec::new();
    let mut removed: Vec<String> = Vec::new();

    for segment in query.split('&') {
        if segment.is_empty() {
            continue;
        }
        let key_raw = segment.split('=').next().unwrap_or("");
        // Form-decode the key for matching: '+' -> space, then percent-decode.
        let key_plus = key_raw.replace('+', " ");
        let key = percent_decode_str(&key_plus).decode_utf8_lossy();

        // The keep-list always wins, even over a matching rule.
        let is_tracker = !config.is_kept_param(&key)
            && (config.is_tracking_param(&key)
                || context.should_remove_parameter(
                    segment,
                    config.apply_vendor_rules,
                    config.strip_referral_marketing,
                ));

        if is_tracker {
            removed.push(key.into_owned());
        } else {
            kept.push(segment);
        }
    }

    if removed.is_empty() {
        return UrlCleanResult {
            url: url.clone(),
            changed: false,
            removed_params: Vec::new(),
        };
    }

    let mut out = url.clone();
    if kept.is_empty() {
        out.set_query(None);
    } else {
        out.set_query(Some(&kept.join("&")));
    }

    UrlCleanResult {
        url: out,
        changed: true,
        removed_params: removed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{RulePackFormat, RulePackSource};

    fn cfg() -> CleanerConfig {
        let mut c = CleanerConfig::default();
        c.finalize();
        c
    }

    #[test]
    fn removes_utm_and_keeps_real_params() {
        let u =
            Url::parse("https://shop.example.com/p?id=42&utm_source=news&utm_medium=email&q=hi")
                .unwrap();
        let r = clean_url(&u, &cfg());
        assert!(r.changed);
        assert_eq!(r.url.as_str(), "https://shop.example.com/p?id=42&q=hi");
        assert_eq!(r.removed_params.len(), 2);
    }

    #[test]
    fn case_insensitive_match() {
        let u = Url::parse("https://e.com/?UTM_Source=x&Keep=1").unwrap();
        let r = clean_url(&u, &cfg());
        assert_eq!(r.url.as_str(), "https://e.com/?Keep=1");
    }

    #[test]
    fn removes_all_params() {
        let u = Url::parse("https://e.com/path?fbclid=abc").unwrap();
        let r = clean_url(&u, &cfg());
        assert!(r.changed);
        assert_eq!(r.url.as_str(), "https://e.com/path");
    }

    #[test]
    fn preserves_value_encoding() {
        // The kept parameter's value must not be re-encoded.
        let u = Url::parse("https://e.com/?token=a%2Bb%2Fc&utm_id=9").unwrap();
        let r = clean_url(&u, &cfg());
        assert_eq!(r.url.as_str(), "https://e.com/?token=a%2Bb%2Fc");
    }

    #[test]
    fn no_query_is_noop() {
        let u = Url::parse("https://e.com/path").unwrap();
        let r = clean_url(&u, &cfg());
        assert!(!r.changed);
    }

    #[test]
    fn vendor_rules_strip_amazon_tracking_only() {
        let u = Url::parse(
            "https://www.amazon.com/dp/B000?ref=foo&pf_rd_r=ABC&pd_rd_w=xyz&th=1&keywords=cable",
        )
        .unwrap();
        let r = clean_url(&u, &cfg());
        assert!(r.changed);
        let s = r.url.as_str();
        assert!(!s.contains("ref="));
        assert!(!s.contains("pf_rd_r"));
        assert!(!s.contains("pd_rd_w"));
        // Functional params survive.
        assert!(s.contains("th=1"));
        assert!(s.contains("keywords=cable"));
    }

    #[test]
    fn vendor_rules_are_host_scoped() {
        // `pf_rd_r` is Amazon-only tracking; on another host it must survive
        // (and it is not in the global tracking-param table).
        let u = Url::parse("https://shop.example.com/p?pf_rd_r=affiliate&id=5").unwrap();
        let r = clean_url(&u, &cfg());
        assert!(!r.changed);
        assert!(r.url.as_str().contains("pf_rd_r=affiliate"));
    }

    #[test]
    fn vendor_rules_can_be_disabled() {
        let mut c = CleanerConfig::default();
        c.apply_vendor_rules = false;
        c.finalize();
        // pf_rd_r is vendor-only; with vendor rules off and no global match it
        // must survive.
        let u = Url::parse("https://www.amazon.com/dp/B000?pf_rd_r=foo&id=1").unwrap();
        let r = clean_url(&u, &c);
        assert!(!r.changed);
    }

    #[test]
    fn clearurls_matches_decoded_case_insensitive_names_with_or_without_values() {
        let mut c = CleanerConfig::default();
        c.rule_packs = vec![write_pack(
            r#"{"providers":{"clear":{"urlPattern":"^https?://example\\.test","rules":["trk"]}}}"#,
        )];
        c.finalize();
        let _ = std::fs::remove_file(&c.rule_packs[0]);

        let u = Url::parse("https://example.test/p?TRK&tr%6b=value&keep=1").unwrap();
        let r = clean_url(&u, &c);
        assert_eq!(r.url.as_str(), "https://example.test/p?keep=1");
    }

    #[test]
    fn clearurls_provider_exception_preserves_legacy_clearurls_carveout() {
        let mut c = CleanerConfig::default();
        c.rule_packs = vec![write_pack(
            r#"{"providers":{"clear":{"urlPattern":"^https?://example\\.test","rules":["provider_id"],"exceptions":["keep"]}}}"#,
        )];
        c.finalize();
        let _ = std::fs::remove_file(&c.rule_packs[0]);

        let u = Url::parse("https://example.test/p?provider_id=1&keep=1&utm_source=x").unwrap();
        let r = clean_url(&u, &c);
        assert_eq!(
            r.url.as_str(),
            "https://example.test/p?provider_id=1&keep=1&utm_source=x"
        );
    }

    #[test]
    fn brave_configured_source_keeps_raw_case_and_requires_equals() {
        let mut c = CleanerConfig::default();
        c.disabled_providers = vec!["globalRules".into()];
        c.rule_pack_sources = vec![RulePackSource {
            source: write_pack(
                r#"[{"include":["*://example.test/*"],"exclude":[],"params":["UTM_Source"]}]"#,
            ),
            format: Some(RulePackFormat::BraveCleanUrls),
            usage: None,
        }];
        c.finalize();
        let _ = std::fs::remove_file(&c.rule_pack_sources[0].source);

        let u = Url::parse("https://example.test/p?UTM_Source=x&utm_source=x&UTM_Source&keep=1")
            .unwrap();
        let r = clean_url(&u, &c);
        assert_eq!(
            r.url.as_str(),
            "https://example.test/p?utm_source=x&UTM_Source&keep=1"
        );
    }

    fn write_pack(json: &str) -> String {
        let path = std::env::temp_dir().join(format!(
            "epc-url-clean-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, json).unwrap();
        path.to_string_lossy().into_owned()
    }
}

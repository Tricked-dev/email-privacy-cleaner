//! Vendor-specific (per-destination-domain) URL cleaning rules.
//!
//! Unlike [`DEFAULT_TRACKING_PARAMS`](crate::config::DEFAULT_TRACKING_PARAMS),
//! which are stripped from *every* URL, the rules here only apply when the
//! URL's host matches a specific vendor. This lets us remove parameters that
//! are pure tracking *for that vendor* (e.g. Amazon's `ref`, `pf_rd_*`) without
//! risking the same name being meaningful on another site.
//!
//! Matching is host-suffix based and case-insensitive. Parameter names are
//! matched case-insensitively, either exactly or — for families like Amazon's
//! `pf_rd_r`, `pf_rd_p`, … — by prefix.
//!
//! This is a hardcoded, curated table (ClearURLs-style) and is deliberately
//! conservative: only parameters that are known to carry no functional meaning
//! are listed. Search terms, item IDs, pagination, etc. are never included.

/// A single vendor rule: the host suffixes it applies to and the parameter
/// names (exact + prefix) it strips.
pub struct VendorRule {
    /// Human-readable vendor label (used by `explain-url` / `print-trackers`).
    pub name: &'static str,
    /// Host suffixes this rule applies to (matched as `host == s` or
    /// `host.ends_with(".{s}")`).
    pub suffixes: &'static [&'static str],
    /// Parameter names removed by exact (case-insensitive) match.
    pub exact: &'static [&'static str],
    /// Parameter names removed when they start with one of these prefixes.
    pub prefixes: &'static [&'static str],
}

/// The curated vendor rule table.
pub const VENDOR_RULES: &[VendorRule] = &[
    VendorRule {
        name: "amazon",
        suffixes: &[
            "amazon.com",
            "amazon.co.uk",
            "amazon.de",
            "amazon.fr",
            "amazon.it",
            "amazon.es",
            "amazon.nl",
            "amazon.se",
            "amazon.pl",
            "amazon.com.tr",
            "amazon.co.jp",
            "amazon.cn",
            "amazon.in",
            "amazon.com.au",
            "amazon.com.br",
            "amazon.com.mx",
            "amazon.ca",
            "amazon.sg",
            "amazon.ae",
            "amazon.sa",
            "amzn.to",
        ],
        exact: &[
            "ref",
            "ref_",
            "_encoding",
            "psc",
            "qid",
            "sr",
            "sprefix",
            "crid",
            "dib",
            "dib_tag",
            "content-id",
            "linkcode",
            "tag",
            "ascsubtag",
            "smid",
            "spia",
            "linkid",
            "creativeasin",
            "creative",
            "camp",
        ],
        prefixes: &["pf_rd_", "pd_rd_"],
    },
    VendorRule {
        name: "ebay",
        suffixes: &["ebay.com", "ebay.co.uk", "ebay.de", "ebay.com.au"],
        exact: &[
            "_trkparms",
            "_trksid",
            "_from",
            "hash",
            "ul_noapp",
            "mkcid",
            "mkrid",
            "mkevt",
            "campid",
            "toolid",
            "customid",
            "siteid",
            "amdata",
        ],
        prefixes: &[],
    },
    VendorRule {
        name: "youtube",
        suffixes: &["youtube.com", "youtu.be", "youtube-nocookie.com"],
        exact: &["si", "feature", "pp", "kw"],
        prefixes: &[],
    },
    VendorRule {
        name: "google",
        suffixes: &["google.com", "google.co.uk", "google.de", "google.fr"],
        exact: &[
            "ved", "ei", "gs_l", "gs_lcp", "sa", "oq", "sclient", "uact", "sxsrf", "gws_rd",
            "gbv", "sourceid", "client", "dpr",
        ],
        prefixes: &[],
    },
    VendorRule {
        name: "twitter",
        suffixes: &["twitter.com", "x.com", "t.co"],
        exact: &["s", "t", "ref_src", "ref_url", "cn", "refsrc"],
        prefixes: &[],
    },
    VendorRule {
        name: "facebook",
        suffixes: &["facebook.com", "fb.com", "fb.watch"],
        exact: &["mibextid", "comment_tracking", "rdid", "share_url", "refsrc", "hrc"],
        prefixes: &[],
    },
    VendorRule {
        name: "instagram",
        suffixes: &["instagram.com"],
        exact: &["igsh", "img_index"],
        prefixes: &[],
    },
    VendorRule {
        name: "linkedin",
        suffixes: &["linkedin.com", "lnkd.in"],
        exact: &[
            "trk",
            "trkinfo",
            "originalsubdomain",
            "midtoken",
            "eid",
            "otptoken",
            "li_fat_id",
            "refid",
        ],
        prefixes: &[],
    },
    VendorRule {
        name: "reddit",
        suffixes: &["reddit.com", "redd.it"],
        exact: &[
            "share_id",
            "correlation_id",
            "ref",
            "ref_source",
            "rdt",
            "$deep_link",
            "$original_url",
        ],
        prefixes: &[],
    },
    VendorRule {
        name: "tiktok",
        suffixes: &["tiktok.com"],
        exact: &[
            "_t",
            "_r",
            "is_copy_url",
            "is_from_webapp",
            "sender_device",
            "sender_web_id",
        ],
        prefixes: &[],
    },
    VendorRule {
        name: "spotify",
        suffixes: &["spotify.com", "open.spotify.com"],
        exact: &["si", "nd", "context"],
        prefixes: &[],
    },
    VendorRule {
        name: "aliexpress",
        suffixes: &["aliexpress.com", "aliexpress.us"],
        exact: &[
            "spm",
            "scm",
            "pvid",
            "algo_pvid",
            "algo_expid",
            "btsid",
            "ws_ab_test",
            "gatewayadapt",
        ],
        prefixes: &[],
    },
    VendorRule {
        name: "medium",
        suffixes: &["medium.com"],
        exact: &["source", "sk"],
        prefixes: &[],
    },
];

/// Returns the vendor label whose rule matches `host`, if any.
pub fn vendor_for_host(host: &str) -> Option<&'static str> {
    let host = host.to_ascii_lowercase();
    rule_for_host(&host).map(|r| r.name)
}

fn rule_for_host(host_lc: &str) -> Option<&'static VendorRule> {
    VENDOR_RULES.iter().find(|rule| {
        rule.suffixes
            .iter()
            .any(|s| host_lc == *s || host_lc.ends_with(&format!(".{s}")))
    })
}

/// Returns `true` if `param` (already lowercased by the caller is not required;
/// we lowercase internally) is a vendor tracking parameter for `host`.
pub fn is_vendor_tracking_param(host: &str, param: &str) -> bool {
    let host_lc = host.to_ascii_lowercase();
    let param_lc = param.to_ascii_lowercase();
    match rule_for_host(&host_lc) {
        Some(rule) => {
            rule.exact.iter().any(|p| *p == param_lc)
                || rule.prefixes.iter().any(|p| param_lc.starts_with(p))
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amazon_ref_and_pf_rd_are_tracking() {
        assert!(is_vendor_tracking_param("www.amazon.com", "ref"));
        assert!(is_vendor_tracking_param("amazon.co.uk", "pf_rd_r"));
        assert!(is_vendor_tracking_param("smile.amazon.de", "pd_rd_w"));
        assert!(is_vendor_tracking_param("www.amazon.com", "TAG"));
        // A real functional param must survive.
        assert!(!is_vendor_tracking_param("www.amazon.com", "node"));
        assert!(!is_vendor_tracking_param("www.amazon.com", "k")); // search keywords
    }

    #[test]
    fn rules_are_host_scoped() {
        // `ref` is Amazon/Reddit tracking, but must not be stripped elsewhere.
        assert!(!is_vendor_tracking_param("shop.example.com", "ref"));
        // `s` is Twitter tracking, but not generic.
        assert!(is_vendor_tracking_param("x.com", "s"));
        assert!(!is_vendor_tracking_param("example.com", "s"));
    }

    #[test]
    fn vendor_label_lookup() {
        assert_eq!(vendor_for_host("www.amazon.com"), Some("amazon"));
        assert_eq!(vendor_for_host("youtu.be"), Some("youtube"));
        assert_eq!(vendor_for_host("example.com"), None);
    }
}

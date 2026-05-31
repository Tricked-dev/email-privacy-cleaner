//! ClearURLs-format rule engine.
//!
//! The built-in rules ship as a JSON document in the [ClearURLs] data format
//! (`rules/builtin.json`, compiled into the binary). The same parser loads
//! external packs — including the real ClearURLs `data.min.json` — so coverage
//! can be extended without code changes (see [`CleanerConfig`] `rule_packs` /
//! `rule_pack_urls`).
//!
//! [ClearURLs]: https://docs.clearurls.xyz/latest/specs/rules/
//!
//! ## Format support
//!
//! For each provider we honour:
//! * `urlPattern` — regex gating which URLs the provider applies to.
//! * `rules` — regexes matched against query-parameter **names** to strip.
//! * `referralMarketing` — like `rules`, but only stripped when the operator
//!   opts in (`strip_referral_marketing`).
//! * `rawRules` — regexes whose matches are removed from the whole URL string.
//! * `exceptions` — if any matches the URL, the URL is left untouched.
//! * `redirections` — regex whose **first capture group** is the (often
//!   percent-encoded) embedded destination, used for offline unwrapping. The
//!   extracted destination is always re-validated by the caller
//!   ([`crate::validate`]) before any link is rewritten.
//! * `completeProvider` — marks a pure tracker/beacon host. We use it **only**
//!   for tracking-pixel / remote-image host detection; we never neutralise an
//!   `<a>` link on this basis (that would break legitimate click-throughs).
//!
//! All regexes are compiled with the linear-time `regex` crate (RE2-style, no
//! catastrophic backtracking). Patterns that use features the crate doesn't
//! support (e.g. lookaround) simply fail to compile and are skipped — the rest
//! of the pack still loads.

use std::collections::BTreeMap;

use regex::Regex;
use serde::Deserialize;

use crate::error::{CleanerError, Result};

/// The built-in rule pack, in ClearURLs JSON format.
const BUILTIN_JSON: &str = include_str!("../rules/builtin.json");

#[derive(Debug, Deserialize)]
struct RawRuleset {
    providers: BTreeMap<String, RawProvider>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawProvider {
    url_pattern: String,
    #[serde(default)]
    complete_provider: bool,
    #[serde(default)]
    rules: Vec<String>,
    #[serde(default)]
    raw_rules: Vec<String>,
    #[serde(default)]
    referral_marketing: Vec<String>,
    #[serde(default)]
    exceptions: Vec<String>,
    #[serde(default)]
    redirections: Vec<String>,
}

/// A compiled provider.
#[derive(Debug)]
struct Provider {
    name: String,
    is_global: bool,
    complete: bool,
    url_pattern: Regex,
    rules: Vec<Regex>,
    referral: Vec<Regex>,
    raw_rules: Vec<Regex>,
    exceptions: Vec<Regex>,
    redirections: Vec<Regex>,
}

/// A compiled set of providers.
#[derive(Debug, Default)]
pub struct Ruleset {
    providers: Vec<Provider>,
    /// Number of individual regex patterns that failed to compile and were
    /// skipped (e.g. unsupported lookaround in an external pack).
    pub skipped_patterns: usize,
}

/// Compile a parameter-name rule: anchored, case-insensitive full match.
fn compile_name_rule(pat: &str) -> Option<Regex> {
    Regex::new(&format!("(?i)^(?:{pat})$")).ok()
}

/// Compile a whole-URL rule: case-insensitive, not anchored.
fn compile_url_rule(pat: &str) -> Option<Regex> {
    Regex::new(&format!("(?i){pat}")).ok()
}

fn compile_many(pats: &[String], name_rule: bool, skipped: &mut usize) -> Vec<Regex> {
    pats.iter()
        .filter_map(|p| {
            let r = if name_rule {
                compile_name_rule(p)
            } else {
                compile_url_rule(p)
            };
            if r.is_none() {
                *skipped += 1;
            }
            r
        })
        .collect()
}

impl Ruleset {
    /// The compiled built-in rule pack.
    pub fn builtin() -> Ruleset {
        Self::from_clearurls_str(BUILTIN_JSON).expect("built-in rules/builtin.json must be valid")
    }

    /// Parse and compile a ClearURLs-format rule document.
    pub fn from_clearurls_str(json: &str) -> Result<Ruleset> {
        let raw: RawRuleset = serde_json::from_str(json)
            .map_err(|e| CleanerError::Config(format!("rule pack: {e}")))?;

        let mut providers = Vec::with_capacity(raw.providers.len());
        let mut skipped = 0usize;

        for (name, p) in raw.providers {
            let url_pattern = match compile_url_rule(&p.url_pattern) {
                Some(r) => r,
                None => {
                    // A provider whose urlPattern won't compile is useless; skip it.
                    skipped += 1;
                    continue;
                }
            };
            providers.push(Provider {
                is_global: name == "globalRules",
                complete: p.complete_provider,
                url_pattern,
                rules: compile_many(&p.rules, true, &mut skipped),
                referral: compile_many(&p.referral_marketing, true, &mut skipped),
                raw_rules: compile_many(&p.raw_rules, false, &mut skipped),
                exceptions: compile_many(&p.exceptions, false, &mut skipped),
                redirections: compile_many(&p.redirections, false, &mut skipped),
                name,
            });
        }

        Ok(Ruleset {
            providers,
            skipped_patterns: skipped,
        })
    }

    /// Merge another ruleset's providers into this one (the other pack augments
    /// this one; both sets of providers are evaluated).
    pub fn merge(&mut self, mut other: Ruleset) {
        self.providers.append(&mut other.providers);
        self.skipped_patterns += other.skipped_patterns;
    }

    /// Number of compiled providers.
    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }

    /// Remove providers whose name matches any of `names` (case-insensitive).
    /// Used to honour the `disabled_providers` config exclusion.
    pub fn disable(&mut self, names: &[String]) {
        let disabled: Vec<String> = names.iter().map(|n| n.to_ascii_lowercase()).collect();
        self.providers
            .retain(|p| !disabled.contains(&p.name.to_ascii_lowercase()));
    }

    fn matching<'a>(&'a self, url: &'a str) -> impl Iterator<Item = &'a Provider> + 'a {
        self.providers
            .iter()
            .filter(move |p| p.url_pattern.is_match(url))
    }

    /// Returns `true` if any matching provider declares an exception for `url`.
    pub fn is_exception(&self, url: &str) -> bool {
        self.matching(url)
            .any(|p| p.exceptions.iter().any(|e| e.is_match(url)))
    }

    /// Returns `true` if `name` is a tracking parameter for `url`.
    ///
    /// `include_vendor` gates host-specific (non-global) providers; global rules
    /// always apply. `include_referral` additionally applies referral-marketing
    /// rules.
    pub fn param_is_tracking(
        &self,
        url: &str,
        name: &str,
        include_vendor: bool,
        include_referral: bool,
    ) -> bool {
        for p in &self.providers {
            if !p.is_global && !include_vendor {
                continue;
            }
            if !p.url_pattern.is_match(url) {
                continue;
            }
            if p.rules.iter().any(|r| r.is_match(name)) {
                return true;
            }
            if include_referral && p.referral.iter().any(|r| r.is_match(name)) {
                return true;
            }
        }
        false
    }

    /// The first non-global provider whose `urlPattern` matches, if any.
    pub fn detect_provider(&self, url: &str) -> Option<&str> {
        self.providers
            .iter()
            .find(|p| !p.is_global && p.url_pattern.is_match(url))
            .map(|p| p.name.as_str())
    }

    /// Extract the raw (still possibly percent-encoded) redirect destination
    /// from the first matching `redirections` rule, if any. The caller decodes
    /// and validates it.
    pub fn redirect_target(&self, url: &str) -> Option<String> {
        for p in self.matching(url) {
            for re in &p.redirections {
                if let Some(caps) = re.captures(url) {
                    if let Some(m) = caps.get(1) {
                        return Some(m.as_str().to_string());
                    }
                }
            }
        }
        None
    }

    /// Apply `rawRules` (whole-URL substring removal) to `url`, returning the
    /// possibly-rewritten string and whether anything changed.
    pub fn apply_raw_rules(&self, url: &str) -> (String, bool) {
        let mut current = url.to_string();
        let mut changed = false;
        for p in self.matching(url) {
            for re in &p.raw_rules {
                if re.is_match(&current) {
                    current = re.replace_all(&current, "").into_owned();
                    changed = true;
                }
            }
        }
        (current, changed)
    }

    /// Returns `true` if `url` matches a `completeProvider` (pure tracker /
    /// beacon host). Used for tracking-pixel detection only.
    pub fn is_complete_block(&self, url: &str) -> bool {
        self.matching(url).any(|p| p.complete)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_compiles_with_no_skipped_patterns() {
        let rs = Ruleset::builtin();
        assert!(rs.provider_count() >= 20);
        assert_eq!(
            rs.skipped_patterns, 0,
            "every built-in pattern must compile cleanly"
        );
    }

    #[test]
    fn global_params_match_anywhere() {
        let rs = Ruleset::builtin();
        assert!(rs.param_is_tracking("https://anywhere.example/x", "utm_source", true, false));
        assert!(rs.param_is_tracking("https://anywhere.example/x", "fbclid", false, false));
        assert!(!rs.param_is_tracking("https://anywhere.example/x", "id", true, false));
    }

    #[test]
    fn vendor_params_are_host_scoped_and_gated() {
        let rs = Ruleset::builtin();
        // pf_rd_r is Amazon-only.
        assert!(rs.param_is_tracking("https://www.amazon.com/dp/x", "pf_rd_r", true, false));
        assert!(!rs.param_is_tracking("https://shop.example.com/x", "pf_rd_r", true, false));
        // With vendor rules disabled, even on Amazon it isn't matched.
        assert!(!rs.param_is_tracking("https://www.amazon.com/dp/x", "pf_rd_r", false, false));
    }

    #[test]
    fn detects_providers_and_redirect_targets() {
        let rs = Ruleset::builtin();
        assert_eq!(
            rs.detect_provider("https://news.us1.list-manage.com/track/click?u=1"),
            Some("mailchimp")
        );
        let t = rs
            .redirect_target(
                "https://u1.ct.sendgrid.net/ls/click?upn=a&url=https%3A%2F%2Fx.example",
            )
            .unwrap();
        assert_eq!(t, "https%3A%2F%2Fx.example");
        // Mailchimp has no redirection.
        assert!(rs
            .redirect_target("https://news.us1.list-manage.com/track/click?u=1")
            .is_none());
    }

    #[test]
    fn complete_provider_marks_beacon_hosts() {
        let rs = Ruleset::builtin();
        assert!(rs.is_complete_block("https://doubleclick.net/pixel"));
        assert!(!rs.is_complete_block("https://cdn.example.com/hero.jpg"));
    }

    #[test]
    fn external_pack_augments_builtin() {
        let mut rs = Ruleset::builtin();
        let pack = r#"{"providers":{"acme":{
            "urlPattern":"^https?://(?:[a-z0-9-]+\\.)*?acme\\.example",
            "rules":["sid","trk_.*"]}}}"#;
        let extra = Ruleset::from_clearurls_str(pack).unwrap();
        let before = rs.provider_count();
        rs.merge(extra);
        assert_eq!(rs.provider_count(), before + 1);
        // New vendor rule applies on its host...
        assert!(rs.param_is_tracking("https://shop.acme.example/x", "sid", true, false));
        assert!(rs.param_is_tracking("https://shop.acme.example/x", "trk_abc", true, false));
        // ...but not elsewhere, and the built-in globals still work.
        assert!(!rs.param_is_tracking("https://other.example/x", "sid", true, false));
        assert!(rs.param_is_tracking("https://other.example/x", "utm_source", true, false));
    }

    #[test]
    fn disable_removes_named_providers() {
        let mut rs = Ruleset::builtin();
        assert_eq!(
            rs.detect_provider("https://www.amazon.com/dp/x"),
            Some("amazon")
        );
        rs.disable(&["AMAZON".to_string()]);
        assert_eq!(rs.detect_provider("https://www.amazon.com/dp/x"), None);
        // Other providers remain.
        assert_eq!(
            rs.detect_provider("https://news.us1.list-manage.com/track/click?u=1"),
            Some("mailchimp")
        );
    }

    #[test]
    fn referral_marketing_only_strips_when_enabled() {
        let pack = r#"{"providers":{"shop":{
            "urlPattern":"^https?://shop\\.example",
            "referralMarketing":["aff_id"]}}}"#;
        let rs = Ruleset::from_clearurls_str(pack).unwrap();
        let url = "https://shop.example/p?aff_id=9";
        assert!(!rs.param_is_tracking(url, "aff_id", true, false));
        assert!(rs.param_is_tracking(url, "aff_id", true, true));
    }
}

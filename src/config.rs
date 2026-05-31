//! Runtime configuration for the cleaner.
//!
//! The configuration is normally loaded from a TOML file (see
//! `config.example.toml`), but [`CleanerConfig`] also implements [`Default`]
//! so the library can be used without any config file.

use serde::Deserialize;
use std::borrow::Cow;
use std::collections::HashSet;
use std::path::Path;
use std::sync::{Arc, OnceLock};

use crate::error::{CleanerError, Result};
use crate::ruleset::Ruleset;

/// Operating mode of the cleaner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    /// Compute what *would* be cleaned and emit audit headers, but never alter
    /// the message body.
    ReportOnly,
    /// Actually rewrite the message body.
    #[default]
    Enforce,
}

impl Mode {
    /// Header-friendly string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::ReportOnly => "report-only",
            Mode::Enforce => "enforce",
        }
    }

    /// `true` when the body should actually be modified.
    pub fn is_enforce(self) -> bool {
        matches!(self, Mode::Enforce)
    }
}

// The default tracking parameters, vendor rules, ESP redirect unwrappers and
// known beacon/pixel hosts now live in the built-in ClearURLs-format rule pack
// (`rules/builtin.json`, compiled in via [`Ruleset::builtin`]). The TOML keys
// `extra_tracking_params` / `extra_pixel_domains` still layer user additions on
// top, and `rule_packs` / `rule_pack_urls` load external ClearURLs-format packs.

/// Built-in "sensitive sender" domains. Mail from these senders frequently
/// carries security-critical links (password resets, magic-login tokens, 2FA,
/// payment confirmations) whose query parameters must **not** be rewritten or
/// unwrapped, lest a login/verification flow break.
///
/// When [`CleanerConfig::protect_sensitive_senders`] is enabled (the default),
/// a message whose `From:` domain matches one of these has query-param cleaning
/// and redirect unwrapping disabled — pixel removal still applies, since it is
/// always safe. Extend the set per deployment via a [`SenderPolicy`].
pub const DEFAULT_SENSITIVE_SENDER_DOMAINS: &[&str] = &[
    // Identity / SSO
    "accounts.google.com",
    "google.com",
    "login.microsoftonline.com",
    "microsoft.com",
    "apple.com",
    "okta.com",
    "auth0.com",
    "duosecurity.com",
    // Payments / finance
    "paypal.com",
    "stripe.com",
    "wise.com",
    "revolut.com",
    "americanexpress.com",
    "chase.com",
    "bankofamerica.com",
    // Auth/notification senders for common services
    "github.com",
    "gitlab.com",
];

/// A per-sender policy override. Rules are matched against the message's `From:`
/// domain (host-suffix, case-insensitive); the first matching rule applies.
///
/// Every toggle is optional: `None` means "inherit the global setting". The
/// `no_modify` shorthand forces report-only behaviour (audit headers are still
/// added, but the body is never rewritten) for that sender.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct SenderPolicy {
    /// Sender domains this rule applies to (host-suffix match).
    pub match_domains: Vec<String>,
    /// Override the operating mode for matching senders.
    pub mode: Option<Mode>,
    /// Shorthand: never modify the body for this sender (implies report-only).
    pub no_modify: bool,
    /// Override `clean_html`.
    pub clean_html: Option<bool>,
    /// Override `remove_pixels`.
    pub remove_pixels: Option<bool>,
    /// Override `clean_query_params`.
    pub clean_query_params: Option<bool>,
    /// Override `unwrap_known_redirects`.
    pub unwrap_known_redirects: Option<bool>,
}

impl SenderPolicy {
    fn matches(&self, sender_domain: &str) -> bool {
        let d = sender_domain.to_ascii_lowercase();
        self.match_domains
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .any(|s| d == s || d.ends_with(&format!(".{s}")))
    }
}

/// Which policy ended up applying to a message — surfaced as the
/// `X-Privacy-Cleaner-Policy` audit header and used by the CLI explainers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyLabel {
    /// The global configuration applied unchanged.
    Default,
    /// A built-in sensitive-sender protection applied.
    SensitiveSender,
    /// A user-defined [`SenderPolicy`] applied (matched on this domain).
    Custom(String),
}

impl PolicyLabel {
    /// Header-safe string form.
    pub fn as_header(&self) -> String {
        match self {
            PolicyLabel::Default => "default".into(),
            PolicyLabel::SensitiveSender => "sensitive-sender".into(),
            PolicyLabel::Custom(d) => format!("custom:{d}"),
        }
    }
}

/// Configuration controlling every part of the cleaning pipeline.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CleanerConfig {
    /// Enforce (rewrite) or report-only (headers only).
    pub mode: Mode,

    /// Rewrite `text/html` body parts.
    pub clean_html: bool,
    /// Apply URL query-param cleaning to `text/plain` parts (conservative).
    pub clean_text_plain: bool,
    /// Remove likely tracking pixels from HTML.
    pub remove_pixels: bool,
    /// Neutralise tracking beacons referenced from CSS rather than an `<img>`:
    /// a `url(...)` in an inline `style` (`background`/`background-image`, …) or
    /// the legacy `background="…"` attribute, when it points at a known beacon
    /// host or is fetched by an element that is itself hidden or 1×1. These are
    /// counted alongside the pixels removed and only apply when `remove_pixels`
    /// is enabled.
    pub neutralize_css_beacons: bool,
    /// Strip the hyperlink-auditing `ping` attribute from `<a>`/`<area>` tags so
    /// a click never fires a background beacon to the listed URLs.
    pub strip_link_ping: bool,
    /// Strip known tracking query parameters from URLs.
    pub clean_query_params: bool,
    /// Apply host-specific (non-global) provider rules from the rule pack
    /// (Amazon `pf_rd_*`, YouTube `si`, eBay `_trkparms`, …). When `false`, only
    /// the global tracking parameters are stripped.
    pub apply_vendor_rules: bool,
    /// Also strip referral-marketing parameters (provider `referralMarketing`
    /// rules). Off by default, since some recipients want affiliate credit.
    pub strip_referral_marketing: bool,
    /// Unwrap known ESP redirect links offline.
    pub unwrap_known_redirects: bool,
    /// Enable the optional, opt-in network redirect resolver (phase 2).
    pub network_redirect_resolution: bool,
    /// Preserve the original href in a `data-original-href` attribute.
    pub preserve_original_href: bool,
    /// In debug mode, removed tags are kept as HTML comments.
    pub debug_preserve_removed: bool,

    /// Apply the built-in sensitive-sender protection (see
    /// [`DEFAULT_SENSITIVE_SENDER_DOMAINS`]): for matching senders, query-param
    /// cleaning and redirect unwrapping are skipped so security links survive.
    pub protect_sensitive_senders: bool,
    /// Surface the message's `List-Unsubscribe` HTTP(S) target in an
    /// `X-Privacy-Cleaner-Unsubscribe` header.
    pub surface_unsubscribe: bool,
    /// Per-sender policy overrides, evaluated in order (first match wins).
    pub sender_policies: Vec<SenderPolicy>,

    /// Fail open: on internal errors, return the original message and add an
    /// `X-Privacy-Cleaner-Error` header instead of tempfailing.
    pub fail_open: bool,

    /// Maximum total message size accepted (bytes).
    pub max_message_size: usize,
    /// Maximum size of a single HTML part processed (bytes).
    pub max_html_part_size: usize,
    /// Generic operation timeout hint (milliseconds). Used by the network
    /// resolver and as a soft bound elsewhere.
    pub timeout_ms: u64,

    /// Domains the network resolver is allowed to contact (suffix match).
    pub allowlisted_redirect_domains: Vec<String>,
    /// Domains whose links are always neutralised (suffix match).
    pub blocked_domains: Vec<String>,
    /// Additional global tracking query parameters, merged on top of the rule
    /// pack. A value ending in `*` is matched as a name prefix.
    pub extra_tracking_params: Vec<String>,
    /// Additional tracking-pixel host suffixes, merged on top of the rule pack.
    pub extra_pixel_domains: Vec<String>,

    // ---- Exclusions (carve-outs that override the rule pack) ----
    /// Query-parameter names that are **never** stripped, even when a rule pack
    /// matches them (case-insensitive, `prefix*` allowed). Use this to keep a
    /// parameter a built-in or external rule would otherwise remove.
    pub keep_params: Vec<String>,
    /// Host suffixes whose URLs are left **entirely** untouched — no param
    /// stripping and no redirect unwrapping (case-insensitive suffix match).
    pub exclude_domains: Vec<String>,
    /// Rule-pack provider names to disable (removed from the compiled ruleset).
    /// Lets you switch off a single built-in or external provider by name.
    pub disabled_providers: Vec<String>,

    /// External ClearURLs-format rule pack files (paths) to load and merge on
    /// top of the built-in pack.
    pub rule_packs: Vec<String>,
    /// External ClearURLs-format rule pack URLs to load and merge. `file://`
    /// URLs and bare local paths are read offline in any build; `http(s)://`
    /// URLs are fetched at startup and require the `network` feature.
    pub rule_pack_urls: Vec<String>,

    /// Listen address for the milter daemon.
    pub listen: String,

    // ---- derived / cached, not part of the TOML ----
    #[serde(skip)]
    tracking_params: Option<HashSet<String>>,
    #[serde(skip)]
    tracking_prefixes: Option<Vec<String>>,
    #[serde(skip)]
    keep_param_set: Option<HashSet<String>>,
    #[serde(skip)]
    keep_param_prefixes: Option<Vec<String>>,
    #[serde(skip)]
    ruleset: Option<Arc<Ruleset>>,
}

impl Default for CleanerConfig {
    fn default() -> Self {
        CleanerConfig {
            mode: Mode::Enforce,
            clean_html: true,
            clean_text_plain: false,
            remove_pixels: true,
            neutralize_css_beacons: true,
            strip_link_ping: true,
            clean_query_params: true,
            apply_vendor_rules: true,
            strip_referral_marketing: false,
            unwrap_known_redirects: true,
            network_redirect_resolution: false,
            preserve_original_href: true,
            debug_preserve_removed: false,
            protect_sensitive_senders: true,
            surface_unsubscribe: true,
            sender_policies: Vec::new(),
            fail_open: true,
            max_message_size: 50 * 1024 * 1024,
            max_html_part_size: 8 * 1024 * 1024,
            timeout_ms: 1500,
            allowlisted_redirect_domains: Vec::new(),
            blocked_domains: Vec::new(),
            extra_tracking_params: Vec::new(),
            extra_pixel_domains: Vec::new(),
            keep_params: Vec::new(),
            exclude_domains: Vec::new(),
            disabled_providers: Vec::new(),
            rule_packs: Vec::new(),
            rule_pack_urls: Vec::new(),
            listen: "127.0.0.1:11333".to_string(),
            tracking_params: None,
            tracking_prefixes: None,
            keep_param_set: None,
            keep_param_prefixes: None,
            ruleset: None,
        }
    }
}

/// The process-wide compiled built-in rule pack (shared via `Arc`).
fn builtin_ruleset() -> Arc<Ruleset> {
    static BUILTIN: OnceLock<Arc<Ruleset>> = OnceLock::new();
    BUILTIN.get_or_init(|| Arc::new(Ruleset::builtin())).clone()
}

/// Split a list of parameter patterns into an exact-match (lower-cased) set and
/// a list of prefixes (entries ending in `*`).
fn split_param_patterns(list: &[String]) -> (HashSet<String>, Vec<String>) {
    let mut set: HashSet<String> = HashSet::new();
    let mut prefixes: Vec<String> = Vec::new();
    for p in list {
        let p = p.to_ascii_lowercase();
        if let Some(stripped) = p.strip_suffix('*') {
            if !stripped.is_empty() {
                prefixes.push(stripped.to_string());
            }
        } else {
            set.insert(p);
        }
    }
    (set, prefixes)
}

impl CleanerConfig {
    /// Load configuration from a TOML file.
    pub fn from_toml_file(path: impl AsRef<Path>) -> Result<Self> {
        let data = std::fs::read_to_string(path.as_ref())
            .map_err(|e| CleanerError::Config(format!("reading {:?}: {e}", path.as_ref())))?;
        Self::from_toml_str(&data)
    }

    /// Parse configuration from a TOML string.
    pub fn from_toml_str(s: &str) -> Result<Self> {
        let mut cfg: CleanerConfig =
            toml::from_str(s).map_err(|e| CleanerError::Config(e.to_string()))?;
        cfg.finalize();
        Ok(cfg)
    }

    /// Build the cached lookup tables. Call after mutating the param/domain
    /// lists; [`from_toml_*`](Self::from_toml_str) and the milter/CLI entry
    /// points do this automatically.
    pub fn finalize(&mut self) {
        let (set, prefixes) = split_param_patterns(&self.extra_tracking_params);
        self.tracking_params = Some(set);
        self.tracking_prefixes = Some(prefixes);

        let (keep_set, keep_prefixes) = split_param_patterns(&self.keep_params);
        self.keep_param_set = Some(keep_set);
        self.keep_param_prefixes = Some(keep_prefixes);

        self.ruleset = Some(Arc::new(self.build_ruleset()));
    }

    /// Build the combined rule pack: the built-in pack plus any external packs,
    /// then drop any `disabled_providers`. Packs that fail to load are skipped
    /// with a warning so a bad pack can't take the cleaner down.
    fn build_ruleset(&self) -> Ruleset {
        let mut rs = Ruleset::builtin();
        for path in &self.rule_packs {
            self.merge_pack_file(&mut rs, path);
        }
        for entry in &self.rule_pack_urls {
            self.merge_pack_url(&mut rs, entry);
        }
        if !self.disabled_providers.is_empty() {
            rs.disable(&self.disabled_providers);
        }
        rs
    }

    fn merge_pack_file(&self, rs: &mut Ruleset, path: &str) {
        match std::fs::read_to_string(path) {
            Ok(s) => match Ruleset::from_clearurls_str(&s) {
                Ok(pack) => rs.merge(pack),
                Err(e) => eprintln!("warning: rule pack {path:?} failed to parse: {e}"),
            },
            Err(e) => eprintln!("warning: rule pack {path:?} could not be read: {e}"),
        }
    }

    /// Load a `rule_pack_urls` entry. `file://` URLs and bare local paths are
    /// read from disk in any build (so Nix users can prefetch a remote pack into
    /// the store and reference it offline); `http(s)://` URLs require the
    /// `network` feature.
    fn merge_pack_url(&self, rs: &mut Ruleset, entry: &str) {
        let entry = entry.trim();
        if let Some(path) = entry.strip_prefix("file://") {
            self.merge_pack_file(rs, path);
            return;
        }
        let is_http = entry.starts_with("http://") || entry.starts_with("https://");
        if !is_http {
            // Treat anything else as a local path.
            self.merge_pack_file(rs, entry);
            return;
        }
        #[cfg(feature = "network")]
        match crate::network::fetch_rule_pack(entry, self.timeout_ms) {
            Ok(s) => match Ruleset::from_clearurls_str(&s) {
                Ok(pack) => rs.merge(pack),
                Err(e) => eprintln!("warning: rule pack {entry:?} failed to parse: {e}"),
            },
            Err(e) => eprintln!("warning: rule pack {entry:?} could not be fetched: {e}"),
        }
        #[cfg(not(feature = "network"))]
        eprintln!(
            "warning: rule pack {entry:?} needs the `network` feature to fetch over HTTP; \
             prefetch it and use a file path or file:// URL instead. Ignoring."
        );
    }

    /// The active rule pack (built-in + merged external packs). Falls back to the
    /// shared built-in pack when [`finalize`](Self::finalize) hasn't been called.
    pub fn ruleset(&self) -> Arc<Ruleset> {
        match &self.ruleset {
            Some(rs) => Arc::clone(rs),
            None => builtin_ruleset(),
        }
    }

    fn params(&self) -> Cow<'_, HashSet<String>> {
        match &self.tracking_params {
            Some(s) => Cow::Borrowed(s),
            None => Cow::Owned(split_param_patterns(&self.extra_tracking_params).0),
        }
    }

    fn param_prefixes(&self) -> Cow<'_, [String]> {
        match &self.tracking_prefixes {
            Some(v) => Cow::Borrowed(v),
            None => Cow::Owned(split_param_patterns(&self.extra_tracking_params).1),
        }
    }

    fn keep_params_set(&self) -> Cow<'_, HashSet<String>> {
        match &self.keep_param_set {
            Some(s) => Cow::Borrowed(s),
            None => Cow::Owned(split_param_patterns(&self.keep_params).0),
        }
    }

    fn keep_params_prefixes(&self) -> Cow<'_, [String]> {
        match &self.keep_param_prefixes {
            Some(v) => Cow::Borrowed(v),
            None => Cow::Owned(split_param_patterns(&self.keep_params).1),
        }
    }

    /// Returns `true` if `name` is on the keep-list and must never be stripped,
    /// even when a rule pack matches it (`extra_tracking_params`-style `prefix*`
    /// patterns are honoured).
    pub fn is_kept_param(&self, name: &str) -> bool {
        let name = name.to_ascii_lowercase();
        self.keep_params_set().contains(&name)
            || self
                .keep_params_prefixes()
                .iter()
                .any(|p| name.starts_with(p))
    }

    /// Returns `true` if `host` is excluded from all cleaning (suffix match).
    pub fn is_excluded_domain(&self, host: &str) -> bool {
        if self.exclude_domains.is_empty() {
            return false;
        }
        let host = host.to_ascii_lowercase();
        self.exclude_domains
            .iter()
            .map(|d| d.to_ascii_lowercase())
            .any(|d| host == d || host.ends_with(&format!(".{d}")))
    }

    /// Returns `true` if `name` matches a **user-supplied** global tracking
    /// parameter (`extra_tracking_params`, case-insensitive, `prefix*` allowed).
    /// Built-in and vendor parameters are matched via [`Self::ruleset`].
    pub fn is_tracking_param(&self, name: &str) -> bool {
        let name = name.to_ascii_lowercase();
        self.params().contains(&name) || self.param_prefixes().iter().any(|p| name.starts_with(p))
    }

    /// Resolve the effective configuration for a message from `sender_domain`.
    ///
    /// Returns the global config unchanged (borrowed) when no policy applies, or
    /// an overridden clone together with a [`PolicyLabel`] describing what
    /// matched. Resolution order: built-in sensitive-sender protection first
    /// (most conservative), then the first matching user [`SenderPolicy`], which
    /// may further restrict (or, if desired, re-enable) behaviour.
    pub fn effective_for_sender(
        &self,
        sender_domain: Option<&str>,
    ) -> (Cow<'_, CleanerConfig>, PolicyLabel) {
        let domain = match sender_domain {
            Some(d) if !d.is_empty() => d,
            _ => return (Cow::Borrowed(self), PolicyLabel::Default),
        };

        let mut label = PolicyLabel::Default;
        let mut cfg: Option<CleanerConfig> = None;

        // Built-in sensitive-sender protection: be conservative.
        if self.protect_sensitive_senders && is_sensitive_sender(domain) {
            let c = cfg.get_or_insert_with(|| self.clone());
            c.clean_query_params = false;
            c.unwrap_known_redirects = false;
            c.apply_vendor_rules = false;
            c.clean_text_plain = false;
            label = PolicyLabel::SensitiveSender;
        }

        // First matching user policy wins and overrides the built-in defaults.
        if let Some(policy) = self.sender_policies.iter().find(|p| p.matches(domain)) {
            let c = cfg.get_or_insert_with(|| self.clone());
            if policy.no_modify {
                c.mode = Mode::ReportOnly;
            }
            if let Some(m) = policy.mode {
                c.mode = m;
            }
            if let Some(v) = policy.clean_html {
                c.clean_html = v;
            }
            if let Some(v) = policy.remove_pixels {
                c.remove_pixels = v;
            }
            if let Some(v) = policy.clean_query_params {
                c.clean_query_params = v;
            }
            if let Some(v) = policy.unwrap_known_redirects {
                c.unwrap_known_redirects = v;
            }
            label = PolicyLabel::Custom(domain.to_ascii_lowercase());
        }

        match cfg {
            Some(c) => (Cow::Owned(c), label),
            None => (Cow::Borrowed(self), PolicyLabel::Default),
        }
    }

    /// Returns `true` if a remote image is a known tracking beacon: either its
    /// URL matches a `completeProvider` host in the rule pack, or its host
    /// matches a configured `extra_pixel_domains` suffix.
    ///
    /// `url_str` is the full image `src`; `host` is its host component.
    pub fn is_beacon(&self, url_str: &str, host: &str) -> bool {
        if self.ruleset().is_complete_block(url_str) {
            return true;
        }
        let host = host.to_ascii_lowercase();
        self.extra_pixel_domains
            .iter()
            .map(|d| d.to_ascii_lowercase())
            .any(|d| host == d || host.ends_with(&format!(".{d}")))
    }

    /// Returns `true` if `host` matches a blocked domain (suffix match).
    pub fn is_blocked_domain(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        self.blocked_domains
            .iter()
            .map(|d| d.to_ascii_lowercase())
            .any(|d| host == d || host.ends_with(&format!(".{d}")))
    }

    /// Returns `true` if `host` is allowed for network resolution.
    pub fn is_allowlisted_domain(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        self.allowlisted_redirect_domains
            .iter()
            .map(|d| d.to_ascii_lowercase())
            .any(|d| host == d || host.ends_with(&format!(".{d}")))
    }
}

/// Returns `true` if `sender_domain` matches a built-in sensitive-sender
/// domain (host-suffix, case-insensitive).
pub fn is_sensitive_sender(sender_domain: &str) -> bool {
    let d = sender_domain.to_ascii_lowercase();
    DEFAULT_SENSITIVE_SENDER_DOMAINS
        .iter()
        .any(|s| d == *s || d.ends_with(&format!(".{s}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_extra_param_matches_by_prefix() {
        let mut c = CleanerConfig {
            extra_tracking_params: vec!["mkt_*".into(), "exact_one".into()],
            ..Default::default()
        };
        c.finalize();
        assert!(c.is_tracking_param("mkt_tok"));
        assert!(c.is_tracking_param("MKT_anything"));
        assert!(c.is_tracking_param("exact_one"));
        assert!(!c.is_tracking_param("mkt")); // prefix needs the stem
        assert!(!c.is_tracking_param("keep_me"));
    }

    #[test]
    fn keep_params_and_exclude_domains() {
        let mut c = CleanerConfig {
            keep_params: vec!["utm_source".into(), "keep_*".into()],
            exclude_domains: vec!["trusted.example".into()],
            ..Default::default()
        };
        c.finalize();
        assert!(c.is_kept_param("utm_source"));
        assert!(c.is_kept_param("UTM_SOURCE"));
        assert!(c.is_kept_param("keep_this"));
        assert!(!c.is_kept_param("utm_medium"));
        assert!(c.is_excluded_domain("mail.trusted.example"));
        assert!(!c.is_excluded_domain("other.example"));
    }

    #[test]
    fn disabled_providers_drop_from_ruleset() {
        let c = CleanerConfig::from_toml_str("disabled_providers = [\"amazon\"]").unwrap();
        let rs = c.ruleset();
        assert!(rs.detect_provider("https://www.amazon.com/dp/x").is_none());
    }

    #[test]
    fn sensitive_sender_protection_disables_link_rewriting() {
        let mut c = CleanerConfig::default();
        c.finalize();
        let (eff, label) = c.effective_for_sender(Some("security.paypal.com"));
        assert_eq!(label, PolicyLabel::SensitiveSender);
        assert!(!eff.clean_query_params);
        assert!(!eff.unwrap_known_redirects);
        // Pixel removal stays on — it is always safe.
        assert!(eff.remove_pixels);
    }

    #[test]
    fn unknown_sender_uses_global_config_unchanged() {
        let mut c = CleanerConfig::default();
        c.finalize();
        let (eff, label) = c.effective_for_sender(Some("newsletter.example.com"));
        assert_eq!(label, PolicyLabel::Default);
        assert!(eff.clean_query_params);
        assert!(matches!(eff, Cow::Borrowed(_)));
    }

    #[test]
    fn custom_sender_policy_overrides() {
        let toml = r#"
            [[sender_policies]]
            match_domains = ["bank.example"]
            no_modify = true
            remove_pixels = false
        "#;
        let c = CleanerConfig::from_toml_str(toml).unwrap();
        let (eff, label) = c.effective_for_sender(Some("mail.bank.example"));
        assert_eq!(label, PolicyLabel::Custom("mail.bank.example".into()));
        assert_eq!(eff.mode, Mode::ReportOnly);
        assert!(!eff.remove_pixels);
    }
}

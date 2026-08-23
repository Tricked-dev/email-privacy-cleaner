//! Runtime configuration for the cleaner.
//!
//! The configuration is normally loaded from a TOML file (see
//! `config.example.toml`), but [`CleanerConfig`] also implements [`Default`]
//! so the library can be used without any config file.

use serde::Deserialize;
use std::borrow::Cow;
use std::collections::HashSet;
use std::io::Read;
use std::path::Path;
use std::sync::{Arc, OnceLock};

use crate::error::{CleanerError, Result};
use crate::ruleset::{RuleLoadLimits, RuleLoadReport, Ruleset, SkipReason};

/// Resource limits used while loading external rule packs.
pub type RuleResourceLimits = RuleLoadLimits;

pub use crate::ruleset::{RulePackFormat, RulePackSource, RulePackUsage};

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
    //
    // Matching is a literal host-suffix compare, so ccTLD storefronts do NOT
    // inherit from the .com entry — `paypal.nl` has to be listed separately or
    // it is treated as an ordinary marketing sender.
    "paypal.com",
    "paypal.nl",
    "paypal.be",
    "paypal.de",
    "paypal.fr",
    "paypal.it",
    "paypal.es",
    "paypal.co.uk",
    "stripe.com",
    "wise.com",
    "revolut.com",
    "americanexpress.com",
    "chase.com",
    "bankofamerica.com",
    "kraken.com",
    "degiro.com",
    "degiro.nl",
    "rabobank.nl",
    // Government / national identity
    "overheid.nl",
    "digid.nl",
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
    /// Preserve the original href in a `data-original-href` attribute on every
    /// cleaned `<a>`/`<area>`. Off by default because the attribute lives in
    /// the HTML body and therefore gets carried into recipients' **replies**
    /// (most clients quote the original body verbatim), undoing the cleaning
    /// for anyone reading the reply chain's source — and revealing both the
    /// original tracker and the fact that this milter was used. Turn on only
    /// when you specifically want a per-link audit trail visible to the
    /// recipient.
    pub preserve_original_href: bool,
    /// In debug mode, removed tags are kept as HTML comments. Off by default;
    /// note that turning it on has the same leak-into-replies caveat as
    /// `preserve_original_href` since the comments live in the HTML body.
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
    /// Structured rule-pack sources with optional format and usage hints.
    pub rule_pack_sources: Vec<RulePackSource>,
    /// Resource bounds applied independently of source transport.
    #[serde(default)]
    pub rule_limits: RuleResourceLimits,

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
    #[serde(skip)]
    finalization_key: Option<FinalizationKey>,
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
            preserve_original_href: false,
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
            rule_pack_sources: Vec::new(),
            rule_limits: RuleResourceLimits::default(),
            listen: "127.0.0.1:11333".to_string(),
            tracking_params: None,
            tracking_prefixes: None,
            keep_param_set: None,
            keep_param_prefixes: None,
            ruleset: None,
            finalization_key: None,
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

/// The public configuration exposes its source lists so callers can mutate
/// them after finalization. Keep a compact description of
/// the inputs that affect the derived lookup tables and compiled ruleset. This
/// lets repeated finalization be idempotent without making those public fields
/// private or requiring callers to manually invalidate a cache.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FinalizationKey {
    extra_tracking_params: Vec<String>,
    keep_params: Vec<String>,
    disabled_providers: Vec<String>,
    rule_packs: Vec<String>,
    rule_pack_urls: Vec<String>,
    rule_pack_sources: Vec<RulePackSource>,
    rule_limits: RuleResourceLimits,
}

impl CleanerConfig {
    /// Load configuration from a TOML file.
    pub fn from_toml_file(path: impl AsRef<Path>) -> Result<Self> {
        let data = std::fs::read_to_string(path.as_ref())
            .map_err(|e| CleanerError::Config(format!("reading {:?}: {e}", path.as_ref())))?;
        Self::from_toml_str(&data)
    }

    /// Parse a configuration file without reading or compiling rule packs.
    pub fn parse_toml_file(path: impl AsRef<Path>) -> Result<Self> {
        let data = std::fs::read_to_string(path.as_ref())
            .map_err(|e| CleanerError::Config(format!("reading {:?}: {e}", path.as_ref())))?;
        Self::parse_toml_str(&data)
    }

    /// Parse configuration from a TOML string.
    pub fn from_toml_str(s: &str) -> Result<Self> {
        let mut cfg = Self::parse_toml_str(s)?;
        cfg.finalize();
        Ok(cfg)
    }

    /// Parse TOML without reading or compiling configured rule packs.
    pub fn parse_toml_str(s: &str) -> Result<Self> {
        let mut cfg: CleanerConfig =
            toml::from_str(s).map_err(|e| CleanerError::Config(e.to_string()))?;
        cfg.ruleset = None;
        Ok(cfg)
    }

    /// Compatibility alias for the unfinalized parse path.
    pub fn from_toml_str_unfinalized(s: &str) -> Result<Self> {
        Self::parse_toml_str(s)
    }

    fn finalization_key(&self) -> FinalizationKey {
        FinalizationKey {
            extra_tracking_params: self.extra_tracking_params.clone(),
            keep_params: self.keep_params.clone(),
            disabled_providers: self.disabled_providers.clone(),
            rule_packs: self.rule_packs.clone(),
            rule_pack_urls: self.rule_pack_urls.clone(),
            rule_pack_sources: self.rule_pack_sources.clone(),
            rule_limits: self.rule_limits,
        }
    }

    /// Build the cached lookup tables. Call after mutating the param/domain
    /// lists; [`from_toml_*`](Self::from_toml_str) and the milter/CLI entry
    /// points do this automatically.
    pub fn finalize(&mut self) {
        let key = self.finalization_key();
        if self.ruleset.is_some() && self.finalization_key.as_ref() == Some(&key) {
            return;
        }

        let (set, prefixes) = split_param_patterns(&self.extra_tracking_params);
        self.tracking_params = Some(set);
        self.tracking_prefixes = Some(prefixes);

        let (keep_set, keep_prefixes) = split_param_patterns(&self.keep_params);
        self.keep_param_set = Some(keep_set);
        self.keep_param_prefixes = Some(keep_prefixes);

        let ruleset = self.build_ruleset_with_loader(&mut |source| self.read_source(source));
        log_rule_load_report(ruleset.load_report());
        self.ruleset = Some(Arc::new(ruleset));
        self.finalization_key = Some(key);
    }

    /// Finalize using an injected source loader. Each configured source is
    /// passed to the loader at most once and is added to one builder before it
    /// is frozen.
    pub fn finalize_with_loader<F>(
        &mut self,
        loader: &mut F,
    ) -> Result<crate::ruleset::RuleLoadReport>
    where
        F: FnMut(&str) -> Result<Vec<u8>>,
    {
        let key = self.finalization_key();
        if let Some(ruleset) = &self.ruleset {
            if self.finalization_key.as_ref() == Some(&key) {
                return Ok(ruleset.load_report().clone());
            }
        }

        let (set, prefixes) = split_param_patterns(&self.extra_tracking_params);
        self.tracking_params = Some(set);
        self.tracking_prefixes = Some(prefixes);
        let (keep_set, keep_prefixes) = split_param_patterns(&self.keep_params);
        self.keep_param_set = Some(keep_set);
        self.keep_param_prefixes = Some(keep_prefixes);

        let ruleset = self.build_ruleset_with_loader(loader);
        let report = ruleset.load_report().clone();
        log_rule_load_report(&report);
        self.ruleset = Some(Arc::new(ruleset));
        self.finalization_key = Some(key);
        Ok(report)
    }

    fn build_ruleset_with_loader<F>(&self, loader: &mut F) -> Ruleset
    where
        F: FnMut(&str) -> Result<Vec<u8>>,
    {
        use crate::ruleset::RulesetBuilder;
        // The built-in pack occupies one builder source and its bytes. Keep
        // the public limits scoped to external sources by reserving those
        // bookkeeping slots for the built-in source.
        let mut limits = self.rule_limits;
        limits.max_rule_pack_sources = limits.max_rule_pack_sources.saturating_add(1);
        limits.max_total_rule_pack_bytes = limits
            .max_total_rule_pack_bytes
            .saturating_add(include_str!("../rules/builtin.json").len());
        let mut builder = RulesetBuilder::new(limits);
        builder
            .add_source_str(
                "builtin",
                include_str!("../rules/builtin.json"),
                Some(RulePackFormat::ClearUrls),
                None,
            )
            .expect("built-in rules/builtin.json must be valid");
        builder.disable_providers(&self.disabled_providers);

        let mut sources = Vec::new();
        sources.extend(self.rule_packs.iter().map(|source| RulePackSource {
            source: source.clone(),
            format: Some(RulePackFormat::ClearUrls),
            usage: None,
        }));
        sources.extend(self.rule_pack_urls.iter().map(|source| RulePackSource {
            source: source.clone(),
            format: Some(RulePackFormat::ClearUrls),
            usage: None,
        }));
        sources.extend(self.rule_pack_sources.iter().cloned());

        let mut seen = HashSet::new();
        let mut external_sources = 0usize;
        let mut external_bytes = 0usize;
        for source in sources {
            if !seen.insert(source.source.clone()) {
                continue;
            }
            if external_sources >= self.rule_limits.max_rule_pack_sources {
                builder.record_skipped_source(
                    source.source,
                    0,
                    SkipReason::SourceCountLimit,
                    source.format,
                );
                continue;
            }
            external_sources += 1;
            match loader(&source.source) {
                Ok(bytes) => {
                    if bytes.len() > self.rule_limits.max_rule_pack_bytes
                        || external_bytes.saturating_add(bytes.len())
                            > self.rule_limits.max_total_rule_pack_bytes
                    {
                        let reason = if bytes.len() > self.rule_limits.max_rule_pack_bytes {
                            SkipReason::ByteLimit
                        } else {
                            SkipReason::TotalByteLimit
                        };
                        builder.record_skipped_source(
                            source.source,
                            bytes.len(),
                            reason,
                            source.format,
                        );
                    } else {
                        external_bytes += bytes.len();
                        let _ = builder.add_source_bytes(
                            source.source,
                            &bytes,
                            source.format,
                            source.usage,
                        );
                    }
                }
                Err(_) => {
                    builder.record_skipped_source(source.source, 0, SkipReason::Io, source.format);
                }
            }
        }
        builder.finish()
    }

    fn read_source(&self, source: &str) -> Result<Vec<u8>> {
        let source = source.trim();
        if source.starts_with("https://") {
            #[cfg(feature = "network")]
            {
                return crate::network::fetch_rule_pack_with_limit(
                    source,
                    self.timeout_ms,
                    self.rule_limits.max_rule_pack_bytes,
                );
            }
            #[cfg(not(feature = "network"))]
            {
                return Err(CleanerError::Network(
                    "HTTPS rule packs require the network feature".into(),
                ));
            }
        }
        if source.starts_with("http://") {
            return Err(CleanerError::Config(
                "insecure HTTP rule-pack source rejected".into(),
            ));
        }
        let path = source.strip_prefix("file://").unwrap_or(source);
        let file = std::fs::File::open(path)?;
        let mut bytes = Vec::new();
        let mut reader = file.take(self.rule_limits.max_rule_pack_bytes as u64 + 1);
        reader.read_to_end(&mut bytes)?;
        Ok(bytes)
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

fn log_rule_load_report(report: &RuleLoadReport) {
    for source in &report.sources {
        eprintln!(
            "rule-pack source={} format={:?} bytes={} parsed={} accepted={} unsupported={} duplicates={} failed_regexes={} skipped={:?}",
            source.source,
            source.format,
            source.bytes_read,
            source.parsed_rules,
            source.accepted_rules,
            source.unsupported_rules,
            source.duplicates,
            source.failed_regexes,
            source.skipped_reason,
        );
    }
    eprintln!(
        "rule-pack totals: sources={} accepted_bytes={}",
        report.sources.len(),
        report.total_bytes
    );
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
    fn http_rule_pack_urls_are_ignored() {
        let c =
            CleanerConfig::from_toml_str("rule_pack_urls = [\"http://example.invalid/pack.json\"]")
                .unwrap();
        assert!(c
            .ruleset()
            .detect_provider("https://acme.invalid/path")
            .is_none());
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

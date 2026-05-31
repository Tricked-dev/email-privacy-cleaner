//! Runtime configuration for the cleaner.
//!
//! The configuration is normally loaded from a TOML file (see
//! `config.example.toml`), but [`CleanerConfig`] also implements [`Default`]
//! so the library can be used without any config file.

use serde::Deserialize;
use std::collections::HashSet;
use std::path::Path;

use crate::error::{CleanerError, Result};

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

/// The canonical set of tracking query parameters removed by default.
///
/// Matching is always case-insensitive (see [`CleanerConfig::is_tracking_param`]).
pub const DEFAULT_TRACKING_PARAMS: &[&str] = &[
    // Google / generic UTM
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "utm_id",
    // Ad-click identifiers
    "fbclid",
    "gclid",
    "dclid",
    "msclkid",
    "twclid",
    "igshid",
    "rb_clickid",
    "vero_id",
    // Mailchimp / Mandrill
    "mc_cid",
    "mc_eid",
    "mkt_tok",
    // HubSpot
    "_hsenc",
    "_hsmi",
    "hsa_acc",
    "hsa_cam",
    "hsa_grp",
    "hsa_ad",
    "hsa_src",
    "hsa_tgt",
    "hsa_kw",
    "hsa_mt",
    "hsa_net",
    "hsa_ver",
    // Google Analytics manual tagging variants
    "ga_source",
    "ga_medium",
    "ga_term",
    "ga_content",
    "ga_campaign",
    // Piwik / Matomo
    "pk_campaign",
    "pk_kwd",
    "piwik_campaign",
    "piwik_kwd",
    "mtm_source",
    "mtm_medium",
    "mtm_campaign",
    "mtm_keyword",
    "mtm_content",
    // Misc.
    "spm",
    "ref",
    "ref_src",
    "source",
    "campaign",
];

/// Hostnames (suffix-matched) that are treated as known tracking-pixel /
/// beacon providers.
pub const DEFAULT_PIXEL_DOMAINS: &[&str] = &[
    "open.convertkit-mail.com",
    "click.convertkit-mail.com",
    "list-manage.com",
    "mailchimp.com",
    "sendgrid.net",
    "sg-links.com",
    "ct.sendgrid.net",
    "email.mailgun.net",
    "track.customer.io",
    "links.iterable.com",
    "click.klaviyo.com",
    "trk.klclick.com",
    "px.ads.linkedin.com",
    "ct.pinterest.com",
    "open.sibautomation.com",
    "trackcmp.net",
    "doubleclick.net",
    "google-analytics.com",
    "googletagmanager.com",
    "beacon.krxd.net",
    "pixel.mathtag.com",
    "t.signaux.example", // placeholder kept short; extend via extra_pixel_domains
];

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
    /// Strip known tracking query parameters from URLs.
    pub clean_query_params: bool,
    /// Unwrap known ESP redirect links offline.
    pub unwrap_known_redirects: bool,
    /// Enable the optional, opt-in network redirect resolver (phase 2).
    pub network_redirect_resolution: bool,
    /// Preserve the original href in a `data-original-href` attribute.
    pub preserve_original_href: bool,
    /// In debug mode, removed tags are kept as HTML comments.
    pub debug_preserve_removed: bool,

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
    /// Additional tracking query parameters (merged with the defaults).
    pub extra_tracking_params: Vec<String>,
    /// Additional tracking-pixel host suffixes (merged with the defaults).
    pub extra_pixel_domains: Vec<String>,

    /// Listen address for the milter daemon.
    pub listen: String,

    // ---- derived / cached, not part of the TOML ----
    #[serde(skip)]
    tracking_params: Option<HashSet<String>>,
    #[serde(skip)]
    pixel_domains: Option<Vec<String>>,
}

impl Default for CleanerConfig {
    fn default() -> Self {
        CleanerConfig {
            mode: Mode::Enforce,
            clean_html: true,
            clean_text_plain: false,
            remove_pixels: true,
            clean_query_params: true,
            unwrap_known_redirects: true,
            network_redirect_resolution: false,
            preserve_original_href: true,
            debug_preserve_removed: false,
            fail_open: true,
            max_message_size: 50 * 1024 * 1024,
            max_html_part_size: 8 * 1024 * 1024,
            timeout_ms: 1500,
            allowlisted_redirect_domains: Vec::new(),
            blocked_domains: Vec::new(),
            extra_tracking_params: Vec::new(),
            extra_pixel_domains: Vec::new(),
            listen: "127.0.0.1:11333".to_string(),
            tracking_params: None,
            pixel_domains: None,
        }
    }
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
        let mut set: HashSet<String> = DEFAULT_TRACKING_PARAMS
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .collect();
        for p in &self.extra_tracking_params {
            set.insert(p.to_ascii_lowercase());
        }
        self.tracking_params = Some(set);

        let mut domains: Vec<String> = DEFAULT_PIXEL_DOMAINS
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .collect();
        for d in &self.extra_pixel_domains {
            domains.push(d.to_ascii_lowercase());
        }
        self.pixel_domains = Some(domains);
    }

    fn params(&self) -> std::borrow::Cow<'_, HashSet<String>> {
        match &self.tracking_params {
            Some(s) => std::borrow::Cow::Borrowed(s),
            None => {
                // Lazily compute without mutation (used when finalize() wasn't called).
                let mut set: HashSet<String> = DEFAULT_TRACKING_PARAMS
                    .iter()
                    .map(|s| s.to_ascii_lowercase())
                    .collect();
                for p in &self.extra_tracking_params {
                    set.insert(p.to_ascii_lowercase());
                }
                std::borrow::Cow::Owned(set)
            }
        }
    }

    /// Returns `true` if `name` is a tracking parameter (case-insensitive).
    pub fn is_tracking_param(&self, name: &str) -> bool {
        self.params().contains(&name.to_ascii_lowercase())
    }

    /// Returns `true` if `host` matches a known tracking-pixel domain
    /// (suffix match, case-insensitive).
    pub fn is_pixel_domain(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        let defaults_and_extra: Vec<String> = match &self.pixel_domains {
            Some(v) => v.clone(),
            None => {
                let mut v: Vec<String> = DEFAULT_PIXEL_DOMAINS
                    .iter()
                    .map(|s| s.to_ascii_lowercase())
                    .collect();
                v.extend(
                    self.extra_pixel_domains
                        .iter()
                        .map(|s| s.to_ascii_lowercase()),
                );
                v
            }
        };
        defaults_and_extra
            .iter()
            .any(|d| host == *d || host.ends_with(&format!(".{d}")))
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

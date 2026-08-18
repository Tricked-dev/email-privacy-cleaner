//! Normalized rule loading and immutable runtime matching.
//!
//! The cleaner accepts several deliberately different rule languages.  They
//! are parsed into a small source IR first and only then compiled into one
//! immutable [`RuleStore`].  Keeping the source semantics in the IR is
//! important: ClearURLs, Brave Clean URLs, and AdGuard do not agree on query
//! decoding, case sensitivity, or exception scope.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine;
use percent_encoding::percent_decode_str;
use regex::{Regex, RegexSet};
use regex_syntax::hir::{Class, Hir, HirKind};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::{CleanerError, Result};

/// The built-in rule pack, in ClearURLs JSON format.
const BUILTIN_JSON: &str = include_str!("../rules/builtin.json");

const MAX_LITERAL_EXPANSION: usize = 64;
const MAX_REGEX_PATTERN_BYTES: usize = 64 * 1024;
const MAX_GENERATED_REGEX_BYTES: usize = 64 * 1024;
const MAX_REGEX_CHUNK_PATTERNS: usize = 256;
const MAX_REGEX_CHUNK_BYTES: usize = 128 * 1024;
const MAX_DIAGNOSTIC_SAMPLES: usize = 16;

/// Supported external rule-pack formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum RulePackFormat {
    /// Detect JSON ClearURLs, Brave, or text AdGuard input.
    #[default]
    Auto,
    /// ClearURLs `providers` JSON.
    ClearUrls,
    /// Brave `clean-urls.json`.
    BraveCleanUrls,
    /// Brave `debounce.json`.
    BraveDebounce,
    /// AdGuard network-filter syntax.
    AdGuard,
}

/// Optional purpose hint for a source whose syntax is ambiguous in email.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RulePackUsage {
    /// Permit modifierless AdGuard blocking rules as mail image rules.
    MailBeacon,
}

/// A structured source entry. The `rule_packs` and `rule_pack_urls` string
/// arrays are also supported; this form supplies a format/purpose hint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RulePackSource {
    /// Local path or HTTPS URL.
    #[serde(alias = "url", alias = "path")]
    pub source: String,
    /// Explicit format.  `None` means auto-detect.
    #[serde(default)]
    pub format: Option<RulePackFormat>,
    /// Optional interpretation hint for ambiguous blocking lists.
    #[serde(default)]
    pub usage: Option<RulePackUsage>,
}

/// Resource bounds applied before an external source is retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RuleLoadLimits {
    /// Maximum decompressed bytes accepted from one source.
    pub max_rule_pack_bytes: usize,
    /// Maximum decompressed bytes accepted across all sources.
    pub max_total_rule_pack_bytes: usize,
    /// Maximum number of configured sources.
    pub max_rule_pack_sources: usize,
    /// Maximum normalized external atoms retained from one source.
    pub max_external_rules: usize,
    /// Maximum regex-bearing expressions retained from one source.  This
    /// includes parameter regexes, URL scopes, redirect/path extractors,
    /// raw-rule expressions, beacon patterns, provider URL patterns, and
    /// provider exceptions.  The source is rejected atomically when this
    /// budget is exceeded.
    pub max_regex_rules: usize,
    /// Maximum diagnostic samples retained per source.
    pub max_diagnostic_samples: usize,
}

impl Default for RuleLoadLimits {
    fn default() -> Self {
        Self {
            max_rule_pack_bytes: 5 * 1024 * 1024,
            max_total_rule_pack_bytes: 25 * 1024 * 1024,
            max_rule_pack_sources: 32,
            max_external_rules: 50_000,
            max_regex_rules: 10_000,
            max_diagnostic_samples: MAX_DIAGNOSTIC_SAMPLES,
        }
    }
}

/// Why a rule source was not accepted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SkipReason {
    /// The source exceeded the per-source byte budget.
    ByteLimit,
    /// Adding the source would exceed the aggregate byte budget.
    TotalByteLimit,
    /// The configured source count is exhausted.
    SourceCountLimit,
    /// The normalized atom budget was exceeded.
    RuleLimit,
    /// The retained regex budget was exceeded.
    RegexLimit,
    /// The source could not be decoded or parsed.
    Parse,
    /// The source format could not be identified.
    UnknownFormat,
    /// The source could not be read or fetched.
    Io,
    /// The source uses a feature this mail cleaner cannot represent.
    Unsupported,
}

/// Bounded diagnostics for one source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceReport {
    /// Sanitized path or URL identifier (credentials and query strings removed).
    pub source: String,
    /// Format after detection, when detection succeeded.
    pub format: Option<RulePackFormat>,
    /// Bytes read before parsing.
    pub bytes_read: usize,
    /// Logical rules seen by the adapter.
    pub parsed_rules: usize,
    /// Normalized rules accepted into the global builder.
    pub accepted_rules: usize,
    /// Rules intentionally skipped by the adapter.
    pub unsupported_rules: usize,
    /// Semantic duplicates discarded during global merge.
    pub duplicates: usize,
    /// Individual regexes rejected by validation or compilation.
    pub failed_regexes: usize,
    /// Atomic source rejection reason, if any.
    pub skipped_reason: Option<SkipReason>,
    /// Capped examples of unsupported syntax.
    pub unsupported_samples: Vec<String>,
    /// Capped examples of failed patterns.
    pub failed_samples: Vec<String>,
}

impl SourceReport {
    fn new(source: &str) -> Self {
        Self {
            source: sanitize_source_id(source),
            format: None,
            bytes_read: 0,
            parsed_rules: 0,
            accepted_rules: 0,
            unsupported_rules: 0,
            duplicates: 0,
            failed_regexes: 0,
            skipped_reason: None,
            unsupported_samples: Vec::new(),
            failed_samples: Vec::new(),
        }
    }
}

/// Structured load diagnostics retained by a compiled ruleset.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleLoadReport {
    /// One bounded report per attempted source.
    pub sources: Vec<SourceReport>,
    /// Bytes accepted into the builder.
    pub total_bytes: usize,
}

/// Deterministic counts for the frozen runtime store.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleStoreStats {
    pub scopes: usize,
    pub groups: usize,
    pub exact_param_rules: usize,
    pub prefix_param_rules: usize,
    pub regex_param_rules: usize,
    pub regex_set_chunks: usize,
    pub domain_index_keys: usize,
    pub beacon_rules: usize,
    pub redirect_rules: usize,
    pub raw_rules: usize,
    pub providers: usize,
}

/// Which normalized subject is fed to a parameter matcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub enum ParamSubject {
    /// The query key exactly as received on the wire.
    RawName,
    /// The form-decoded query key.
    DecodedName,
    /// The form-decoded `name=value` pair.
    DecodedPair,
}

/// How Brave/other redirect extractors decode their destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DecodeMode {
    Direct,
    Base64Url,
    /// Decode mode used by existing ClearURLs rules.
    ExistingAutoDecode,
}

/// Origin of a compiled redirect extractor.
///
/// `Legacy` covers ClearURLs and built-in redirect behavior.
/// `Brave` is marked separately so Brave-specific safety checks cannot change
/// legacy redirect behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RedirectOrigin {
    Legacy,
    Brave,
}

/// A redirect destination together with the source format that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedirectTarget {
    pub target: String,
    pub origin: RedirectOrigin,
}

/// How path captures are assembled into a destination.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CaptureAssembly {
    Concatenate,
    Template(Box<str>),
}

/// A scoped action group.  Scope checks are performed while constructing a
/// [`UrlContext`], not once per query parameter.
#[derive(Debug, Clone)]
struct RuleGroup {
    include_scopes: Box<[ScopeId]>,
    exclude_scopes: Box<[ScopeId]>,
    action: ActionId,
    order: u32,
}

type ScopeId = usize;
type ActionId = usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum SourceKind {
    ClearUrls,
    BraveCleanUrls,
    AdGuard,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ScopeSpec {
    Any,
    UrlRegex(Box<str>),
    UrlGlob(Box<str>),
    AdGuardTarget {
        pattern: Box<str>,
        domains: Box<[Box<str>]>,
        match_case: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ParamMatcherSpec {
    Exact {
        value: Box<str>,
        subject: ParamSubject,
        case_sensitive: bool,
        requires_equals: bool,
    },
    Prefix {
        value: Box<str>,
        subject: ParamSubject,
        case_sensitive: bool,
        requires_equals: bool,
    },
    Regex {
        pattern: Box<str>,
        subject: ParamSubject,
        case_sensitive: bool,
        requires_equals: bool,
    },
}

#[derive(Debug, Clone)]
struct ParamRuleIr {
    source: SourceKind,
    provider: Option<Box<str>>,
    global: bool,
    referral: bool,
    exception: bool,
    exception_all: bool,
    matcher: ParamMatcherSpec,
    include: Vec<ScopeSpec>,
    exclude: Vec<ScopeSpec>,
    report_index: usize,
}

#[derive(Debug, Clone)]
struct ProviderIr {
    name: Box<str>,
    global: bool,
    complete: bool,
    url_pattern: Box<str>,
    exceptions: Vec<Box<str>>,
}

#[derive(Debug, Clone)]
enum RedirectExtractorIr {
    ClearUrls {
        pattern: Box<str>,
    },
    QueryParam {
        names: Box<[Box<str>]>,
        decode: DecodeMode,
        prepend_scheme: Option<Box<str>>,
    },
    PathRegex {
        pattern: Box<str>,
        assembly: CaptureAssembly,
        prepend_scheme: Option<Box<str>>,
    },
}

#[derive(Debug, Clone)]
struct RedirectRuleIr {
    provider: Option<Box<str>>,
    include: Vec<ScopeSpec>,
    exclude: Vec<ScopeSpec>,
    extractor: RedirectExtractorIr,
}

#[derive(Debug, Clone)]
struct BeaconRuleIr {
    include: Vec<ScopeSpec>,
    exclude: Vec<ScopeSpec>,
    raw_pattern: Option<Box<str>>,
}

#[derive(Debug, Clone)]
struct RawRuleIr {
    provider: Box<str>,
    include: Vec<ScopeSpec>,
    pattern: Box<str>,
}

#[derive(Debug, Clone, Default)]
struct SourceIr {
    format: RulePackFormat,
    source: String,
    providers: Vec<ProviderIr>,
    params: Vec<ParamRuleIr>,
    redirects: Vec<RedirectRuleIr>,
    beacons: Vec<BeaconRuleIr>,
    raw_rules: Vec<RawRuleIr>,
    parsed_rules: usize,
    accepted_rules: usize,
    unsupported_rules: usize,
    failed_regexes: usize,
}

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

#[derive(Debug, Deserialize)]
struct BraveCleanEntry {
    #[serde(default)]
    include: Vec<String>,
    #[serde(default)]
    exclude: Vec<String>,
    #[serde(default)]
    params: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct BraveDebounceEntry {
    #[serde(default)]
    include: Vec<String>,
    #[serde(default)]
    exclude: Vec<String>,
    action: String,
    #[serde(default)]
    param: Option<String>,
    #[serde(default)]
    redirect_url_template: Option<String>,
    #[serde(default)]
    prepend_scheme: Option<String>,
    #[serde(default)]
    pref: Option<String>,
}

#[derive(Debug, Default)]
struct ParseCounters {
    unsupported: Vec<String>,
    failed: Vec<String>,
}

impl ParseCounters {
    fn unsupported(&mut self, sample: impl Into<String>) {
        if self.unsupported.len() < MAX_DIAGNOSTIC_SAMPLES {
            self.unsupported.push(sample.into());
        }
    }

    fn failed(&mut self, sample: impl Into<String>) {
        if self.failed.len() < MAX_DIAGNOSTIC_SAMPLES {
            self.failed.push(sample.into());
        }
    }
}

#[derive(Debug, Clone)]
struct Provider {
    name: String,
    global: bool,
    complete: bool,
    url_pattern: Regex,
    exceptions: Vec<Regex>,
}

#[derive(Debug, Clone)]
enum CompiledScope {
    Any,
    UrlRegex(Regex),
    UrlGlob {
        regex: Regex,
        host_suffix: Option<Box<str>>,
    },
    AdGuardTarget {
        regex: Regex,
        domains: Box<[Box<str>]>,
        host_suffix: Option<Box<str>>,
    },
}

impl CompiledScope {
    fn matches(&self, raw_url: &str, parsed: &Url) -> bool {
        match self {
            Self::Any => true,
            Self::UrlRegex(re) | Self::UrlGlob { regex: re, .. } => re.is_match(raw_url),
            Self::AdGuardTarget { regex, domains, .. } => {
                regex.is_match(raw_url)
                    && (domains.is_empty()
                        || parsed.host_str().is_some_and(|host| {
                            domains
                                .iter()
                                .any(|domain| host_suffix_matches(host, domain))
                        }))
            }
        }
    }

    fn for_each_host_hint(&self, mut visit: impl FnMut(&str)) {
        match self {
            Self::UrlGlob { host_suffix, .. } => {
                if let Some(host_suffix) = host_suffix.as_deref() {
                    visit(host_suffix);
                }
            }
            Self::AdGuardTarget {
                domains,
                host_suffix,
                ..
            } => {
                if domains.is_empty() {
                    if let Some(host_suffix) = host_suffix.as_deref() {
                        visit(host_suffix);
                    }
                } else {
                    for domain in domains {
                        visit(domain);
                    }
                }
            }
            Self::Any | Self::UrlRegex(_) => {}
        }
    }
}

#[derive(Debug, Clone)]
enum CompiledMatcherKind {
    Exact(Box<str>),
    Prefix(Box<str>),
    Regex { chunk: usize, index: usize },
}

#[derive(Debug, Clone)]
struct CompiledParamMatcher {
    kind: CompiledMatcherKind,
    subject: ParamSubject,
    case_sensitive: bool,
    requires_equals: bool,
}

impl CompiledParamMatcher {
    fn matches(&self, segment: &str, chunks: &[RegexSetChunk]) -> bool {
        let (raw_name, has_equals, raw_value) = split_query_segment(segment);
        if self.requires_equals && !has_equals {
            return false;
        }
        let decoded_name = decode_query_component(raw_name);
        let subject = match self.subject {
            ParamSubject::RawName => raw_name.to_string(),
            ParamSubject::DecodedName => decoded_name.clone(),
            ParamSubject::DecodedPair => {
                let value = decode_query_component(raw_value);
                format!("{decoded_name}={value}")
            }
        };

        match &self.kind {
            CompiledMatcherKind::Exact(value) => {
                if self.case_sensitive {
                    subject == value.as_ref()
                } else {
                    subject.eq_ignore_ascii_case(value)
                }
            }
            CompiledMatcherKind::Prefix(value) => {
                if self.case_sensitive {
                    subject.starts_with(value.as_ref())
                } else {
                    subject.to_ascii_lowercase().starts_with(value.as_ref())
                }
            }
            CompiledMatcherKind::Regex { chunk, index } => chunks
                .get(*chunk)
                .map(|chunk| chunk.set.matches(&subject).matched(*index))
                .unwrap_or(false),
        }
    }
}

#[derive(Debug, Clone)]
struct RegexSetChunk {
    set: RegexSet,
}

#[derive(Debug, Clone)]
struct ParamAction {
    source: SourceKind,
    global: bool,
    referral: bool,
    exception: bool,
    exception_all: bool,
    legacy_builtin_global_carveout: bool,
    clearurls_provider_ids: Box<[usize]>,
    matcher_spec: ParamMatcherSpec,
    matcher: CompiledParamMatcher,
}

#[derive(Debug, Clone)]
struct CompiledRedirectRule {
    include: Box<[ScopeId]>,
    exclude: Box<[ScopeId]>,
    extractor: RedirectExtractor,
    origin: RedirectOrigin,
    order: u32,
}

#[derive(Debug, Clone)]
enum RedirectExtractor {
    ClearUrls {
        regex: Regex,
    },
    QueryParam {
        names: Box<[Box<str>]>,
        decode: DecodeMode,
        prepend_scheme: Option<Box<str>>,
    },
    PathRegex {
        regex: Regex,
        assembly: CaptureAssembly,
        prepend_scheme: Option<Box<str>>,
    },
}

#[derive(Debug, Clone)]
struct CompiledBeaconRule {
    include: Box<[ScopeId]>,
    exclude: Box<[ScopeId]>,
    raw_regex: Option<Regex>,
}

#[derive(Debug, Clone)]
struct CompiledRawRule {
    include: Box<[ScopeId]>,
    regex: Regex,
}

#[derive(Debug, Default)]
struct ScopeIndex {
    global: Vec<usize>,
    suffix: HashMap<Box<str>, Vec<usize>>,
    generic: Vec<usize>,
}

#[derive(Debug)]
struct RuleStore {
    providers: Box<[Provider]>,
    scopes: Box<[CompiledScope]>,
    groups: Box<[RuleGroup]>,
    actions: Box<[ParamAction]>,
    regex_chunks: Box<[RegexSetChunk]>,
    scope_index: ScopeIndex,
    redirects: Box<[CompiledRedirectRule]>,
    beacons: Box<[CompiledBeaconRule]>,
    raw_rules: Box<[CompiledRawRule]>,
    stats: RuleStoreStats,
}

/// The compiled, shareable ruleset facade.
#[derive(Debug)]
pub struct Ruleset {
    store: Arc<RuleStore>,
    /// Compact canonical definitions retained for the compatibility `merge`
    /// and `disable` methods. Callers that load many sources should use
    /// [`RulesetBuilder`] and call `finish` once; builder maps are released.
    canonical: Arc<[SourceIr]>,
    disabled_providers: Arc<[String]>,
    report: RuleLoadReport,
    /// Number of individual patterns skipped during parsing or compilation.
    pub skipped_patterns: usize,
}

impl Default for Ruleset {
    fn default() -> Self {
        Self::empty()
    }
}

/// Builder for one immutable, globally deduplicated ruleset.
#[derive(Debug)]
pub struct RulesetBuilder {
    limits: RuleLoadLimits,
    total_bytes: usize,
    attempted_sources: usize,
    sources: Vec<SourceIr>,
    report: RuleLoadReport,
    disabled_providers: HashSet<String>,
}

impl RulesetBuilder {
    /// Create an empty builder with explicit resource bounds.
    pub fn new(limits: RuleLoadLimits) -> Self {
        Self {
            limits,
            total_bytes: 0,
            attempted_sources: 0,
            sources: Vec::new(),
            report: RuleLoadReport::default(),
            disabled_providers: HashSet::new(),
        }
    }

    /// Disable ClearURLs providers before semantic deduplication.
    pub fn disable_providers(&mut self, names: &[String]) {
        self.disabled_providers
            .extend(names.iter().map(|name| name.to_ascii_lowercase()));
    }

    /// Retain a bounded diagnostic for a source that could not enter the
    /// parser.  The source is deliberately not added to `sources`, so a
    /// transport or resource failure cannot leave a partially active pack.
    pub fn record_skipped_source(
        &mut self,
        source_id: impl Into<String>,
        bytes_read: usize,
        reason: SkipReason,
        format_hint: Option<RulePackFormat>,
    ) {
        let source_id = source_id.into();
        self.attempted_sources = self.attempted_sources.saturating_add(1);
        let mut report = SourceReport::new(&source_id);
        report.bytes_read = bytes_read;
        report.format = format_hint.filter(|format| *format != RulePackFormat::Auto);
        report.skipped_reason = Some(reason);
        self.report.sources.push(report);
    }

    /// Add a UTF-8 source.  Parsing and budget validation happen before the
    /// source enters the global builder, so an over-budget source is atomic.
    pub fn add_source_str(
        &mut self,
        source_id: impl Into<String>,
        text: &str,
        format_hint: Option<RulePackFormat>,
        usage: Option<RulePackUsage>,
    ) -> Result<()> {
        let source_id = source_id.into();
        let retain_report = true;
        self.attempted_sources += 1;
        let report_index = if retain_report {
            self.report.sources.len()
        } else {
            usize::MAX
        };
        let mut report = SourceReport::new(&source_id);
        report.bytes_read = text.len();

        if self.attempted_sources > self.limits.max_rule_pack_sources {
            report.skipped_reason = Some(SkipReason::SourceCountLimit);
            if retain_report {
                self.report.sources.push(report);
            }
            return Ok(());
        }
        if text.len() > self.limits.max_rule_pack_bytes {
            report.skipped_reason = Some(SkipReason::ByteLimit);
            if retain_report {
                self.report.sources.push(report);
            }
            return Ok(());
        }
        if self.total_bytes.saturating_add(text.len()) > self.limits.max_total_rule_pack_bytes {
            report.skipped_reason = Some(SkipReason::TotalByteLimit);
            if retain_report {
                self.report.sources.push(report);
            }
            return Ok(());
        }

        let format = match format_hint.filter(|format| *format != RulePackFormat::Auto) {
            Some(format) => format,
            None => match detect_format(text) {
                Some(format) => format,
                None => {
                    report.skipped_reason = Some(SkipReason::UnknownFormat);
                    if retain_report {
                        self.report.sources.push(report);
                    }
                    return Ok(());
                }
            },
        };
        report.format = Some(format);
        let mut counters = ParseCounters::default();
        let ir = parse_source(
            text,
            source_id.clone(),
            format,
            usage,
            report_index,
            &mut counters,
        )
        .map_err(|e| {
            report.skipped_reason = Some(SkipReason::Parse);
            if retain_report {
                self.report.sources.push(report.clone());
            }
            e
        })?;

        report.parsed_rules = ir.parsed_rules;
        report.accepted_rules = ir.accepted_rules;
        report.unsupported_rules = ir.unsupported_rules;
        report.failed_regexes = ir.failed_regexes;
        for sample in counters.unsupported {
            if report.unsupported_samples.len() < MAX_DIAGNOSTIC_SAMPLES {
                report.unsupported_samples.push(sample);
            }
        }
        for sample in counters.failed {
            if report.failed_samples.len() < MAX_DIAGNOSTIC_SAMPLES {
                report.failed_samples.push(sample);
            }
        }
        report
            .unsupported_samples
            .truncate(self.limits.max_diagnostic_samples);
        report
            .failed_samples
            .truncate(self.limits.max_diagnostic_samples);

        let normalized = ir.accepted_rules;
        let regex_rules = count_regex_rules(&ir);
        if normalized > self.limits.max_external_rules && source_id != "builtin" {
            report.skipped_reason = Some(SkipReason::RuleLimit);
            report.accepted_rules = 0;
            if retain_report {
                self.report.sources.push(report);
            }
            return Ok(());
        }
        if regex_rules > self.limits.max_regex_rules && source_id != "builtin" {
            report.skipped_reason = Some(SkipReason::RegexLimit);
            report.accepted_rules = 0;
            if retain_report {
                self.report.sources.push(report);
            }
            return Ok(());
        }

        self.total_bytes += text.len();
        self.report.total_bytes = self.total_bytes;
        self.sources.push(ir);
        if retain_report {
            self.report.sources.push(report);
        }
        Ok(())
    }

    /// Add bounded UTF-8 bytes from a local or remote loader.
    pub fn add_source_bytes(
        &mut self,
        source_id: impl Into<String>,
        bytes: &[u8],
        format_hint: Option<RulePackFormat>,
        usage: Option<RulePackUsage>,
    ) -> Result<()> {
        let source_id = source_id.into();
        let text = match String::from_utf8(bytes.to_vec()) {
            Ok(text) => text,
            Err(error) => {
                self.record_skipped_source(
                    source_id.clone(),
                    bytes.len(),
                    SkipReason::Parse,
                    format_hint,
                );
                return Err(CleanerError::Config(format!(
                    "rule source {source_id:?} is not UTF-8: {error}"
                )));
            }
        };
        self.add_source_str(source_id, &text, format_hint, usage)
    }

    /// Finish the builder and publish one immutable runtime store.
    pub fn finish(self) -> Ruleset {
        let disabled: Vec<String> = self.disabled_providers.into_iter().collect();
        build_ruleset(self.sources, disabled, self.report, self.limits)
    }
}

impl Ruleset {
    /// Construct an empty ruleset.
    ///
    /// This is the empty default expected by the public ruleset API. Call
    /// [`Ruleset::builtin`] when the built-in rules are explicitly desired.
    pub fn empty() -> Ruleset {
        RulesetBuilder::new(RuleLoadLimits::default()).finish()
    }

    /// The built-in ClearURLs-format rule pack.
    pub fn builtin() -> Ruleset {
        let mut builder = RulesetBuilder::new(RuleLoadLimits::default());
        builder
            .add_source_str(
                "builtin",
                BUILTIN_JSON,
                Some(RulePackFormat::ClearUrls),
                None,
            )
            .expect("built-in rules/builtin.json must be valid");
        builder.finish()
    }

    /// Parse a ClearURLs-format rule document.
    pub fn from_clearurls_str(json: &str) -> Result<Ruleset> {
        Self::from_source_str(json, RulePackFormat::ClearUrls)
    }

    /// Parse Brave Clean URLs JSON.
    pub fn from_brave_clean_urls_str(json: &str) -> Result<Ruleset> {
        Self::from_source_str(json, RulePackFormat::BraveCleanUrls)
    }

    /// Parse Brave Debounce JSON.
    pub fn from_brave_debounce_str(json: &str) -> Result<Ruleset> {
        Self::from_source_str(json, RulePackFormat::BraveDebounce)
    }

    /// Parse the supported AdGuard subset.
    pub fn from_adguard_str(text: &str) -> Result<Ruleset> {
        Self::from_source_str(text, RulePackFormat::AdGuard)
    }

    fn from_source_str(text: &str, format: RulePackFormat) -> Result<Ruleset> {
        let mut builder = RulesetBuilder::new(RuleLoadLimits::default());
        builder.add_source_str("source", text, Some(format), None)?;
        Ok(builder.finish())
    }

    /// Merge another ruleset through canonical definitions and rebuild all
    /// indexes. This compatibility API is slower than using one
    /// [`RulesetBuilder`] and should not be used at startup for many sources.
    pub fn merge(&mut self, other: Ruleset) {
        let mut sources = self.canonical.to_vec();
        sources.extend(other.canonical.iter().cloned());
        let mut disabled = self.disabled_providers.to_vec();
        disabled.extend(other.disabled_providers.iter().cloned());
        *self = build_ruleset(
            sources,
            disabled,
            RuleLoadReport::default(),
            RuleLoadLimits::default(),
        );
    }

    /// Disable named ClearURLs providers and rebuild the canonical store.
    pub fn disable(&mut self, names: &[String]) {
        let mut disabled = self.disabled_providers.to_vec();
        disabled.extend(names.iter().map(|name| name.to_ascii_lowercase()));
        *self = build_ruleset(
            self.canonical.to_vec(),
            disabled,
            RuleLoadReport::default(),
            RuleLoadLimits::default(),
        );
    }

    /// Number of active compiled providers.
    pub fn provider_count(&self) -> usize {
        self.store.providers.len()
    }

    /// Final immutable runtime statistics.
    pub fn stats(&self) -> &RuleStoreStats {
        &self.store.stats
    }

    /// Bounded source diagnostics.
    pub fn load_report(&self) -> &RuleLoadReport {
        &self.report
    }

    /// Build the candidate group set once for one URL.  Query-parameter loops
    /// should retain this context instead of rescanning provider scopes.
    pub fn context_for<'a>(&'a self, raw_url: &'a str, parsed_url: &'a Url) -> UrlContext<'a> {
        let mut candidates = BTreeSet::new();
        candidates.extend(self.store.scope_index.global.iter().copied());
        candidates.extend(self.store.scope_index.generic.iter().copied());

        if let Some(host) = parsed_url.host_str() {
            let host = host.to_ascii_lowercase();
            let labels: Vec<&str> = host.split('.').collect();
            for index in 0..labels.len() {
                let suffix = labels[index..].join(".");
                if let Some(groups) = self.store.scope_index.suffix.get(suffix.as_str()) {
                    candidates.extend(groups.iter().copied());
                }
            }
        }

        let active: Vec<usize> = candidates
            .into_iter()
            .filter(|group_id| {
                let group = &self.store.groups[*group_id];
                scopes_match(
                    &self.store.scopes,
                    &group.include_scopes,
                    &group.exclude_scopes,
                    raw_url,
                    parsed_url,
                )
            })
            .collect();

        let mut active = active;
        active.sort_by_key(|group_id| self.store.groups[*group_id].order);

        let clearurls_exceptions = self
            .store
            .providers
            .iter()
            .enumerate()
            .filter(|(_, provider)| {
                provider.url_pattern.is_match(raw_url)
                    && provider
                        .exceptions
                        .iter()
                        .any(|exception| exception.is_match(raw_url))
            })
            .map(|(id, _)| id)
            .collect();

        UrlContext {
            store: &self.store,
            raw_url,
            parsed_url,
            candidate_groups: active.into_boxed_slice(),
            clearurls_exceptions,
        }
    }

    /// Returns whether one raw query segment should be removed.
    pub fn should_remove_parameter(
        &self,
        url: &str,
        segment: &str,
        include_vendor: bool,
        include_referral: bool,
    ) -> bool {
        let Ok(parsed) = Url::parse(url) else {
            return false;
        };
        self.context_for(url, &parsed).should_remove_parameter(
            segment,
            include_vendor,
            include_referral,
        )
    }

    /// Compatibility API accepting a decoded parameter name. Query
    /// cleaners should call [`Ruleset::context_for`] with the raw segment so
    /// Brave's raw-key semantics survive.
    pub fn param_is_tracking(
        &self,
        url: &str,
        name: &str,
        include_vendor: bool,
        include_referral: bool,
    ) -> bool {
        let Ok(parsed) = Url::parse(url) else {
            return false;
        };
        let context = self.context_for(url, &parsed);
        if context.should_remove_parameter(name, include_vendor, include_referral) {
            return true;
        }

        // This legacy API receives a parameter name rather than a raw query
        // segment. Give matchers that require `=` a value-bearing
        // compatibility subject, while keeping actual URL cleaning on the
        // raw segment path above.
        if !name.contains('=') {
            let with_equals = format!("{name}=");
            return context.should_remove_parameter(&with_equals, include_vendor, include_referral);
        }
        false
    }

    /// Returns true when a ClearURLs provider exception applies to this URL.
    /// The runtime uses this only for ClearURLs actions; it cannot suppress
    /// Brave, AdGuard, or user-defined actions.
    pub fn is_exception(&self, url: &str) -> bool {
        let Ok(parsed) = Url::parse(url) else {
            return false;
        };
        !self
            .context_for(url, &parsed)
            .clearurls_exceptions
            .is_empty()
    }

    /// The first non-global provider matching this URL.
    pub fn detect_provider(&self, url: &str) -> Option<&str> {
        self.store
            .providers
            .iter()
            .find(|provider| !provider.global && provider.url_pattern.is_match(url))
            .map(|provider| provider.name.as_str())
    }

    /// Extract a destination from the first matching redirect rule in source
    /// order.  Ambiguous or invalid extractors return `None` rather than
    /// guessing.
    pub fn redirect_target(&self, url: &str) -> Option<String> {
        self.redirect_target_with_origin(url)
            .map(|target| target.target)
    }

    /// Extract a redirect destination and retain the source-format marker
    /// needed by the caller's format-specific safety policy.
    pub fn redirect_target_with_origin(&self, url: &str) -> Option<RedirectTarget> {
        let parsed = Url::parse(url).ok()?;
        for rule in self.store.redirects.iter() {
            if !scopes_match(
                &self.store.scopes,
                &rule.include,
                &rule.exclude,
                url,
                &parsed,
            ) {
                continue;
            }
            if let Some(target) = extract_redirect_target(&rule.extractor, url, &parsed) {
                return Some(RedirectTarget {
                    target,
                    origin: rule.origin,
                });
            }
        }
        None
    }

    /// Apply ClearURLs `rawRules` only when explicitly requested by callers.
    /// The normal URL/message cleaning path deliberately does not call this.
    pub fn apply_raw_rules(&self, url: &str) -> (String, bool) {
        let parsed = Url::parse(url).ok();
        let mut current = url.to_string();
        let mut changed = false;
        for rule in self.store.raw_rules.iter() {
            let Some(parsed) = parsed.as_ref() else {
                break;
            };
            if !scopes_match(&self.store.scopes, &rule.include, &[], url, parsed) {
                continue;
            }
            if rule.regex.is_match(&current) {
                current = rule.regex.replace_all(&current, "").into_owned();
                changed = true;
            }
        }
        (current, changed)
    }

    /// Returns true for a complete ClearURLs provider or an explicit image
    /// beacon rule.  This method is only a classifier; HTML call sites decide
    /// whether an image/CSS context is safe to neutralize.
    pub fn is_complete_block(&self, url: &str) -> bool {
        if self
            .store
            .providers
            .iter()
            .any(|provider| provider.complete && provider.url_pattern.is_match(url))
        {
            return true;
        }
        self.is_beacon_url(url, None)
    }

    /// Match external/complete-provider beacon rules against the raw source
    /// URL and, when available, its parsed host.
    pub fn is_beacon_url(&self, url: &str, host: Option<&str>) -> bool {
        let parsed = Url::parse(url).ok();
        self.store.beacons.iter().any(|rule| {
            if let Some(parsed) = parsed.as_ref() {
                if scopes_match(
                    &self.store.scopes,
                    &rule.include,
                    &rule.exclude,
                    url,
                    parsed,
                ) {
                    return true;
                }
                // A parsed URL that did not satisfy the target scope is an
                // ordinary direct URL, not an encoded proxy payload.  Do not
                // let a broad raw fallback (for example `*`) turn a scoped
                // image rule into a global beacon rule.
                if !contains_embedded_url(url) {
                    return false;
                }
            }
            let Some(raw_regex) = &rule.raw_regex else {
                return false;
            };
            raw_regex.is_match(url)
                || host.map(|host| raw_regex.is_match(host)).unwrap_or(false)
                || (contains_embedded_url(url) && regex_matches_embedded_url(raw_regex, url))
        })
    }
}

/// A per-URL immutable candidate context.
pub struct UrlContext<'a> {
    store: &'a RuleStore,
    raw_url: &'a str,
    parsed_url: &'a Url,
    candidate_groups: Box<[usize]>,
    clearurls_exceptions: Box<[usize]>,
}

impl fmt::Debug for UrlContext<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UrlContext")
            .field("raw_url", &self.raw_url)
            .field("candidate_groups", &self.candidate_groups.len())
            .field("clearurls_exceptions", &self.clearurls_exceptions.len())
            .finish()
    }
}

impl UrlContext<'_> {
    /// Number of groups whose URL scopes were evaluated for this URL.
    pub fn candidate_group_count(&self) -> usize {
        self.candidate_groups.len()
    }

    /// True when a ClearURLs exception matched this URL.
    pub fn has_clearurls_exception(&self) -> bool {
        !self.clearurls_exceptions.is_empty()
    }

    /// Match one raw query segment against the active groups.
    pub fn should_remove_parameter(
        &self,
        segment: &str,
        include_vendor: bool,
        include_referral: bool,
    ) -> bool {
        for group_id in self.candidate_groups.iter().copied() {
            let action = &self.store.actions[self.store.groups[group_id].action];
            if action.exception || !action_enabled(action, self, include_vendor, include_referral) {
                continue;
            }
            if !action.matcher.matches(segment, &self.store.regex_chunks) {
                continue;
            }
            // ClearURLs exceptions are URL-wide within the matching provider.
            // A semantically deduplicated action may have
            // several active provider contributors, so the carve-out applies
            // only when every contributor is currently exceptional.
            if action.source == SourceKind::ClearUrls
                && action.legacy_builtin_global_carveout
                && self.has_clearurls_exception()
            {
                continue;
            }
            if action.source == SourceKind::ClearUrls
                && !action.clearurls_provider_ids.is_empty()
                && action
                    .clearurls_provider_ids
                    .iter()
                    .all(|provider_id| self.clearurls_exceptions.contains(provider_id))
            {
                continue;
            }
            if action.source == SourceKind::AdGuard
                && self.has_matching_adguard_exception(
                    action,
                    segment,
                    include_vendor,
                    include_referral,
                )
            {
                continue;
            }
            return true;
        }
        false
    }

    fn has_matching_adguard_exception(
        &self,
        positive: &ParamAction,
        segment: &str,
        include_vendor: bool,
        include_referral: bool,
    ) -> bool {
        self.candidate_groups.iter().copied().any(|group_id| {
            let action = &self.store.actions[self.store.groups[group_id].action];
            action.source == SourceKind::AdGuard
                && action.exception
                && action_enabled(action, self, include_vendor, include_referral)
                && (action.exception_all
                    || (action.matcher_spec == positive.matcher_spec
                        && action.matcher.matches(segment, &self.store.regex_chunks)))
        })
    }
}

fn action_enabled(
    action: &ParamAction,
    context: &UrlContext<'_>,
    include_vendor: bool,
    include_referral: bool,
) -> bool {
    if action.source == SourceKind::ClearUrls {
        if action.referral && !include_referral {
            return false;
        }
        if !action.global && !include_vendor {
            return false;
        }
    }
    // Keep the URL fields visibly part of the context contract.  Scopes have
    // already been evaluated once; this also prevents accidental future APIs
    // from silently dropping them.
    let _ = (context.raw_url, context.parsed_url);
    true
}

fn build_ruleset(
    sources: Vec<SourceIr>,
    disabled_providers: Vec<String>,
    mut report: RuleLoadReport,
    _limits: RuleLoadLimits,
) -> Ruleset {
    let disabled: HashSet<String> = disabled_providers
        .iter()
        .map(|name| name.to_ascii_lowercase())
        .collect();
    let (store, skipped, duplicates) = compile_store(&sources, &disabled);
    for (report_index, count) in duplicates {
        if let Some(source) = report.sources.get_mut(report_index) {
            source.duplicates += count;
        }
    }
    if report.sources.is_empty() {
        for source in &sources {
            let mut source_report = SourceReport::new(&source.source);
            source_report.format = Some(source.format);
            source_report.parsed_rules = source.parsed_rules;
            source_report.accepted_rules = source.accepted_rules;
            source_report.unsupported_rules = source.unsupported_rules;
            source_report.failed_regexes = source.failed_regexes;
            report.sources.push(source_report);
        }
    }
    Ruleset {
        store: Arc::new(store),
        canonical: Arc::from(sources.into_boxed_slice()),
        disabled_providers: Arc::from(disabled_providers.into_boxed_slice()),
        report,
        skipped_patterns: skipped,
    }
}

fn compile_store(
    sources: &[SourceIr],
    disabled: &HashSet<String>,
) -> (RuleStore, usize, HashMap<usize, usize>) {
    let mut skipped = 0usize;
    let mut scopes = Vec::<CompiledScope>::new();
    let mut scope_ids = HashMap::<ScopeSpec, ScopeId>::new();
    let mut intern_scope = |spec: &ScopeSpec| -> Option<ScopeId> {
        if let Some(id) = scope_ids.get(spec).copied() {
            return Some(id);
        }
        let compiled = compile_scope(spec).ok()?;
        let id = scopes.len();
        scopes.push(compiled);
        scope_ids.insert(spec.clone(), id);
        Some(id)
    };

    let mut providers = Vec::<Provider>::new();
    let mut provider_ids = HashMap::<String, usize>::new();
    for source in sources {
        for provider in &source.providers {
            if disabled.contains(&provider.name.to_ascii_lowercase()) {
                continue;
            }
            let Some(url_pattern) = compile_url_pattern(&provider.url_pattern) else {
                skipped += 1;
                continue;
            };
            let exceptions = provider
                .exceptions
                .iter()
                .filter_map(|pattern| compile_url_pattern(pattern))
                .collect::<Vec<_>>();
            let provider_id = providers.len();
            providers.push(Provider {
                name: provider.name.to_string(),
                global: provider.global,
                complete: provider.complete,
                url_pattern,
                exceptions,
            });
            provider_ids.insert(
                clearurls_provider_identity(&source.source, &provider.name),
                provider_id,
            );
        }
    }

    let mut pending = Vec::<PendingParamAction>::new();
    let mut parameter_order = 0u32;
    let mut seen = HashMap::<ParamDedupKey, usize>::new();
    let mut duplicates = HashMap::<usize, usize>::new();
    for source in sources {
        for rule in &source.params {
            if rule
                .provider
                .as_deref()
                .map(|provider| disabled.contains(&provider.to_ascii_lowercase()))
                .unwrap_or(false)
            {
                continue;
            }
            let clearurls_provider_ids = if rule.source == SourceKind::ClearUrls {
                let Some(provider) = rule.provider.as_deref() else {
                    skipped += 1;
                    continue;
                };
                let Some(provider_id) = provider_ids
                    .get(&clearurls_provider_identity(&source.source, provider))
                    .copied()
                else {
                    // A positive rule cannot remain active when its provider
                    // scope failed to compile.  This also prevents a failed
                    // provider from contributing an incomplete exception
                    // membership to a deduplicated action.
                    skipped += 1;
                    continue;
                };
                vec![provider_id]
            } else {
                Vec::new()
            };
            let legacy_builtin_global_carveout =
                rule.source == SourceKind::ClearUrls && rule.global && source.source == "builtin";
            let key = ParamDedupKey {
                global: rule.global,
                referral: rule.referral,
                exception: rule.exception,
                exception_all: rule.exception_all,
                legacy_builtin_global_carveout,
                matcher: rule.matcher.clone(),
                include: rule.include.clone(),
                exclude: rule.exclude.clone(),
            };
            if let Some(existing_index) = seen.get(&key).copied() {
                let existing = &mut pending[existing_index];
                for provider_id in clearurls_provider_ids {
                    if !existing.clearurls_provider_ids.contains(&provider_id) {
                        existing.clearurls_provider_ids.push(provider_id);
                    }
                }
                *duplicates.entry(rule.report_index).or_default() += 1;
                continue;
            }
            let Some(include) = intern_scopes(&mut intern_scope, &rule.include) else {
                skipped += 1;
                continue;
            };
            let Some(exclude) = intern_scopes(&mut intern_scope, &rule.exclude) else {
                skipped += 1;
                continue;
            };
            let pending_index = pending.len();
            seen.insert(key, pending_index);
            pending.push(PendingParamAction {
                source: rule.source,
                global: rule.global,
                referral: rule.referral,
                exception: rule.exception,
                exception_all: rule.exception_all,
                legacy_builtin_global_carveout,
                clearurls_provider_ids,
                matcher: rule.matcher.clone(),
                include,
                exclude,
                order: parameter_order,
            });
            parameter_order = parameter_order.saturating_add(1);
        }
    }

    let (regex_chunks, regex_refs, failed_regex_actions) = compile_regex_chunks(&pending);
    skipped += failed_regex_actions;
    let mut actions = Vec::<ParamAction>::new();
    let mut groups = Vec::<RuleGroup>::new();
    let mut exact = 0;
    let mut prefix = 0;
    let mut regex = 0;
    for (pending_index, item) in pending.into_iter().enumerate() {
        let Some(matcher) = compile_matcher(&item.matcher, regex_refs[pending_index]) else {
            continue;
        };
        match item.matcher {
            ParamMatcherSpec::Exact { .. } => exact += 1,
            ParamMatcherSpec::Prefix { .. } => prefix += 1,
            ParamMatcherSpec::Regex { .. } => regex += 1,
        }
        let action = actions.len();
        actions.push(ParamAction {
            source: item.source,
            global: item.global,
            referral: item.referral,
            exception: item.exception,
            exception_all: item.exception_all,
            legacy_builtin_global_carveout: item.legacy_builtin_global_carveout,
            clearurls_provider_ids: item.clearurls_provider_ids.into_boxed_slice(),
            matcher_spec: item.matcher.clone(),
            matcher,
        });
        groups.push(RuleGroup {
            include_scopes: item.include,
            exclude_scopes: item.exclude,
            action,
            order: item.order,
        });
    }

    let mut redirects = Vec::new();
    let mut redirect_order = 0u32;
    for source in sources {
        for rule in &source.redirects {
            if rule
                .provider
                .as_deref()
                .map(|provider| disabled.contains(&provider.to_ascii_lowercase()))
                .unwrap_or(false)
            {
                continue;
            }
            let Some(include) = intern_scopes(&mut intern_scope, &rule.include) else {
                skipped += 1;
                continue;
            };
            let Some(exclude) = intern_scopes(&mut intern_scope, &rule.exclude) else {
                skipped += 1;
                continue;
            };
            let Some(extractor) = compile_redirect_extractor(&rule.extractor) else {
                skipped += 1;
                continue;
            };
            redirects.push(CompiledRedirectRule {
                include,
                exclude,
                extractor,
                origin: if source.format == RulePackFormat::BraveDebounce {
                    RedirectOrigin::Brave
                } else {
                    RedirectOrigin::Legacy
                },
                order: redirect_order,
            });
            redirect_order = redirect_order.saturating_add(1);
        }
    }
    redirects.sort_by_key(|rule| rule.order);

    let mut beacons = Vec::new();
    for source in sources {
        for rule in &source.beacons {
            let Some(include) = intern_scopes(&mut intern_scope, &rule.include) else {
                skipped += 1;
                continue;
            };
            let Some(exclude) = intern_scopes(&mut intern_scope, &rule.exclude) else {
                skipped += 1;
                continue;
            };
            let raw_regex = rule
                .raw_pattern
                .as_deref()
                .and_then(compile_beacon_raw_regex);
            beacons.push(CompiledBeaconRule {
                include,
                exclude,
                raw_regex,
            });
        }
    }
    for provider in providers.iter() {
        if provider.complete {
            let include = intern_scope(&ScopeSpec::UrlRegex(
                format_regex_for_scope(provider.url_pattern.as_str()).into_boxed_str(),
            ))
            .into_iter()
            .collect::<Box<[_]>>();
            beacons.push(CompiledBeaconRule {
                include,
                exclude: Box::new([]),
                raw_regex: Some(provider.url_pattern.clone()),
            });
        }
    }

    let mut raw_rules = Vec::new();
    for source in sources {
        for rule in &source.raw_rules {
            if disabled.contains(&rule.provider.to_ascii_lowercase()) {
                continue;
            }
            let Some(include) = intern_scopes(&mut intern_scope, &rule.include) else {
                skipped += 1;
                continue;
            };
            let Some(regex) = compile_whole_url_pattern(&rule.pattern) else {
                skipped += 1;
                continue;
            };
            raw_rules.push(CompiledRawRule { include, regex });
        }
    }

    let scope_index = build_scope_index(&scopes, &groups);
    let stats = RuleStoreStats {
        scopes: scopes.len(),
        groups: groups.len(),
        exact_param_rules: exact,
        prefix_param_rules: prefix,
        regex_param_rules: regex,
        regex_set_chunks: regex_chunks.len(),
        domain_index_keys: scope_index.suffix.len(),
        beacon_rules: beacons.len(),
        redirect_rules: redirects.len(),
        raw_rules: raw_rules.len(),
        providers: providers.len(),
    };
    (
        RuleStore {
            providers: providers.into_boxed_slice(),
            scopes: scopes.into_boxed_slice(),
            groups: groups.into_boxed_slice(),
            actions: actions.into_boxed_slice(),
            regex_chunks: regex_chunks.into_boxed_slice(),
            scope_index,
            redirects: redirects.into_boxed_slice(),
            beacons: beacons.into_boxed_slice(),
            raw_rules: raw_rules.into_boxed_slice(),
            stats,
        },
        skipped,
        duplicates,
    )
}

fn clearurls_provider_identity(source: &str, provider: &str) -> String {
    format!("{source}\u{1f}{provider}")
}

#[derive(Debug, Clone)]
struct PendingParamAction {
    source: SourceKind,
    global: bool,
    referral: bool,
    exception: bool,
    exception_all: bool,
    legacy_builtin_global_carveout: bool,
    clearurls_provider_ids: Vec<usize>,
    matcher: ParamMatcherSpec,
    include: Box<[ScopeId]>,
    exclude: Box<[ScopeId]>,
    order: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ParamDedupKey {
    global: bool,
    referral: bool,
    exception: bool,
    exception_all: bool,
    legacy_builtin_global_carveout: bool,
    matcher: ParamMatcherSpec,
    include: Vec<ScopeSpec>,
    exclude: Vec<ScopeSpec>,
}

type RegexCompileResult = (Vec<RegexSetChunk>, Vec<Option<(usize, usize)>>, usize);

fn compile_regex_chunks(pending: &[PendingParamAction]) -> RegexCompileResult {
    let mut groups: BTreeMap<(ParamSubject, bool, bool), Vec<(usize, String)>> = BTreeMap::new();
    for (index, item) in pending.iter().enumerate() {
        if let ParamMatcherSpec::Regex {
            pattern,
            subject,
            case_sensitive,
            requires_equals,
        } = &item.matcher
        {
            groups
                .entry((*subject, *case_sensitive, *requires_equals))
                .or_default()
                .push((index, pattern.to_string()));
        }
    }

    let mut chunks = Vec::new();
    let mut refs = vec![None; pending.len()];
    let mut failed = 0;
    for entries in groups.into_values() {
        let mut batch_start = 0;
        let mut batch_bytes: usize = 0;
        for (index, (_, pattern)) in entries.iter().enumerate() {
            let pattern_bytes = pattern.len();
            if pattern_bytes > MAX_REGEX_PATTERN_BYTES {
                if batch_start < index {
                    compile_regex_batch(
                        &entries[batch_start..index],
                        &mut chunks,
                        &mut refs,
                        &mut failed,
                    );
                }
                batch_start = index + 1;
                batch_bytes = 0;
                failed += 1;
                continue;
            }
            let would_exceed = batch_start < index
                && batch_bytes.saturating_add(pattern_bytes) > MAX_REGEX_CHUNK_BYTES;
            if would_exceed || index.saturating_sub(batch_start) >= MAX_REGEX_CHUNK_PATTERNS {
                compile_regex_batch(
                    &entries[batch_start..index],
                    &mut chunks,
                    &mut refs,
                    &mut failed,
                );
                batch_start = index;
                batch_bytes = 0;
            }
            batch_bytes = batch_bytes.saturating_add(pattern_bytes);
        }
        if batch_start < entries.len() {
            compile_regex_batch(&entries[batch_start..], &mut chunks, &mut refs, &mut failed);
        }
    }
    (chunks, refs, failed)
}

fn compile_regex_batch(
    entries: &[(usize, String)],
    chunks: &mut Vec<RegexSetChunk>,
    refs: &mut [Option<(usize, usize)>],
    failed: &mut usize,
) {
    let patterns: Vec<&str> = entries
        .iter()
        .map(|(_, pattern)| pattern.as_str())
        .collect();
    match RegexSet::new(patterns) {
        Ok(set) => {
            let chunk = chunks.len();
            chunks.push(RegexSetChunk { set });
            for (index, (pending, _)) in entries.iter().enumerate() {
                refs[*pending] = Some((chunk, index));
            }
        }
        Err(_) if entries.len() > 1 => {
            let midpoint = entries.len() / 2;
            compile_regex_batch(&entries[..midpoint], chunks, refs, failed);
            compile_regex_batch(&entries[midpoint..], chunks, refs, failed);
        }
        Err(_) => {
            *failed += 1;
        }
    }
}

fn compile_matcher(
    spec: &ParamMatcherSpec,
    regex_ref: Option<(usize, usize)>,
) -> Option<CompiledParamMatcher> {
    let (kind, subject, case_sensitive, requires_equals) = match spec {
        ParamMatcherSpec::Exact {
            value,
            subject,
            case_sensitive,
            requires_equals,
        } => (
            CompiledMatcherKind::Exact(value.clone()),
            *subject,
            *case_sensitive,
            *requires_equals,
        ),
        ParamMatcherSpec::Prefix {
            value,
            subject,
            case_sensitive,
            requires_equals,
        } => (
            CompiledMatcherKind::Prefix(value.clone()),
            *subject,
            *case_sensitive,
            *requires_equals,
        ),
        ParamMatcherSpec::Regex {
            subject,
            case_sensitive,
            requires_equals,
            ..
        } => (
            CompiledMatcherKind::Regex {
                chunk: regex_ref?.0,
                index: regex_ref?.1,
            },
            *subject,
            *case_sensitive,
            *requires_equals,
        ),
    };
    Some(CompiledParamMatcher {
        kind,
        subject,
        case_sensitive,
        requires_equals,
    })
}

fn build_scope_index(scopes: &[CompiledScope], groups: &[RuleGroup]) -> ScopeIndex {
    let mut index = ScopeIndex::default();
    for (group_id, group) in groups.iter().enumerate() {
        if group.include_scopes.is_empty() {
            index.global.push(group_id);
            continue;
        }
        let mut indexed = false;
        for scope_id in group.include_scopes.iter().copied() {
            scopes[scope_id].for_each_host_hint(|host| {
                index
                    .suffix
                    .entry(host.to_ascii_lowercase().into_boxed_str())
                    .or_default()
                    .push(group_id);
                indexed = true;
            });
        }
        if !indexed {
            index.generic.push(group_id);
        }
    }
    index
}

fn intern_scopes(
    intern: &mut impl FnMut(&ScopeSpec) -> Option<ScopeId>,
    specs: &[ScopeSpec],
) -> Option<Box<[ScopeId]>> {
    specs
        .iter()
        .map(intern)
        .collect::<Option<Vec<_>>>()
        .map(Vec::into_boxed_slice)
}

fn scopes_match(
    scopes: &[CompiledScope],
    include: &[ScopeId],
    exclude: &[ScopeId],
    raw_url: &str,
    parsed: &Url,
) -> bool {
    let included = include.is_empty()
        || include
            .iter()
            .any(|id| scopes[*id].matches(raw_url, parsed));
    included
        && !exclude
            .iter()
            .any(|id| scopes[*id].matches(raw_url, parsed))
}

fn compile_scope(spec: &ScopeSpec) -> std::result::Result<CompiledScope, String> {
    match spec {
        ScopeSpec::Any => Ok(CompiledScope::Any),
        ScopeSpec::UrlRegex(pattern) => checked_regex(pattern)
            .map(CompiledScope::UrlRegex)
            .map_err(|error| error.to_string()),
        ScopeSpec::UrlGlob(pattern) => {
            if !regex_pattern_allowed(pattern) {
                return Err("pattern exceeds hard byte limit".into());
            }
            let regex = checked_generated_regex(&glob_to_regex(pattern))
                .map_err(|error| error.to_string())?;
            Ok(CompiledScope::UrlGlob {
                regex,
                host_suffix: extract_glob_host_suffix(pattern),
            })
        }
        ScopeSpec::AdGuardTarget {
            pattern,
            domains,
            match_case,
        } => {
            if !regex_pattern_allowed(pattern) {
                return Err("pattern exceeds hard byte limit".into());
            }
            let regex = checked_generated_regex(&adguard_target_regex(pattern, *match_case))
                .map_err(|error| error.to_string())?;
            let host_suffix = domains
                .first()
                .cloned()
                .or_else(|| extract_adguard_host(pattern));
            Ok(CompiledScope::AdGuardTarget {
                regex,
                domains: domains.clone(),
                host_suffix,
            })
        }
    }
}

fn compile_url_pattern(pattern: &str) -> Option<Regex> {
    checked_regex(&format!("(?i){pattern}")).ok()
}

fn compile_whole_url_pattern(pattern: &str) -> Option<Regex> {
    checked_regex(&format!("(?i){pattern}")).ok()
}

fn format_regex_for_scope(pattern: &str) -> String {
    if pattern.starts_with("(?i)") {
        pattern.to_string()
    } else {
        format!("(?i){pattern}")
    }
}

fn compile_redirect_extractor(ir: &RedirectExtractorIr) -> Option<RedirectExtractor> {
    match ir {
        RedirectExtractorIr::ClearUrls { pattern } => checked_regex(&format!("(?i){pattern}"))
            .ok()
            .map(|regex| RedirectExtractor::ClearUrls { regex }),
        RedirectExtractorIr::QueryParam {
            names,
            decode,
            prepend_scheme,
        } => Some(RedirectExtractor::QueryParam {
            names: names.clone(),
            decode: *decode,
            prepend_scheme: prepend_scheme.clone(),
        }),
        RedirectExtractorIr::PathRegex {
            pattern,
            assembly,
            prepend_scheme,
        } => checked_regex(pattern)
            .ok()
            .map(|regex| RedirectExtractor::PathRegex {
                regex,
                assembly: assembly.clone(),
                prepend_scheme: prepend_scheme.clone(),
            }),
    }
}

fn extract_redirect_target(
    extractor: &RedirectExtractor,
    raw_url: &str,
    parsed: &Url,
) -> Option<String> {
    match extractor {
        RedirectExtractor::ClearUrls { regex } => regex
            .captures(raw_url)
            .and_then(|captures| captures.get(1).map(|match_| match_.as_str().to_string())),
        RedirectExtractor::QueryParam {
            names,
            decode,
            prepend_scheme,
        } => {
            let query = parsed.query()?;
            let mut found: Option<&str> = None;
            for segment in query.split('&') {
                let (raw_name, has_equals, raw_value) = split_query_segment(segment);
                if !has_equals || !names.iter().any(|name| name.as_ref() == raw_name) {
                    continue;
                }
                if let Some(previous) = found {
                    if previous != raw_value {
                        return None;
                    }
                } else {
                    found = Some(raw_value);
                }
            }
            let value = found?;
            let mut value = match decode {
                DecodeMode::Direct | DecodeMode::ExistingAutoDecode => value.to_string(),
                DecodeMode::Base64Url => {
                    let decoded = percent_decode_str(value).decode_utf8_lossy();
                    String::from_utf8(decode_base64_loose(&decoded)?).ok()?
                }
            };
            if let Some(scheme) = prepend_scheme {
                value = prepend_scheme_value(&value, scheme)?;
            }
            Some(value)
        }
        RedirectExtractor::PathRegex {
            regex,
            assembly,
            prepend_scheme,
        } => {
            let captures = regex.captures(parsed.path())?;
            let mut parts = Vec::new();
            for index in 1..captures.len() {
                parts.push(captures.get(index)?.as_str());
            }
            let mut value = match assembly {
                CaptureAssembly::Concatenate => parts.concat(),
                CaptureAssembly::Template(template) => {
                    let mut out = template.to_string();
                    for index in 1..captures.len() {
                        let placeholder = format!("${index}");
                        out = out.replace(&placeholder, captures.get(index)?.as_str());
                    }
                    out
                }
            };
            if let Some(scheme) = prepend_scheme {
                value = prepend_scheme_value(&value, scheme)?;
            }
            Some(value)
        }
    }
}

fn prepend_scheme_value(value: &str, scheme: &str) -> Option<String> {
    if Url::parse(value).is_ok() {
        return None;
    }
    let decoded = percent_decode_str(value).decode_utf8_lossy();
    let candidate = format!("{scheme}://{decoded}");
    Url::parse(&candidate).ok().map(|_| candidate)
}

fn decode_base64_loose(raw: &str) -> Option<Vec<u8>> {
    let raw = raw.trim_end_matches('=');
    if raw.len() < 8 {
        return None;
    }
    URL_SAFE_NO_PAD
        .decode(raw)
        .or_else(|_| STANDARD_NO_PAD.decode(raw))
        .ok()
}

fn split_query_segment(segment: &str) -> (&str, bool, &str) {
    match segment.split_once('=') {
        Some((name, value)) => (name, true, value),
        None => (segment, false, ""),
    }
}

fn contains_embedded_url(raw_url: &str) -> bool {
    let lower = raw_url.to_ascii_lowercase();
    lower.contains("%3a%2f%2f")
        || lower
            .find("://")
            .is_some_and(|offset| lower[offset + 3..].contains("://"))
}

fn regex_matches_embedded_url(regex: &Regex, raw_url: &str) -> bool {
    let decoded = decode_query_component(raw_url);
    let lower = decoded.to_ascii_lowercase();
    let mut offset = 0;
    while offset < lower.len() {
        let relative = ["https://", "http://"]
            .iter()
            .filter_map(|marker| lower[offset..].find(marker))
            .min();
        let Some(relative) = relative else {
            break;
        };
        let start = offset + relative;
        if regex.is_match(&decoded[start..]) {
            return true;
        }
        offset = start.saturating_add(1);
    }
    false
}

fn decode_query_component(value: &str) -> String {
    percent_decode_str(&value.replace('+', " "))
        .decode_utf8_lossy()
        .into_owned()
}

fn host_suffix_matches(host: &str, suffix: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let suffix = suffix
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    host == suffix || host.ends_with(&format!(".{suffix}"))
}

fn glob_to_regex(pattern: &str) -> String {
    let mut out = String::from("(?is)^");
    for character in pattern.chars() {
        match character {
            '*' => out.push_str(".*"),
            '?' => out.push('.'),
            _ => out.push_str(&regex::escape(&character.to_string())),
        }
    }
    out.push('$');
    out
}

fn extract_glob_host_suffix(pattern: &str) -> Option<Box<str>> {
    let after_scheme = pattern.split_once("://")?.1;
    let host = after_scheme.split(['/', '?', '#']).next()?;
    if host.is_empty() || host.contains('?') {
        return None;
    }
    let host = host.strip_prefix("*.").unwrap_or(host);
    if host.is_empty() || host.contains('*') {
        return None;
    }
    Some(host.to_ascii_lowercase().into_boxed_str())
}

fn adguard_target_regex(pattern: &str, match_case: bool) -> String {
    let mut pattern = pattern;
    let domain_anchor = pattern.starts_with("||");
    let anchored_start = !domain_anchor && pattern.starts_with('|');
    let anchored_end = pattern.ends_with('|') && !pattern.ends_with("\\|");
    if domain_anchor {
        pattern = &pattern[2..];
    } else if anchored_start {
        pattern = &pattern[1..];
    }
    if anchored_end {
        pattern = &pattern[..pattern.len() - 1];
    }

    let mut out = if match_case {
        String::new()
    } else {
        String::from("(?i)")
    };
    if domain_anchor {
        out.push_str("https?://(?:[^/?#]+\\.)?");
    } else if anchored_start {
        out.push('^');
    }
    for character in pattern.chars() {
        match character {
            '*' => out.push_str(".*"),
            '^' => out.push_str("(?:[^A-Za-z0-9_.%-]|$)"),
            _ => out.push_str(&regex::escape(&character.to_string())),
        }
    }
    if anchored_end {
        out.push('$');
    }
    out
}

fn extract_adguard_host(pattern: &str) -> Option<Box<str>> {
    let rest = pattern.strip_prefix("||")?;
    let host = rest.split(['/', '^', '*', '|']).next()?;
    (!host.is_empty() && !host.contains(':')).then(|| host.to_ascii_lowercase().into_boxed_str())
}

fn compile_beacon_raw_regex(pattern: &str) -> Option<Regex> {
    let domain_anchor = pattern.starts_with("||");
    let literal = if domain_anchor {
        &pattern[2..]
    } else {
        pattern.trim_start_matches('|')
    };
    let mut regex = String::from("(?i)");
    if domain_anchor {
        // AdGuard's `||` is a host boundary, not a substring operator.  Keep
        // the raw-source fallback for proxy URLs, including encoded embedded
        // destinations, while requiring a real or encoded URL authority.
        regex.push_str(r"(?:https?://|https?%3a%2f%2f|%2f%2f)(?:[a-z0-9-]+\.)*");
    }
    for character in literal.chars() {
        match character {
            '*' => regex.push_str(".*"),
            '^' if domain_anchor => regex.push_str("(?:[^A-Za-z0-9_.-]|$)"),
            '^' => regex.push_str("(?:[^A-Za-z0-9_.%-]|$)"),
            '|' => {}
            _ => regex.push_str(&regex::escape(&character.to_string())),
        }
    }
    checked_generated_regex(&regex).ok()
}

fn regex_pattern_allowed(pattern: &str) -> bool {
    pattern.len() <= MAX_REGEX_PATTERN_BYTES
}

fn checked_regex(pattern: &str) -> std::result::Result<Regex, regex::Error> {
    if !regex_pattern_allowed(pattern) {
        return Err(regex::Error::Syntax(
            "pattern exceeds hard byte limit".into(),
        ));
    }
    Regex::new(pattern)
}

fn checked_generated_regex(pattern: &str) -> std::result::Result<Regex, regex::Error> {
    if pattern.len() > MAX_GENERATED_REGEX_BYTES {
        return Err(regex::Error::Syntax(
            "generated pattern exceeds hard byte limit".into(),
        ));
    }
    Regex::new(pattern)
}

fn sanitize_source_id(source: &str) -> String {
    let source = source.trim();
    let sanitized = if let Ok(mut url) = Url::parse(source) {
        let _ = url.set_username("");
        let _ = url.set_password(None);
        url.set_query(None);
        url.set_fragment(None);
        url.to_string()
    } else {
        source.to_string()
    };
    sanitized.chars().take(240).collect()
}

fn detect_format(text: &str) -> Option<RulePackFormat> {
    let trimmed = text.trim_start();
    if trimmed.starts_with('{') {
        return serde_json::from_str::<RawRuleset>(trimmed)
            .ok()
            .map(|_| RulePackFormat::ClearUrls);
    }
    if trimmed.starts_with('[') {
        let entries = serde_json::from_str::<Vec<serde_json::Value>>(trimmed).ok()?;
        if entries.iter().any(|entry| entry.get("action").is_some()) {
            return Some(RulePackFormat::BraveDebounce);
        }
        if entries.iter().any(|entry| entry.get("params").is_some()) {
            return Some(RulePackFormat::BraveCleanUrls);
        }
        return None;
    }
    Some(RulePackFormat::AdGuard)
}

fn parse_source(
    text: &str,
    source: String,
    format: RulePackFormat,
    usage: Option<RulePackUsage>,
    report_index: usize,
    counters: &mut ParseCounters,
) -> Result<SourceIr> {
    match format {
        RulePackFormat::Auto => Err(CleanerError::Config("source format remained auto".into())),
        RulePackFormat::ClearUrls => parse_clearurls(text, source, usage, report_index, counters),
        RulePackFormat::BraveCleanUrls => {
            parse_brave_clean_urls(text, source, usage, report_index, counters)
        }
        RulePackFormat::BraveDebounce => {
            parse_brave_debounce(text, source, usage, report_index, counters)
        }
        RulePackFormat::AdGuard => parse_adguard(text, source, usage, report_index, counters),
    }
}

fn parse_clearurls(
    text: &str,
    source: String,
    _usage: Option<RulePackUsage>,
    report_index: usize,
    counters: &mut ParseCounters,
) -> Result<SourceIr> {
    let raw: RawRuleset = serde_json::from_str(text)
        .map_err(|error| CleanerError::Config(format!("ClearURLs rule pack: {error}")))?;
    let mut ir = SourceIr {
        format: RulePackFormat::ClearUrls,
        source,
        ..SourceIr::default()
    };
    for (name, provider) in raw.providers {
        let provider_pattern = format!("(?i){}", provider.url_pattern);
        if !regex_pattern_allowed(&provider_pattern) || Regex::new(&provider_pattern).is_err() {
            counters.failed(format!("{name}.urlPattern"));
            ir.failed_regexes += 1;
            continue;
        }
        let mut exceptions = Vec::with_capacity(provider.exceptions.len());
        for pattern in &provider.exceptions {
            let compiled = format!("(?i){pattern}");
            if !regex_pattern_allowed(&compiled) || Regex::new(&compiled).is_err() {
                counters.failed(format!("{name}.exceptions:{pattern}"));
                ir.failed_regexes += 1;
                return Err(CleanerError::Config(format!(
                    "ClearURLs provider {name} has an invalid exception regex"
                )));
            }
            exceptions.push(pattern.clone());
        }
        let provider_ir = ProviderIr {
            name: name.clone().into_boxed_str(),
            global: name == "globalRules",
            complete: provider.complete_provider,
            url_pattern: provider.url_pattern.clone().into_boxed_str(),
            exceptions: exceptions.into_iter().map(String::into_boxed_str).collect(),
        };
        ir.providers.push(provider_ir);
        let include = vec![ScopeSpec::UrlRegex(provider_pattern.into_boxed_str())];
        for (is_referral, patterns) in [
            (false, &provider.rules),
            (true, &provider.referral_marketing),
        ] {
            for pattern in patterns {
                ir.parsed_rules += 1;
                match normalize_clearurls_pattern(pattern) {
                    Ok(matchers) => {
                        for matcher in matchers {
                            ir.params.push(ParamRuleIr {
                                source: SourceKind::ClearUrls,
                                provider: Some(name.clone().into_boxed_str()),
                                global: name == "globalRules",
                                referral: is_referral,
                                exception: false,
                                exception_all: false,
                                matcher,
                                include: include.clone(),
                                exclude: Vec::new(),
                                report_index,
                            });
                            ir.accepted_rules += 1;
                        }
                    }
                    Err(error) => {
                        ir.failed_regexes += 1;
                        counters.failed(format!("{name}.rules:{pattern}: {error}"));
                    }
                }
            }
        }
        for pattern in &provider.redirections {
            ir.parsed_rules += 1;
            let compiled = format!("(?i){pattern}");
            if !regex_pattern_allowed(&compiled) || Regex::new(&compiled).is_err() {
                ir.failed_regexes += 1;
                counters.failed(format!("{name}.redirections:{pattern}"));
                continue;
            }
            ir.redirects.push(RedirectRuleIr {
                provider: Some(name.clone().into_boxed_str()),
                include: include.clone(),
                exclude: Vec::new(),
                extractor: RedirectExtractorIr::ClearUrls {
                    pattern: pattern.clone().into_boxed_str(),
                },
            });
            ir.accepted_rules += 1;
        }
        for pattern in &provider.raw_rules {
            ir.parsed_rules += 1;
            let compiled = format!("(?i){pattern}");
            if !regex_pattern_allowed(&compiled) || Regex::new(&compiled).is_err() {
                ir.failed_regexes += 1;
                counters.failed(format!("{name}.rawRules:{pattern}"));
                continue;
            }
            ir.raw_rules.push(RawRuleIr {
                provider: name.clone().into_boxed_str(),
                include: include.clone(),
                pattern: pattern.clone().into_boxed_str(),
            });
            ir.accepted_rules += 1;
        }
        if provider.complete_provider {
            // The compiled provider pass below retains the single beacon
            // action.  Count it here without adding a second IR beacon.
            ir.accepted_rules += 1;
        }
    }
    Ok(ir)
}

fn parse_brave_clean_urls(
    text: &str,
    source: String,
    _usage: Option<RulePackUsage>,
    report_index: usize,
    counters: &mut ParseCounters,
) -> Result<SourceIr> {
    let entries: Vec<BraveCleanEntry> = serde_json::from_str(text)
        .map_err(|error| CleanerError::Config(format!("Brave Clean URLs: {error}")))?;
    let mut ir = SourceIr {
        format: RulePackFormat::BraveCleanUrls,
        source,
        ..SourceIr::default()
    };
    for entry in entries {
        if let Some(pattern) = entry
            .include
            .iter()
            .chain(entry.exclude.iter())
            .find(|pattern| !regex_pattern_allowed(pattern))
        {
            ir.failed_regexes += 1;
            counters.failed(format!(
                "Brave Clean URLs scope exceeds byte limit: {pattern}"
            ));
            continue;
        }
        let include = entry
            .include
            .iter()
            .map(|pattern| ScopeSpec::UrlGlob(pattern.clone().into_boxed_str()))
            .collect::<Vec<_>>();
        let exclude = entry
            .exclude
            .iter()
            .map(|pattern| ScopeSpec::UrlGlob(pattern.clone().into_boxed_str()))
            .collect::<Vec<_>>();
        for parameter in entry.params {
            ir.parsed_rules += 1;
            if parameter.is_empty() {
                ir.unsupported_rules += 1;
                counters.unsupported("Brave Clean URLs empty parameter");
                continue;
            }
            ir.params.push(ParamRuleIr {
                source: SourceKind::BraveCleanUrls,
                provider: None,
                global: false,
                referral: false,
                exception: false,
                exception_all: false,
                matcher: ParamMatcherSpec::Exact {
                    value: parameter.into_boxed_str(),
                    subject: ParamSubject::RawName,
                    case_sensitive: true,
                    requires_equals: true,
                },
                include: include.clone(),
                exclude: exclude.clone(),
                report_index,
            });
            ir.accepted_rules += 1;
        }
    }
    Ok(ir)
}

fn parse_brave_debounce(
    text: &str,
    source: String,
    _usage: Option<RulePackUsage>,
    _report_index: usize,
    counters: &mut ParseCounters,
) -> Result<SourceIr> {
    let entries: Vec<BraveDebounceEntry> = serde_json::from_str(text)
        .map_err(|error| CleanerError::Config(format!("Brave Debounce: {error}")))?;
    let mut ir = SourceIr {
        format: RulePackFormat::BraveDebounce,
        source,
        ..SourceIr::default()
    };
    for entry in entries {
        ir.parsed_rules += 1;
        if let Some(pref) = entry.pref {
            ir.unsupported_rules += 1;
            counters.unsupported(format!("Brave Debounce pref: {pref}"));
            continue;
        }
        if let Some(pattern) = entry
            .include
            .iter()
            .chain(entry.exclude.iter())
            .find(|pattern| !regex_pattern_allowed(pattern))
        {
            ir.failed_regexes += 1;
            counters.failed(format!(
                "Brave Debounce scope exceeds byte limit: {pattern}"
            ));
            continue;
        }
        if matches!(entry.action.as_str(), "regex-path" | "regex-path-template")
            && entry
                .param
                .as_deref()
                .is_some_and(|pattern| !regex_pattern_allowed(pattern))
        {
            ir.failed_regexes += 1;
            counters.failed("Brave Debounce path exceeds byte limit");
            continue;
        }
        let include = entry
            .include
            .iter()
            .map(|pattern| ScopeSpec::UrlGlob(pattern.clone().into_boxed_str()))
            .collect::<Vec<_>>();
        let exclude = entry
            .exclude
            .iter()
            .map(|pattern| ScopeSpec::UrlGlob(pattern.clone().into_boxed_str()))
            .collect::<Vec<_>>();
        let prepend_scheme = match entry.prepend_scheme {
            Some(scheme) if scheme == "http" || scheme == "https" => Some(scheme.into_boxed_str()),
            Some(other) => {
                ir.unsupported_rules += 1;
                counters.unsupported(format!("Brave Debounce invalid scheme: {other}"));
                continue;
            }
            None => None,
        };
        let Some(action) = parse_debounce_action(
            &entry.action,
            entry.param,
            entry.redirect_url_template,
            prepend_scheme,
        ) else {
            ir.unsupported_rules += 1;
            counters.unsupported(format!("Brave Debounce action: {}", entry.action));
            continue;
        };
        if let RedirectExtractorIr::PathRegex { pattern, .. } = &action {
            if !regex_pattern_allowed(pattern) {
                ir.failed_regexes += 1;
                counters.failed(format!("Brave Debounce path exceeds byte limit: {pattern}"));
                continue;
            }
        }
        if let RedirectExtractorIr::PathRegex {
            pattern,
            assembly: CaptureAssembly::Template(template),
            ..
        } = &action
        {
            let Ok(regex) = checked_regex(pattern) else {
                ir.failed_regexes += 1;
                counters.failed(pattern.to_string());
                continue;
            };
            if !template_placeholders_match(template, regex.captures_len().saturating_sub(1)) {
                ir.unsupported_rules += 1;
                counters.unsupported("Brave Debounce template capture mismatch");
                continue;
            }
        }
        ir.redirects.push(RedirectRuleIr {
            provider: None,
            include,
            exclude,
            extractor: action,
        });
        ir.accepted_rules += 1;
    }
    Ok(ir)
}

fn parse_debounce_action(
    action: &str,
    param: Option<String>,
    template: Option<String>,
    prepend_scheme: Option<Box<str>>,
) -> Option<RedirectExtractorIr> {
    match action {
        "redirect" | "base64,redirect" => Some(RedirectExtractorIr::QueryParam {
            names: Box::new([param?.into_boxed_str()]),
            decode: if action == "redirect" {
                DecodeMode::Direct
            } else {
                DecodeMode::Base64Url
            },
            prepend_scheme,
        }),
        "regex-path" => {
            let pattern = param?;
            let regex = checked_regex(&pattern).ok()?;
            (regex.captures_len() > 1).then_some(RedirectExtractorIr::PathRegex {
                pattern: pattern.into_boxed_str(),
                assembly: CaptureAssembly::Concatenate,
                prepend_scheme,
            })
        }
        "regex-path-template" => {
            let pattern = param?;
            let template = template?;
            let regex = checked_regex(&pattern).ok()?;
            (regex.captures_len() > 1).then_some(RedirectExtractorIr::PathRegex {
                pattern: pattern.into_boxed_str(),
                assembly: CaptureAssembly::Template(template.into_boxed_str()),
                prepend_scheme,
            })
        }
        _ => None,
    }
}

fn template_placeholders_match(template: &str, captures: usize) -> bool {
    if captures == 0 || captures > 9 {
        return false;
    }

    // Brave templates use only the literal `$1` through `$9` forms.  Treat
    // every other `$` as syntax, rather than searching for valid-looking
    // substrings: otherwise `$10` would be accepted as `$1` followed by a
    // literal `0`, and malformed templates could enter the redirect index.
    let bytes = template.as_bytes();
    let mut used = [false; 10];
    let mut offset = 0;
    while offset < bytes.len() {
        if bytes[offset] != b'$' {
            offset += 1;
            continue;
        }

        let Some(&digit) = bytes.get(offset + 1) else {
            return false;
        };
        if !(b'1'..=b'9').contains(&digit) {
            return false;
        }
        if bytes
            .get(offset + 2)
            .is_some_and(|next| next.is_ascii_digit())
        {
            return false;
        }

        let capture = usize::from(digit - b'0');
        if capture > captures || used[capture] {
            return false;
        }
        used[capture] = true;
        offset += 2;
    }

    (1..=captures).all(|index| used[index])
}

fn parse_adguard(
    text: &str,
    source: String,
    usage: Option<RulePackUsage>,
    report_index: usize,
    counters: &mut ParseCounters,
) -> Result<SourceIr> {
    let mut ir = SourceIr {
        format: RulePackFormat::AdGuard,
        source,
        ..SourceIr::default()
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('!') || line.starts_with('#') {
            continue;
        }
        ir.parsed_rules += 1;
        let inverted = line.starts_with("@@");
        let body = line.strip_prefix("@@").unwrap_or(line);
        let (target, modifiers) = body.split_once('$').unwrap_or((body, ""));
        let mut removeparam: Option<Option<String>> = None;
        let mut image = false;
        let mut match_case = false;
        let mut domains = Vec::<Box<str>>::new();
        let mut unsupported = None;
        for modifier in modifiers.split(',').filter(|modifier| !modifier.is_empty()) {
            if modifier == "image" {
                image = true;
            } else if modifier == "match-case" {
                match_case = true;
            } else if modifier == "removeparam" {
                removeparam = Some(None);
            } else if let Some(value) = modifier.strip_prefix("removeparam=") {
                removeparam = Some(Some(value.to_string()));
            } else if let Some(value) = modifier.strip_prefix("domain=") {
                for domain in value.split('|') {
                    if domain.is_empty() || domain.starts_with('~') || domain.contains('*') {
                        unsupported = Some("unsupported domain scope");
                        break;
                    }
                    domains.push(domain.to_ascii_lowercase().into_boxed_str());
                }
            } else {
                unsupported = Some("unknown or browser-context modifier");
            }
            if unsupported.is_some() {
                break;
            }
        }
        if let Some(reason) = unsupported {
            ir.unsupported_rules += 1;
            counters.unsupported(format!("{reason}: {line}"));
            continue;
        }
        if image && removeparam.is_some() {
            // The runtime has separate APIs for parameter removal and image
            // beacon matching.  Applying this mixed rule as a parameter rule
            // would incorrectly clean ordinary anchors, while treating it as
            // a beacon would lose its removeparam action.  Skip it until a
            // context-aware action model can preserve both constraints.
            ir.unsupported_rules += 1;
            counters.unsupported(format!(
                "mixed removeparam/image action is unsupported: {line}"
            ));
            continue;
        }
        if !target.is_empty() && !regex_pattern_allowed(target) {
            ir.failed_regexes += 1;
            counters.failed(format!("AdGuard target exceeds byte limit: {line}"));
            continue;
        }
        let scope = if target.is_empty() && domains.is_empty() {
            ScopeSpec::Any
        } else {
            ScopeSpec::AdGuardTarget {
                pattern: target.to_string().into_boxed_str(),
                domains: domains.clone().into_boxed_slice(),
                match_case,
            }
        };
        if inverted && removeparam.is_none() && (image || usage == Some(RulePackUsage::MailBeacon))
        {
            ir.unsupported_rules += 1;
            counters.unsupported(format!("inverted image/beacon rule: {line}"));
            continue;
        }
        match removeparam {
            Some(Some(value)) if value.starts_with('~') => {
                ir.unsupported_rules += 1;
                counters.unsupported(format!("inverted removeparam: {line}"));
            }
            Some(Some(value)) if value.starts_with('/') && value.ends_with('/') => {
                let pattern = &value[1..value.len() - 1];
                // AdGuard removeparam regexes retain the expression's own
                // case behavior. `$match-case` controls target matching; it
                // must not silently make a value regex broader.
                let pattern = format!("^(?:{pattern})$");
                if pattern.len() > MAX_REGEX_PATTERN_BYTES || Regex::new(&pattern).is_err() {
                    ir.failed_regexes += 1;
                    counters.failed(format!("AdGuard removeparam regex: {line}"));
                    continue;
                }
                ir.params.push(ParamRuleIr {
                    source: SourceKind::AdGuard,
                    provider: None,
                    global: true,
                    referral: false,
                    exception: inverted,
                    exception_all: false,
                    matcher: ParamMatcherSpec::Regex {
                        pattern: pattern.into_boxed_str(),
                        subject: ParamSubject::DecodedPair,
                        case_sensitive: true,
                        requires_equals: true,
                    },
                    include: vec![scope],
                    exclude: Vec::new(),
                    report_index,
                });
                ir.accepted_rules += 1;
            }
            Some(Some(value)) if !value.is_empty() => {
                ir.params.push(ParamRuleIr {
                    source: SourceKind::AdGuard,
                    provider: None,
                    global: true,
                    referral: false,
                    exception: inverted,
                    exception_all: false,
                    matcher: ParamMatcherSpec::Exact {
                        value: if match_case {
                            value.into_boxed_str()
                        } else {
                            value.to_ascii_lowercase().into_boxed_str()
                        },
                        subject: ParamSubject::DecodedName,
                        case_sensitive: match_case,
                        requires_equals: false,
                    },
                    include: vec![scope],
                    exclude: Vec::new(),
                    report_index,
                });
                ir.accepted_rules += 1;
            }
            Some(Some(_)) => {
                ir.unsupported_rules += 1;
                counters.unsupported(format!("empty removeparam: {line}"));
            }
            Some(None) if inverted => {
                ir.params.push(ParamRuleIr {
                    source: SourceKind::AdGuard,
                    provider: None,
                    global: true,
                    referral: false,
                    exception: true,
                    exception_all: true,
                    matcher: ParamMatcherSpec::Exact {
                        value: "".into(),
                        subject: ParamSubject::RawName,
                        case_sensitive: true,
                        requires_equals: false,
                    },
                    include: vec![scope],
                    exclude: Vec::new(),
                    report_index,
                });
                ir.accepted_rules += 1;
            }
            Some(None) => {
                ir.unsupported_rules += 1;
                counters.unsupported(format!("naked removeparam: {line}"));
            }
            None if image || usage == Some(RulePackUsage::MailBeacon) => {
                ir.beacons.push(BeaconRuleIr {
                    include: vec![scope],
                    exclude: Vec::new(),
                    raw_pattern: Some(target.to_string().into_boxed_str()),
                });
                ir.accepted_rules += 1;
            }
            None => {
                ir.unsupported_rules += 1;
                counters.unsupported(format!("modifierless AdGuard blocking rule: {line}"));
            }
        }
    }
    Ok(ir)
}

fn normalize_clearurls_pattern(
    pattern: &str,
) -> std::result::Result<Vec<ParamMatcherSpec>, String> {
    let compiled = format!("(?i)^(?:{pattern})$");
    if pattern.len() > MAX_REGEX_PATTERN_BYTES {
        return Err("pattern exceeds hard byte limit".into());
    }
    if Regex::new(&compiled).is_err() {
        return Err("unsupported or invalid regex".into());
    }
    let hir = regex_syntax::parse(pattern).ok();
    if let Some(hir) = hir {
        if let Some(prefix) = literal_prefix(&hir) {
            if !prefix.is_empty() {
                return Ok(vec![ParamMatcherSpec::Prefix {
                    value: prefix.to_ascii_lowercase().into_boxed_str(),
                    subject: ParamSubject::DecodedName,
                    case_sensitive: false,
                    requires_equals: false,
                }]);
            }
        }
        if let Some(values) = expand_hir(&hir, MAX_LITERAL_EXPANSION) {
            if !values.is_empty()
                && values.iter().all(|value| value.is_ascii())
                && values.len() <= MAX_LITERAL_EXPANSION
            {
                return Ok(values
                    .into_iter()
                    .map(|value| ParamMatcherSpec::Exact {
                        value: value.to_ascii_lowercase().into_boxed_str(),
                        subject: ParamSubject::DecodedName,
                        case_sensitive: false,
                        requires_equals: false,
                    })
                    .collect());
            }
        }
    }
    Ok(vec![ParamMatcherSpec::Regex {
        pattern: compiled.into_boxed_str(),
        subject: ParamSubject::DecodedName,
        case_sensitive: false,
        requires_equals: false,
    }])
}

fn literal_prefix(hir: &Hir) -> Option<String> {
    let mut parts = Vec::<&Hir>::new();
    flatten_concat(hir, &mut parts);
    if parts.len() < 2 {
        return None;
    }
    let last = parts.pop()?;
    let HirKind::Repetition(repetition) = last.kind() else {
        return None;
    };
    if repetition.min != 0 || repetition.max.is_some() || !is_any_character(&repetition.sub) {
        return None;
    }
    let mut prefix = String::new();
    for part in parts {
        match part.kind() {
            HirKind::Literal(literal) => prefix.push_str(std::str::from_utf8(&literal.0).ok()?),
            HirKind::Look(_) => {}
            _ => return None,
        }
    }
    Some(prefix)
}

fn flatten_concat<'a>(hir: &'a Hir, output: &mut Vec<&'a Hir>) {
    match hir.kind() {
        HirKind::Concat(parts) => {
            for part in parts {
                flatten_concat(part, output);
            }
        }
        _ => output.push(hir),
    }
}

fn is_any_character(hir: &Hir) -> bool {
    let HirKind::Class(class) = hir.kind() else {
        return false;
    };
    match class {
        Class::Unicode(class) => {
            let contains = |character: char| {
                class
                    .ranges()
                    .iter()
                    .any(|range| range.start() <= character && character <= range.end())
            };
            contains('\0') && contains('A') && contains('z') && contains('/')
        }
        Class::Bytes(class) => {
            let contains = |byte: u8| {
                class
                    .ranges()
                    .iter()
                    .any(|range| range.start() <= byte && byte <= range.end())
            };
            contains(0) && contains(b'A') && contains(b'z') && contains(b'/')
        }
    }
}

fn expand_hir(hir: &Hir, cap: usize) -> Option<Vec<String>> {
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => Some(vec![String::new()]),
        HirKind::Literal(literal) => Some(vec![String::from_utf8(literal.0.to_vec()).ok()?]),
        HirKind::Capture(capture) => expand_hir(&capture.sub, cap),
        HirKind::Concat(parts) => {
            let mut values = vec![String::new()];
            for part in parts {
                let alternatives = expand_hir(part, cap)?;
                let mut next = Vec::new();
                for left in &values {
                    for right in &alternatives {
                        if next.len() >= cap {
                            return None;
                        }
                        next.push(format!("{left}{right}"));
                    }
                }
                values = next;
            }
            Some(values)
        }
        HirKind::Alternation(parts) => {
            let mut values = Vec::new();
            for part in parts {
                for value in expand_hir(part, cap)? {
                    if !values.contains(&value) {
                        if values.len() >= cap {
                            return None;
                        }
                        values.push(value);
                    }
                }
            }
            Some(values)
        }
        HirKind::Repetition(repetition) => {
            let max = repetition.max?;
            if max != repetition.min || max > 8 {
                return None;
            }
            let values = expand_hir(&repetition.sub, cap)?;
            let mut out = vec![String::new()];
            for _ in 0..max {
                let mut next = Vec::new();
                for left in &out {
                    for right in &values {
                        if next.len() >= cap {
                            return None;
                        }
                        next.push(format!("{left}{right}"));
                    }
                }
                out = next;
            }
            Some(out)
        }
        HirKind::Class(class) => class
            .literal()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .map(|value| vec![value]),
    }
}

fn count_regex_rules(source: &SourceIr) -> usize {
    let mut expressions = HashSet::<String>::new();

    for provider in &source.providers {
        add_regex_budget_expression(
            &mut expressions,
            "url-pattern",
            &format_regex_for_scope(provider.url_pattern.as_ref()),
        );
        for exception in &provider.exceptions {
            add_regex_budget_expression(
                &mut expressions,
                "url-exception",
                &format_regex_for_scope(exception),
            );
        }
    }
    for rule in &source.params {
        if matches!(rule.matcher, ParamMatcherSpec::Regex { .. }) {
            if let ParamMatcherSpec::Regex {
                pattern,
                subject,
                case_sensitive,
                requires_equals,
            } = &rule.matcher
            {
                add_regex_budget_expression(
                    &mut expressions,
                    "parameter",
                    &format!("{subject:?}:{case_sensitive}:{requires_equals}:{pattern}"),
                );
            }
        }
        for scope in rule.include.iter().chain(rule.exclude.iter()) {
            add_regex_budget_scope(&mut expressions, scope);
        }
    }
    for rule in &source.redirects {
        for scope in rule.include.iter().chain(rule.exclude.iter()) {
            add_regex_budget_scope(&mut expressions, scope);
        }
        if matches!(
            rule.extractor,
            RedirectExtractorIr::ClearUrls { .. } | RedirectExtractorIr::PathRegex { .. }
        ) {
            match &rule.extractor {
                RedirectExtractorIr::ClearUrls { pattern }
                | RedirectExtractorIr::PathRegex { pattern, .. } => {
                    add_regex_budget_expression(&mut expressions, "redirect", pattern);
                }
                RedirectExtractorIr::QueryParam { .. } => unreachable!(),
            }
        }
    }
    for rule in &source.beacons {
        for scope in rule.include.iter().chain(rule.exclude.iter()) {
            add_regex_budget_scope(&mut expressions, scope);
        }
        if rule.raw_pattern.is_some() {
            add_regex_budget_expression(
                &mut expressions,
                "beacon",
                rule.raw_pattern.as_deref().unwrap_or_default(),
            );
        }
    }
    for rule in &source.raw_rules {
        for scope in &rule.include {
            add_regex_budget_scope(&mut expressions, scope);
        }
        add_regex_budget_expression(&mut expressions, "raw", &rule.pattern);
    }
    expressions.len()
}

fn add_regex_budget_scope(expressions: &mut HashSet<String>, scope: &ScopeSpec) {
    if !matches!(scope, ScopeSpec::Any) {
        expressions.insert(format!("scope:{scope:?}"));
    }
}

fn add_regex_budget_expression(expressions: &mut HashSet<String>, kind: &str, pattern: &str) {
    expressions.insert(format!("{kind}:{pattern}"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_compiles_with_no_skipped_patterns() {
        let rs = Ruleset::builtin();
        assert!(rs.provider_count() >= 20);
        assert_eq!(rs.skipped_patterns, 0);
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
        assert!(rs.param_is_tracking("https://www.amazon.com/dp/x", "pf_rd_r", true, false));
        assert!(!rs.param_is_tracking("https://shop.example.com/x", "pf_rd_r", true, false));
        assert!(!rs.param_is_tracking("https://www.amazon.com/dp/x", "pf_rd_r", false, false));
    }

    #[test]
    fn detects_providers_and_redirect_targets() {
        let rs = Ruleset::builtin();
        assert_eq!(
            rs.detect_provider("https://news.us1.list-manage.com/track/click?u=1"),
            Some("mailchimp")
        );
        assert_eq!(
            rs.redirect_target(
                "https://u1.ct.sendgrid.net/ls/click?upn=a&url=https%3A%2F%2Fx.example"
            ),
            Some("https%3A%2F%2Fx.example".into())
        );
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
        assert!(rs.param_is_tracking("https://shop.acme.example/x", "sid", true, false));
        assert!(rs.param_is_tracking("https://shop.acme.example/x", "trk_abc", true, false));
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

    #[test]
    fn finite_alternatives_are_not_regex_actions() {
        let rs = Ruleset::from_clearurls_str(
            r#"{"providers":{"globalRules":{"urlPattern":"^https?://","rules":["ga_(source|medium|campaign)"]}}}"#,
        )
        .unwrap();
        assert_eq!(rs.stats().regex_param_rules, 0);
        assert_eq!(rs.stats().exact_param_rules, 3);
    }
}

//! Normalized rule loading and immutable runtime matching.
//!
//! The cleaner accepts several deliberately different rule languages.  They
//! are parsed into a small source IR first and only then compiled into one
//! immutable [`RuleStore`].  Keeping the source semantics in the IR is
//! important: ClearURLs, Brave Clean URLs, and AdGuard do not agree on query
//! decoding, case sensitivity, or exception scope.

use std::borrow::Cow;
use std::cell::OnceCell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine;
use percent_encoding::percent_decode_str;
use regex::{Regex, RegexSet, SetMatches};
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
const GOOGLE_SEARCH_REDIRECT_PATTERN: &str =
    r"^https?://(?:[a-z0-9-]+\.)*?google(?:\.[a-z]{2,}){1,}/url\?.*?(?:url|q)=(https?[^&]+)";

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
    #[serde(alias = "adguard")]
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
    url_pattern: ProviderMatcher,
    exceptions: Box<[IndexedRegex]>,
    scope: ScopeId,
}

#[derive(Debug, Clone)]
enum ProviderMatcher {
    Direct {
        literals: Box<[Box<str>]>,
        subdomains: bool,
        match_index: usize,
    },
    Regex(IndexedRegex),
}

impl ProviderMatcher {
    fn matched(&self, matches: &ProviderMatches) -> bool {
        match self {
            Self::Direct { match_index, .. } => matches.direct[*match_index],
            Self::Regex(regex) => regex.matched(&matches.regex),
        }
    }
}

struct ProviderMatches {
    regex: Vec<SetMatches>,
    direct: Vec<bool>,
}

#[derive(Debug, Default)]
struct DirectProviderIndex {
    anchored: DirectProviderTrie,
    subdomains: DirectProviderTrie,
}

#[derive(Debug, Default)]
struct DirectProviderTrie {
    nodes: Box<[DirectProviderTrieNode]>,
    edges: Box<[DirectProviderTrieEdge]>,
    matches: Box<[u32]>,
}

#[derive(Debug, Clone, Copy)]
struct DirectProviderTrieNode {
    edge_start: u32,
    edge_len: u32,
    match_start: u32,
    match_len: u32,
}

#[derive(Debug, Clone, Copy)]
struct DirectProviderTrieEdge {
    byte: u8,
    next: u32,
}

#[derive(Debug, Clone, Copy)]
struct IndexedRegex {
    chunk: usize,
    index: usize,
}

impl IndexedRegex {
    fn matched(self, matches: &[SetMatches]) -> bool {
        matches
            .get(self.chunk)
            .is_some_and(|matches| matches.matched(self.index))
    }
}

#[derive(Debug, Clone)]
enum CompiledScope {
    Any,
    UrlRegex(Regex),
    ProviderPattern(ProviderMatcher),
    UrlGlob {
        pattern: Box<str>,
        host_suffix: Option<Box<str>>,
    },
    AdGuardTarget {
        pattern: Box<str>,
        match_case: bool,
        domains: Box<[Box<str>]>,
        host_suffix: Option<Box<str>>,
    },
}

impl CompiledScope {
    fn matches(&self, raw_url: &str, parsed: &Url, provider_matches: &ProviderMatches) -> bool {
        match self {
            Self::Any => true,
            Self::UrlRegex(re) => re.is_match(raw_url),
            Self::ProviderPattern(pattern) => pattern.matched(provider_matches),
            Self::UrlGlob { pattern, .. } => glob_matches(pattern, raw_url),
            Self::AdGuardTarget {
                pattern,
                match_case,
                domains,
                ..
            } => {
                adguard_target_matches(pattern, raw_url, *match_case)
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
            Self::Any | Self::UrlRegex(_) | Self::ProviderPattern(_) => {}
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
    fn matches(&self, segment: &QuerySegment<'_>, chunks: &[RegexSetChunk]) -> bool {
        if self.requires_equals && !segment.has_equals {
            return false;
        }
        let subject = segment.subject(self.subject);

        match &self.kind {
            CompiledMatcherKind::Exact(value) => {
                if self.case_sensitive {
                    subject == value.as_ref()
                } else {
                    subject.eq_ignore_ascii_case(value)
                }
            }
            CompiledMatcherKind::Prefix(value) => {
                subject.get(..value.len()).is_some_and(|prefix| {
                    if self.case_sensitive {
                        prefix == value.as_ref()
                    } else {
                        prefix.eq_ignore_ascii_case(value)
                    }
                })
            }
            CompiledMatcherKind::Regex { chunk, index } => chunks
                .get(*chunk)
                .is_some_and(|_| segment.regex_matched(self.subject, chunks, *chunk, *index)),
        }
    }
}

struct QuerySegment<'a> {
    raw_name: &'a str,
    raw_value: &'a str,
    has_equals: bool,
    decoded_name: OnceCell<Cow<'a, str>>,
    decoded_pair: OnceCell<String>,
    raw_regex_matches: OnceCell<Vec<OnceCell<Box<[usize]>>>>,
    decoded_name_regex_matches: OnceCell<Vec<OnceCell<Box<[usize]>>>>,
    decoded_pair_regex_matches: OnceCell<Vec<OnceCell<Box<[usize]>>>>,
}

impl<'a> QuerySegment<'a> {
    fn new(segment: &'a str) -> Self {
        let (raw_name, has_equals, raw_value) = split_query_segment(segment);
        Self {
            raw_name,
            raw_value,
            has_equals,
            decoded_name: OnceCell::new(),
            decoded_pair: OnceCell::new(),
            raw_regex_matches: OnceCell::new(),
            decoded_name_regex_matches: OnceCell::new(),
            decoded_pair_regex_matches: OnceCell::new(),
        }
    }

    fn decoded_name(&self) -> &str {
        self.decoded_name
            .get_or_init(|| decode_query_component(self.raw_name))
    }

    fn subject(&self, subject: ParamSubject) -> &str {
        match subject {
            ParamSubject::RawName => self.raw_name,
            ParamSubject::DecodedName => self.decoded_name(),
            ParamSubject::DecodedPair => self.decoded_pair.get_or_init(|| {
                let name = self.decoded_name();
                let value = decode_query_component(self.raw_value);
                let mut pair = String::with_capacity(name.len() + 1 + value.len());
                pair.push_str(name);
                pair.push('=');
                pair.push_str(&value);
                pair
            }),
        }
    }

    fn regex_matched(
        &self,
        subject: ParamSubject,
        chunks: &[RegexSetChunk],
        chunk: usize,
        index: usize,
    ) -> bool {
        let value = self.subject(subject);
        let cache = match subject {
            ParamSubject::RawName => &self.raw_regex_matches,
            ParamSubject::DecodedName => &self.decoded_name_regex_matches,
            ParamSubject::DecodedPair => &self.decoded_pair_regex_matches,
        }
        .get_or_init(|| (0..chunks.len()).map(|_| OnceCell::new()).collect());
        let Some(chunk_cache) = cache.get(chunk) else {
            return false;
        };
        let matched = chunk_cache.get_or_init(|| {
            chunks[chunk]
                .set
                .matches(value)
                .iter()
                .collect::<Vec<_>>()
                .into_boxed_slice()
        });
        matched.binary_search(&index).is_ok()
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
    ClearUrlsGoogle {
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

#[derive(Debug, Default)]
struct RedirectIndex {
    global: Box<[usize]>,
    suffix: HashMap<Box<str>, Box<[usize]>>,
    provider: HashMap<usize, Box<[usize]>>,
    provider_regex: Box<[(IndexedRegex, Box<[usize]>)]>,
    generic: Box<[usize]>,
}

#[derive(Debug)]
struct RuleStore {
    providers: Box<[Provider]>,
    provider_patterns: Box<[RegexSetChunk]>,
    provider_exceptions: Box<[RegexSetChunk]>,
    direct_provider_index: DirectProviderIndex,
    scopes: Box<[CompiledScope]>,
    groups: Box<[RuleGroup]>,
    actions: Box<[ParamAction]>,
    regex_chunks: Box<[RegexSetChunk]>,
    scope_index: ScopeIndex,
    redirect_index: RedirectIndex,
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
        let provider_matches = match_provider_patterns(&self.store, raw_url);
        let mut candidates = Vec::with_capacity(
            self.store.scope_index.global.len() + self.store.scope_index.generic.len() + 8,
        );
        candidates.extend(self.store.scope_index.global.iter().copied());
        candidates.extend(self.store.scope_index.generic.iter().copied());

        if let Some(host) = parsed_url.host_str() {
            let mut suffix = host;
            loop {
                if let Some(groups) = self.store.scope_index.suffix.get(suffix) {
                    candidates.extend(groups.iter().copied());
                }
                let Some(dot) = suffix.find('.') else {
                    break;
                };
                suffix = &suffix[dot + 1..];
            }
        }

        candidates.sort_unstable();
        candidates.dedup();

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
                    &provider_matches,
                )
            })
            .collect();

        let mut active = active;
        active.sort_by_key(|group_id| self.store.groups[*group_id].order);

        let exception_matches = match_regex_chunks(&self.store.provider_exceptions, raw_url);
        let clearurls_exceptions = self
            .store
            .providers
            .iter()
            .enumerate()
            .filter(|(_, provider)| {
                provider.url_pattern.matched(&provider_matches)
                    && provider
                        .exceptions
                        .iter()
                        .any(|exception| exception.matched(&exception_matches))
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
        let matches = match_provider_patterns(&self.store, url);
        self.store
            .providers
            .iter()
            .find(|provider| !provider.global && provider.url_pattern.matched(&matches))
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
        let provider_matches = match_provider_patterns(&self.store, url);
        let mut candidates = Vec::new();
        candidates.extend(self.store.redirect_index.global.iter().copied());
        candidates.extend(self.store.redirect_index.generic.iter().copied());
        for (provider_id, matched) in provider_matches.direct.iter().copied().enumerate() {
            if matched {
                if let Some(redirects) = self.store.redirect_index.provider.get(&provider_id) {
                    candidates.extend(redirects.iter().copied());
                }
            }
        }
        for (pattern, redirects) in self.store.redirect_index.provider_regex.iter() {
            if pattern.matched(&provider_matches.regex) {
                candidates.extend(redirects.iter().copied());
            }
        }
        if let Some(host) = parsed.host_str() {
            let mut suffix = host.trim_end_matches('.');
            loop {
                if let Some(redirects) = self.store.redirect_index.suffix.get(suffix) {
                    candidates.extend(redirects.iter().copied());
                }
                let Some(dot) = suffix.find('.') else {
                    break;
                };
                suffix = &suffix[dot + 1..];
            }
        }
        candidates.sort_unstable();
        candidates.dedup();

        for rule_id in candidates {
            let rule = &self.store.redirects[rule_id];
            if !scopes_match(
                &self.store.scopes,
                &rule.include,
                &rule.exclude,
                url,
                &parsed,
                &provider_matches,
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
        let provider_matches = match_provider_patterns(&self.store, url);
        let mut current = url.to_string();
        let mut changed = false;
        for rule in self.store.raw_rules.iter() {
            let Some(parsed) = parsed.as_ref() else {
                break;
            };
            if !scopes_match(
                &self.store.scopes,
                &rule.include,
                &[],
                url,
                parsed,
                &provider_matches,
            ) {
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
        let matches = match_provider_patterns(&self.store, url);
        if self
            .store
            .providers
            .iter()
            .any(|provider| provider.complete && provider.url_pattern.matched(&matches))
        {
            return true;
        }
        self.is_beacon_url(url, None)
    }

    /// Match external/complete-provider beacon rules against the raw source
    /// URL and, when available, its parsed host.
    pub fn is_beacon_url(&self, url: &str, host: Option<&str>) -> bool {
        let parsed = Url::parse(url).ok();
        let provider_matches = match_provider_patterns(&self.store, url);
        if let Some(parsed) = parsed.as_ref() {
            if self.store.beacons.iter().any(|rule| {
                scopes_match(
                    &self.store.scopes,
                    &rule.include,
                    &rule.exclude,
                    url,
                    parsed,
                    &provider_matches,
                )
            }) {
                return true;
            }
            // A parsed URL that did not satisfy any target scope is an
            // ordinary direct URL, not an encoded proxy payload. Do not let a
            // broad raw fallback (for example `*`) make it a global beacon.
            if !contains_embedded_url(url) {
                return false;
            }
        }

        if scopes_match_embedded_beacon(&self.store, url) {
            return true;
        }

        // Preserve the host-only fallback for callers with a malformed raw
        // URL without compiling a second copy of every beacon expression.
        host.and_then(|host| Url::parse(&format!("https://{host}/")).ok())
            .map(|parsed| {
                let provider_matches = match_provider_patterns(&self.store, parsed.as_str());
                self.store.beacons.iter().any(|rule| {
                    scopes_match(
                        &self.store.scopes,
                        &rule.include,
                        &rule.exclude,
                        parsed.as_str(),
                        &parsed,
                        &provider_matches,
                    )
                })
            })
            .unwrap_or(false)
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
        let segment = QuerySegment::new(segment);
        for group_id in self.candidate_groups.iter().copied() {
            let action = &self.store.actions[self.store.groups[group_id].action];
            if action.exception || !action_enabled(action, self, include_vendor, include_referral) {
                continue;
            }
            if !action.matcher.matches(&segment, &self.store.regex_chunks) {
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
                    &segment,
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
        segment: &QuerySegment<'_>,
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

    let mut pending_providers = Vec::new();
    let mut provider_patterns = Vec::new();
    let mut provider_exception_patterns = Vec::new();
    for source in sources {
        for provider in &source.providers {
            if provider_disabled(disabled, &provider.name) {
                continue;
            }
            let direct = compile_provider_direct_pattern(&provider.url_pattern);
            let pattern_index = if direct.is_none() {
                let index = provider_patterns.len();
                provider_patterns.push(format!("(?i){}", provider.url_pattern));
                Some(index)
            } else {
                None
            };
            let exception_start = provider_exception_patterns.len();
            provider_exception_patterns.extend(
                provider
                    .exceptions
                    .iter()
                    .map(|pattern| format!("(?i){pattern}")),
            );
            let exception_end = provider_exception_patterns.len();
            pending_providers.push((
                source,
                provider,
                direct,
                pattern_index,
                exception_start..exception_end,
            ));
        }
    }
    let (provider_pattern_chunks, provider_pattern_refs, failed_provider_patterns) =
        compile_indexed_regexes(provider_patterns);
    skipped += failed_provider_patterns;
    let (provider_exception_chunks, provider_exception_refs, _) =
        compile_indexed_regexes(provider_exception_patterns);

    let mut providers = Vec::<Provider>::with_capacity(pending_providers.len());
    let mut provider_ids = HashMap::<(&str, &str), usize>::new();
    for (source, provider, direct, pattern_index, exception_range) in pending_providers {
        let mut url_pattern = if let Some(direct) = direct {
            direct
        } else {
            let Some(pattern_index) = pattern_index else {
                continue;
            };
            let Some(indexed) = provider_pattern_refs[pattern_index] else {
                continue;
            };
            ProviderMatcher::Regex(indexed)
        };
        let provider_id = providers.len();
        if let ProviderMatcher::Direct { match_index, .. } = &mut url_pattern {
            *match_index = provider_id;
        }
        let provider_scope =
            ScopeSpec::UrlRegex(format!("(?i){}", provider.url_pattern).into_boxed_str());
        let scope = if let Some(scope) = scope_ids.get(&provider_scope).copied() {
            scope
        } else {
            let scope = scopes.len();
            scopes.push(CompiledScope::ProviderPattern(url_pattern.clone()));
            scope_ids.insert(provider_scope, scope);
            scope
        };
        let exceptions = exception_range
            .filter_map(|index| provider_exception_refs[index])
            .collect::<Vec<_>>()
            .into_boxed_slice();
        providers.push(Provider {
            name: provider.name.to_string(),
            global: provider.global,
            complete: provider.complete,
            url_pattern,
            exceptions,
            scope,
        });
        provider_ids.insert(
            (source.source.as_str(), provider.name.as_ref()),
            provider_id,
        );
    }
    let direct_provider_index = build_direct_provider_index(&providers);
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

    let mut pending = Vec::<PendingParamAction>::new();
    let mut parameter_order = 0u32;
    let mut seen = HashMap::<ParamDedupKey, usize>::new();
    let mut duplicates = HashMap::<usize, usize>::new();
    for source in sources {
        for rule in &source.params {
            if rule
                .provider
                .as_deref()
                .map(|provider| provider_disabled(disabled, provider))
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
                    .get(&(source.source.as_str(), provider))
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
            let Some(include) = intern_scopes(&mut intern_scope, &rule.include) else {
                skipped += 1;
                continue;
            };
            let Some(exclude) = intern_scopes(&mut intern_scope, &rule.exclude) else {
                skipped += 1;
                continue;
            };
            let key = ParamDedupKey {
                global: rule.global,
                referral: rule.referral,
                exception: rule.exception,
                exception_all: rule.exception_all,
                legacy_builtin_global_carveout,
                matcher: rule.matcher.clone(),
                include: include.clone(),
                exclude: exclude.clone(),
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

    let mut pending_redirects = Vec::new();
    let mut redirect_order = 0u32;
    for source in sources {
        for rule in &source.redirects {
            if rule
                .provider
                .as_deref()
                .map(|provider| provider_disabled(disabled, provider))
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
            pending_redirects.push(PendingRedirectCompile {
                include,
                exclude,
                extractor: rule.extractor.clone(),
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
    let compiled_redirects = compile_redirect_extractors(&pending_redirects);
    let mut redirects = Vec::with_capacity(pending_redirects.len());
    for (pending, extractor) in pending_redirects.into_iter().zip(compiled_redirects) {
        let Some(extractor) = extractor else {
            skipped += 1;
            continue;
        };
        redirects.push(CompiledRedirectRule {
            include: pending.include,
            exclude: pending.exclude,
            extractor,
            origin: pending.origin,
            order: pending.order,
        });
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
            beacons.push(CompiledBeaconRule { include, exclude });
        }
    }
    for provider in providers.iter() {
        if provider.complete {
            let include = Box::new([provider.scope]);
            beacons.push(CompiledBeaconRule {
                include,
                exclude: Box::new([]),
            });
        }
    }

    let mut raw_rules = Vec::new();
    for source in sources {
        for rule in &source.raw_rules {
            if provider_disabled(disabled, &rule.provider) {
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
    let redirect_index = build_redirect_index(&scopes, &redirects);
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
            provider_patterns: provider_pattern_chunks.into_boxed_slice(),
            provider_exceptions: provider_exception_chunks.into_boxed_slice(),
            direct_provider_index,
            scopes: scopes.into_boxed_slice(),
            groups: groups.into_boxed_slice(),
            actions: actions.into_boxed_slice(),
            regex_chunks: regex_chunks.into_boxed_slice(),
            scope_index,
            redirect_index,
            redirects: redirects.into_boxed_slice(),
            beacons: beacons.into_boxed_slice(),
            raw_rules: raw_rules.into_boxed_slice(),
            stats,
        },
        skipped,
        duplicates,
    )
}

fn provider_disabled(disabled: &HashSet<String>, provider: &str) -> bool {
    !disabled.is_empty()
        && (disabled.contains(provider) || disabled.contains(&provider.to_ascii_lowercase()))
}

fn compile_provider_direct_pattern(pattern: &str) -> Option<ProviderMatcher> {
    const PREFIXES: [(&str, bool); 4] = [
        (r"^https?://(?:[a-z0-9-]+\.)*?", true),
        (r"^https?:\/\/(?:[a-z0-9-]+\.)*?", true),
        (r"^https?://", false),
        (r"^https?:\/\/", false),
    ];
    let (rest, subdomains) = PREFIXES.iter().find_map(|(prefix, subdomains)| {
        pattern.strip_prefix(prefix).map(|rest| (rest, *subdomains))
    })?;
    let literals = if let Some(literal) = unescape_provider_literal(rest) {
        vec![literal]
    } else {
        let hir = regex_syntax::parse(rest).ok()?;
        let values = expand_hir(&hir, MAX_LITERAL_EXPANSION)?;
        if values.iter().any(|literal| !literal.is_ascii()) {
            return None;
        }
        values
            .into_iter()
            .map(String::into_boxed_str)
            .collect::<Vec<_>>()
    };
    if literals.is_empty() {
        return None;
    }
    Some(ProviderMatcher::Direct {
        literals: literals.into_boxed_slice(),
        subdomains,
        match_index: usize::MAX,
    })
}

fn unescape_provider_literal(pattern: &str) -> Option<Box<str>> {
    let mut literal = String::with_capacity(pattern.len());
    let mut bytes = pattern.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'\\' {
            let escaped = bytes.next()?;
            if escaped.is_ascii_alphanumeric() {
                return None;
            }
            literal.push(escaped as char);
        } else if is_regex_meta_byte(byte) {
            return None;
        } else if byte.is_ascii() {
            literal.push(byte as char);
        } else {
            return None;
        }
    }
    Some(literal.into_boxed_str())
}

fn provider_direct_matches(literal: &str, subdomains: bool, value: &str) -> bool {
    let tail = ["https://", "http://"].into_iter().find_map(|scheme| {
        let prefix = value.get(..scheme.len())?;
        starts_with_unicode_case(prefix, scheme).then_some(&value[scheme.len()..])
    });
    let Some(tail) = tail else {
        return false;
    };
    if starts_with_unicode_case(tail, literal) {
        return true;
    }
    if !subdomains {
        return false;
    }

    let mut label_start = 0;
    for (offset, character) in tail.char_indices() {
        if character == '.' {
            if offset == label_start {
                return false;
            }
            let remainder = &tail[offset + 1..];
            if starts_with_unicode_case(remainder, literal) {
                return true;
            }
            label_start = offset + 1;
        } else if !(character.is_ascii_digit()
            || character == '-'
            || folds_to_ascii_letter(character))
        {
            return false;
        }
    }
    false
}

fn starts_with_unicode_case(value: &str, literal: &str) -> bool {
    let mut value = value.chars();
    for expected in literal.chars() {
        let Some(actual) = value.next() else {
            return false;
        };
        if !chars_eq_ignore_case(expected, actual) {
            return false;
        }
    }
    true
}

fn folds_to_ascii_letter(character: char) -> bool {
    character
        .to_lowercase()
        .all(|folded| folded.is_ascii_alphabetic())
        || character
            .to_uppercase()
            .all(|folded| folded.is_ascii_alphabetic())
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

#[derive(Debug)]
struct PendingRedirectCompile {
    include: Box<[ScopeId]>,
    exclude: Box<[ScopeId]>,
    extractor: RedirectExtractorIr,
    origin: RedirectOrigin,
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
    include: Box<[ScopeId]>,
    exclude: Box<[ScopeId]>,
}

type RegexCompileResult = (Vec<RegexSetChunk>, Vec<Option<IndexedRegex>>, usize);

fn compile_indexed_regexes(
    patterns: Vec<String>,
) -> (Vec<RegexSetChunk>, Vec<Option<IndexedRegex>>, usize) {
    let entries = patterns.into_iter().enumerate().collect::<Vec<_>>();
    let mut chunks = Vec::new();
    let mut refs = vec![None; entries.len()];
    let mut failed = 0;
    let mut batch_start = 0;
    let mut batch_bytes = 0usize;
    for (index, (_, pattern)) in entries.iter().enumerate() {
        let would_exceed = batch_start < index
            && batch_bytes.saturating_add(pattern.len()) > MAX_REGEX_CHUNK_BYTES;
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
        batch_bytes = batch_bytes.saturating_add(pattern.len());
    }
    if batch_start < entries.len() {
        compile_regex_batch(&entries[batch_start..], &mut chunks, &mut refs, &mut failed);
    }
    (chunks, refs, failed)
}

fn match_regex_chunks(chunks: &[RegexSetChunk], value: &str) -> Vec<SetMatches> {
    chunks
        .iter()
        .map(|chunk| chunk.set.matches(value))
        .collect()
}

fn match_provider_patterns(store: &RuleStore, value: &str) -> ProviderMatches {
    let regex = match_regex_chunks(&store.provider_patterns, value);
    let mut direct = vec![false; store.providers.len()];
    if value.is_ascii() {
        store.direct_provider_index.match_ascii(value, &mut direct);
    } else {
        for provider in store.providers.iter() {
            if let ProviderMatcher::Direct {
                literals,
                subdomains,
                match_index,
            } = &provider.url_pattern
            {
                direct[*match_index] = literals
                    .iter()
                    .any(|literal| provider_direct_matches(literal, *subdomains, value));
            }
        }
    }
    ProviderMatches { regex, direct }
}

fn build_direct_provider_index(providers: &[Provider]) -> DirectProviderIndex {
    let mut anchored = Vec::new();
    let mut subdomains = Vec::new();
    for provider in providers {
        let ProviderMatcher::Direct {
            literals,
            subdomains: accepts_subdomains,
            match_index,
        } = &provider.url_pattern
        else {
            continue;
        };
        for literal in literals {
            if *accepts_subdomains {
                subdomains.push((literal.as_ref(), *match_index));
            } else {
                anchored.push((literal.as_ref(), *match_index));
            }
        }
    }
    DirectProviderIndex {
        anchored: DirectProviderTrie::new(&anchored),
        subdomains: DirectProviderTrie::new(&subdomains),
    }
}

impl DirectProviderIndex {
    fn match_ascii(&self, value: &str, matches: &mut [bool]) {
        let Some(tail) = ["https://", "http://"].into_iter().find_map(|scheme| {
            let prefix = value.get(..scheme.len())?;
            prefix
                .eq_ignore_ascii_case(scheme)
                .then_some(&value[scheme.len()..])
        }) else {
            return;
        };
        self.anchored.match_at(tail, 0, matches);
        let mut label_start = 0;
        self.subdomains.match_at(tail, 0, matches);
        for (offset, byte) in tail.bytes().enumerate() {
            if byte == b'.' {
                if offset == label_start {
                    break;
                }
                let start = offset + 1;
                self.subdomains.match_at(tail, start, matches);
                label_start = start;
            } else if !(byte.is_ascii_alphanumeric() || byte == b'-') {
                break;
            }
        }
    }
}

impl DirectProviderTrie {
    fn new(patterns: &[(&str, usize)]) -> Self {
        #[derive(Default)]
        struct BuildNode {
            edges: Vec<(u8, usize)>,
            matches: Vec<usize>,
        }

        let mut nodes = vec![BuildNode::default()];
        for (pattern, provider_id) in patterns {
            let mut node = 0;
            for byte in pattern.bytes().map(|byte| byte.to_ascii_lowercase()) {
                let next = if let Some(next) = nodes[node]
                    .edges
                    .iter()
                    .find_map(|(edge, next)| (*edge == byte).then_some(*next))
                {
                    next
                } else {
                    let next = nodes.len();
                    nodes.push(BuildNode::default());
                    nodes[node].edges.push((byte, next));
                    next
                };
                node = next;
            }
            nodes[node].matches.push(*provider_id);
        }
        let mut flat_nodes = Vec::with_capacity(nodes.len());
        let mut edges = Vec::with_capacity(nodes.iter().map(|node| node.edges.len()).sum());
        let mut matches = Vec::with_capacity(nodes.iter().map(|node| node.matches.len()).sum());
        for mut node in nodes {
            node.edges.sort_unstable_by_key(|(edge, _)| *edge);
            let edge_start = u32::try_from(edges.len()).expect("provider trie edge limit");
            let edge_len = u32::try_from(node.edges.len()).expect("provider trie edge limit");
            edges.extend(
                node.edges
                    .into_iter()
                    .map(|(byte, next)| DirectProviderTrieEdge {
                        byte,
                        next: u32::try_from(next).expect("provider trie node limit"),
                    }),
            );
            let match_start = u32::try_from(matches.len()).expect("provider trie match limit");
            let match_len = u32::try_from(node.matches.len()).expect("provider trie match limit");
            matches.extend(
                node.matches
                    .into_iter()
                    .map(|index| u32::try_from(index).expect("provider index limit")),
            );
            flat_nodes.push(DirectProviderTrieNode {
                edge_start,
                edge_len,
                match_start,
                match_len,
            });
        }
        Self {
            nodes: flat_nodes.into_boxed_slice(),
            edges: edges.into_boxed_slice(),
            matches: matches.into_boxed_slice(),
        }
    }

    fn match_at(&self, value: &str, start: usize, matches: &mut [bool]) {
        let mut node = 0;
        let Some(root) = self.nodes.get(node) else {
            return;
        };
        self.mark_matches(root, matches);
        for byte in value[start..].bytes().map(|byte| byte.to_ascii_lowercase()) {
            let trie_node = self.nodes[node];
            let edge_start = trie_node.edge_start as usize;
            let edge_end = edge_start + trie_node.edge_len as usize;
            let node_edges = &self.edges[edge_start..edge_end];
            let Ok(edge) = node_edges.binary_search_by_key(&byte, |edge| edge.byte) else {
                return;
            };
            node = node_edges[edge].next as usize;
            self.mark_matches(&self.nodes[node], matches);
        }
    }

    fn mark_matches(&self, node: &DirectProviderTrieNode, matched: &mut [bool]) {
        let start = node.match_start as usize;
        let end = start + node.match_len as usize;
        for &provider_id in &self.matches[start..end] {
            matched[provider_id as usize] = true;
        }
    }
}

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
    refs: &mut [Option<IndexedRegex>],
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
                refs[*pending] = Some(IndexedRegex { chunk, index });
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
    regex_ref: Option<IndexedRegex>,
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
                chunk: regex_ref?.chunk,
                index: regex_ref?.index,
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
                if let Some(groups) = index.suffix.get_mut(host) {
                    groups.push(group_id);
                } else {
                    index
                        .suffix
                        .insert(host.to_ascii_lowercase().into_boxed_str(), vec![group_id]);
                }
                indexed = true;
            });
        }
        if !indexed {
            index.generic.push(group_id);
        }
    }
    index
}

fn build_redirect_index(
    scopes: &[CompiledScope],
    redirects: &[CompiledRedirectRule],
) -> RedirectIndex {
    let mut global = Vec::new();
    let mut suffix = HashMap::<Box<str>, Vec<usize>>::new();
    let mut provider = HashMap::<usize, Vec<usize>>::new();
    let mut provider_regex = HashMap::<(usize, usize), Vec<usize>>::new();
    let mut generic = Vec::new();
    for (redirect_id, redirect) in redirects.iter().enumerate() {
        if redirect.include.is_empty() {
            global.push(redirect_id);
            continue;
        }
        let mut indexed = false;
        let mut has_unindexed_include = false;
        for scope_id in redirect.include.iter().copied() {
            if let CompiledScope::ProviderPattern(pattern) = &scopes[scope_id] {
                match pattern {
                    ProviderMatcher::Direct { match_index, .. } => {
                        provider.entry(*match_index).or_default().push(redirect_id);
                    }
                    ProviderMatcher::Regex(pattern) => {
                        provider_regex
                            .entry((pattern.chunk, pattern.index))
                            .or_default()
                            .push(redirect_id);
                    }
                }
                indexed = true;
                continue;
            }
            let mut scope_indexed = false;
            scopes[scope_id].for_each_host_hint(|host| {
                let host = host
                    .trim_start_matches('.')
                    .trim_end_matches('.')
                    .to_ascii_lowercase();
                if host.is_empty()
                    || !host.is_ascii()
                    || !host
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
                {
                    return;
                }
                let candidates = if let Some(candidates) = suffix.get_mut(host.as_str()) {
                    candidates
                } else {
                    suffix.entry(host.into_boxed_str()).or_default()
                };
                if candidates.last().copied() != Some(redirect_id) {
                    candidates.push(redirect_id);
                }
                indexed = true;
                scope_indexed = true;
            });
            if !scope_indexed {
                has_unindexed_include = true;
            }
        }
        if !indexed || has_unindexed_include {
            generic.push(redirect_id);
        }
    }
    RedirectIndex {
        global: global.into_boxed_slice(),
        suffix: suffix
            .into_iter()
            .map(|(host, ids)| (host, ids.into_boxed_slice()))
            .collect(),
        provider: provider
            .into_iter()
            .map(|(provider, ids)| (provider, ids.into_boxed_slice()))
            .collect(),
        provider_regex: provider_regex
            .into_iter()
            .map(|((chunk, index), ids)| (IndexedRegex { chunk, index }, ids.into_boxed_slice()))
            .collect(),
        generic: generic.into_boxed_slice(),
    }
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
    provider_matches: &ProviderMatches,
) -> bool {
    let included = include.is_empty()
        || include
            .iter()
            .any(|id| scopes[*id].matches(raw_url, parsed, provider_matches));
    included
        && !exclude
            .iter()
            .any(|id| scopes[*id].matches(raw_url, parsed, provider_matches))
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
            Ok(CompiledScope::UrlGlob {
                pattern: pattern.clone(),
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
            if adguard_target_regex(pattern, *match_case).len() > MAX_GENERATED_REGEX_BYTES {
                return Err("generated pattern exceeds hard byte limit".into());
            }
            let host_suffix = domains
                .first()
                .cloned()
                .or_else(|| extract_adguard_host(pattern));
            Ok(CompiledScope::AdGuardTarget {
                pattern: pattern.clone(),
                match_case: *match_case,
                domains: domains.clone(),
                host_suffix,
            })
        }
    }
}

fn compile_whole_url_pattern(pattern: &str) -> Option<Regex> {
    checked_regex(&format!("(?i){pattern}")).ok()
}

fn compile_redirect_extractor(ir: &RedirectExtractorIr) -> Option<RedirectExtractor> {
    match ir {
        RedirectExtractorIr::ClearUrls { pattern } => {
            checked_regex(&format!("(?i){pattern}")).ok().map(|regex| {
                if pattern.as_ref() == GOOGLE_SEARCH_REDIRECT_PATTERN {
                    RedirectExtractor::ClearUrlsGoogle { regex }
                } else {
                    RedirectExtractor::ClearUrls { regex }
                }
            })
        }
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

fn compile_redirect_extractors(
    pending: &[PendingRedirectCompile],
) -> Vec<Option<RedirectExtractor>> {
    pending
        .iter()
        .map(|rule| compile_redirect_extractor(&rule.extractor))
        .collect()
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
        RedirectExtractor::ClearUrlsGoogle { regex } => {
            if raw_url.is_ascii() {
                extract_google_search_redirect(raw_url)
            } else {
                regex
                    .captures(raw_url)
                    .and_then(|captures| captures.get(1).map(|match_| match_.as_str().to_string()))
            }
        }
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

fn extract_google_search_redirect(raw_url: &str) -> Option<String> {
    debug_assert!(raw_url.is_ascii());
    let after_scheme = raw_url
        .get(..8)
        .filter(|scheme| scheme.eq_ignore_ascii_case("https://"))
        .map(|_| &raw_url[8..])
        .or_else(|| {
            raw_url
                .get(..7)
                .filter(|scheme| scheme.eq_ignore_ascii_case("http://"))
                .map(|_| &raw_url[7..])
        })?;
    let marker = after_scheme
        .as_bytes()
        .windows(5)
        .position(|window| window.eq_ignore_ascii_case(b"/url?"))?;
    let host = &after_scheme[..marker];
    let labels = host.split('.').collect::<Vec<_>>();
    let valid_subdomain = |label: &&str| {
        !label.is_empty()
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    };
    let valid_tld =
        |label: &&str| label.len() >= 2 && label.bytes().all(|byte| byte.is_ascii_alphabetic());
    if !(0..labels.len().saturating_sub(1)).any(|google| {
        labels[google].eq_ignore_ascii_case("google")
            && labels[..google].iter().all(valid_subdomain)
            && labels[google + 1..].iter().all(valid_tld)
    }) {
        return None;
    }

    let query = &after_scheme[marker + 5..];
    for offset in 0..query.len() {
        let rest = &query[offset..];
        let value = if rest
            .get(..4)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("url="))
        {
            &rest[4..]
        } else if rest
            .get(..2)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("q="))
        {
            &rest[2..]
        } else {
            continue;
        };
        let capture = value.split('&').next().unwrap_or_default();
        let http = capture
            .get(..4)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("http"));
        let suffix_start = if capture
            .get(4..5)
            .is_some_and(|suffix| suffix.eq_ignore_ascii_case("s"))
        {
            5
        } else {
            4
        };
        if http && capture.len() > suffix_start {
            return Some(capture.to_string());
        }
    }
    None
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

fn scopes_match_embedded_beacon(store: &RuleStore, raw_url: &str) -> bool {
    if !contains_embedded_url(raw_url) {
        return false;
    }
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
        let candidate = &decoded[start..];
        if let Ok(parsed) = Url::parse(candidate) {
            let provider_matches = match_provider_patterns(store, candidate);
            if store.beacons.iter().any(|rule| {
                scopes_match(
                    &store.scopes,
                    &rule.include,
                    &rule.exclude,
                    candidate,
                    &parsed,
                    &provider_matches,
                )
            }) {
                return true;
            }
        }
        offset = start.saturating_add(1);
    }
    false
}

fn decode_query_component(value: &str) -> Cow<'_, str> {
    if value.as_bytes().contains(&b'+') {
        let form_value = value.replace('+', " ");
        Cow::Owned(
            percent_decode_str(&form_value)
                .decode_utf8_lossy()
                .into_owned(),
        )
    } else {
        percent_decode_str(value).decode_utf8_lossy()
    }
}

fn host_suffix_matches(host: &str, suffix: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let suffix = suffix
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    host == suffix || host.ends_with(&format!(".{suffix}"))
}

fn adguard_target_matches(pattern: &str, raw_url: &str, match_case: bool) -> bool {
    let domain_anchor = pattern.starts_with("||");
    let anchored_start = !domain_anchor && pattern.starts_with('|');
    let anchored_end = pattern.ends_with('|') && !pattern.ends_with("\\|");
    let body_start = if domain_anchor {
        2
    } else if anchored_start {
        1
    } else {
        0
    };
    let body_end = if anchored_end {
        pattern.len().saturating_sub(1).max(body_start)
    } else {
        pattern.len()
    };
    let body = &pattern[body_start..body_end];

    if domain_anchor {
        for marker_start in raw_url
            .char_indices()
            .map(|(offset, _)| offset)
            .chain(std::iter::once(raw_url.len()))
        {
            let remainder = &raw_url[marker_start..];
            let scheme_len = ["https://", "http://"].into_iter().find_map(|scheme| {
                let prefix = remainder.get(..scheme.len())?;
                let matches = if match_case {
                    prefix == scheme
                } else {
                    prefix.eq_ignore_ascii_case(scheme)
                };
                matches.then_some(scheme.len())
            });
            let Some(scheme_len) = scheme_len else {
                continue;
            };
            let authority_start = marker_start + scheme_len;
            let authority_end = raw_url[authority_start..]
                .find(['/', '?', '#'])
                .map(|offset| authority_start + offset)
                .unwrap_or(raw_url.len());
            let mut start = authority_start;
            loop {
                if adguard_glob_matches_at(body, &raw_url[start..], match_case, anchored_end) {
                    return true;
                }
                let Some(dot) = raw_url[start..authority_end].find('.') else {
                    break;
                };
                start += dot + 1;
            }
        }
        return false;
    }

    if anchored_start {
        return adguard_glob_matches_at(body, raw_url, match_case, anchored_end);
    }

    raw_url
        .char_indices()
        .map(|(offset, _)| offset)
        .chain(std::iter::once(raw_url.len()))
        .any(|offset| adguard_glob_matches_at(body, &raw_url[offset..], match_case, anchored_end))
}

fn adguard_glob_matches_at(
    pattern: &str,
    value: &str,
    match_case: bool,
    anchored_end: bool,
) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let mut pattern_index = 0usize;
    let mut value_index = 0usize;
    let mut star = None;
    let mut star_value = 0usize;

    loop {
        if pattern_index == pattern.len() {
            if !anchored_end || value_index == value.len() {
                return true;
            }
        } else if pattern[pattern_index] == b'*' {
            star = Some(pattern_index);
            pattern_index += 1;
            star_value = value_index;
            continue;
        } else if pattern[pattern_index] == b'^' && value_index == value.len() {
            pattern_index += 1;
            continue;
        } else if value_index < value.len() {
            let expected = pattern[pattern_index];
            let actual = value[value_index];
            let matches = if expected == b'^' {
                !actual.is_ascii_alphanumeric() && !matches!(actual, b'_' | b'.' | b'%' | b'-')
            } else if match_case {
                expected == actual
            } else {
                expected.eq_ignore_ascii_case(&actual)
            };
            if matches {
                pattern_index += 1;
                value_index += 1;
                continue;
            }
        }

        let Some(star_index) = star else {
            return false;
        };
        if star_value == value.len() {
            return false;
        }
        star_value += 1;
        pattern_index = star_index + 1;
        value_index = star_value;
    }
}

fn glob_matches(pattern: &str, value: &str) -> bool {
    if pattern.is_ascii() && value.is_ascii() {
        return glob_matches_ascii(pattern.as_bytes(), value.as_bytes());
    }
    glob_matches_unicode(pattern, value)
}

fn glob_matches_ascii(pattern: &[u8], value: &[u8]) -> bool {
    let mut pattern_index = 0usize;
    let mut value_index = 0usize;
    let mut star = None;
    let mut star_value = 0usize;

    loop {
        if pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
            star = Some(pattern_index);
            pattern_index += 1;
            star_value = value_index;
            continue;
        }
        if pattern_index < pattern.len()
            && value_index < value.len()
            && (pattern[pattern_index] == b'?'
                || pattern[pattern_index].eq_ignore_ascii_case(&value[value_index]))
        {
            pattern_index += 1;
            value_index += 1;
            continue;
        }
        if pattern_index == pattern.len() && value_index == value.len() {
            return true;
        }

        let Some(star_index) = star else {
            return false;
        };
        if star_value == value.len() {
            return false;
        }
        star_value += 1;
        pattern_index = star_index + 1;
        value_index = star_value;
    }
}

fn glob_matches_unicode(pattern: &str, value: &str) -> bool {
    let mut pattern = pattern.chars().peekable();
    let mut value = value.chars().peekable();
    let mut star_pattern = None;
    let mut star_value = None;

    loop {
        match (pattern.peek().copied(), value.peek().copied()) {
            (Some('*'), _) => {
                pattern.next();
                star_pattern = Some(pattern.clone());
                star_value = Some(value.clone());
            }
            (Some('?'), Some(_)) => {
                pattern.next();
                value.next();
            }
            (Some(expected), Some(actual)) if chars_eq_ignore_case(expected, actual) => {
                pattern.next();
                value.next();
            }
            (None, None) => return true,
            _ => {
                let (Some(saved_pattern), Some(mut saved_value)) =
                    (star_pattern.clone(), star_value.clone())
                else {
                    return false;
                };
                if saved_value.next().is_none() {
                    return false;
                }
                pattern = saved_pattern;
                value = saved_value.clone();
                star_value = Some(saved_value);
            }
        }
    }
}

fn chars_eq_ignore_case(left: char, right: char) -> bool {
    if left.is_ascii() && right.is_ascii() {
        left.eq_ignore_ascii_case(&right)
    } else {
        left.to_lowercase().eq(right.to_lowercase()) || left.to_uppercase().eq(right.to_uppercase())
    }
}

fn extract_glob_host_suffix(pattern: &str) -> Option<Box<str>> {
    let after_scheme = pattern.split_once("://")?.1;
    let host = after_scheme.split(['/', '?', '#']).next()?;
    if host.is_empty() || host.contains('?') {
        return None;
    }
    let host = host.strip_prefix("*.").unwrap_or(host);
    if host.is_empty()
        || !host.is_ascii()
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    {
        return None;
    }
    Some(host.to_ascii_lowercase().into_boxed_str())
}

fn adguard_target_regex(pattern: &str, match_case: bool) -> String {
    let domain_anchor = pattern.starts_with("||");
    let anchored_start = !domain_anchor && pattern.starts_with('|');
    let anchored_end = pattern.ends_with('|') && !pattern.ends_with("\\|");
    let body_start = if domain_anchor {
        2
    } else if anchored_start {
        1
    } else {
        0
    };
    let body_end = if anchored_end {
        pattern.len().saturating_sub(1).max(body_start)
    } else {
        pattern.len()
    };
    let pattern = &pattern[body_start..body_end];

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
        if !regex_pattern_allowed(&provider_pattern)
            || regex_syntax::parse(&provider_pattern).is_err()
        {
            counters.failed(format!("{name}.urlPattern"));
            ir.failed_regexes += 1;
            continue;
        }
        let mut exceptions = Vec::with_capacity(provider.exceptions.len());
        for pattern in &provider.exceptions {
            let compiled = format!("(?i){pattern}");
            if !regex_pattern_allowed(&compiled) || regex_syntax::parse(&compiled).is_err() {
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
            if !regex_pattern_allowed(&compiled) || regex_syntax::parse(&compiled).is_err() {
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
            if !regex_pattern_allowed(&compiled) || regex_syntax::parse(&compiled).is_err() {
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
                if pattern.len() > MAX_REGEX_PATTERN_BYTES || regex_syntax::parse(&pattern).is_err()
                {
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
    if pattern.is_ascii() && !pattern.bytes().any(is_regex_meta_byte) {
        return Ok(vec![ParamMatcherSpec::Exact {
            value: pattern.to_ascii_lowercase().into_boxed_str(),
            subject: ParamSubject::DecodedName,
            case_sensitive: false,
            requires_equals: false,
        }]);
    }
    let hir = regex_syntax::parse(pattern).map_err(|_| "unsupported or invalid regex")?;
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
    Ok(vec![ParamMatcherSpec::Regex {
        pattern: compiled.into_boxed_str(),
        subject: ParamSubject::DecodedName,
        case_sensitive: false,
        requires_equals: false,
    }])
}

fn is_regex_meta_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'.' | b'^'
            | b'$'
            | b'*'
            | b'+'
            | b'?'
            | b'{'
            | b'}'
            | b'['
            | b']'
            | b'\\'
            | b'|'
            | b'('
            | b')'
    )
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

#[derive(Hash, PartialEq, Eq)]
enum RegexBudgetKey<'a> {
    UrlPattern(&'a str),
    UrlException(&'a str),
    Parameter {
        pattern: &'a str,
        subject: ParamSubject,
        case_sensitive: bool,
        requires_equals: bool,
    },
    Scope(&'a ScopeSpec),
    Redirect(&'a str),
    Beacon(&'a str),
    Raw(&'a str),
}

fn case_insensitive_pattern_key(pattern: &str) -> &str {
    pattern.strip_prefix("(?i)").unwrap_or(pattern)
}

fn count_regex_rules(source: &SourceIr) -> usize {
    let mut expressions = HashSet::<RegexBudgetKey<'_>>::new();

    for provider in &source.providers {
        expressions.insert(RegexBudgetKey::UrlPattern(case_insensitive_pattern_key(
            &provider.url_pattern,
        )));
        for exception in &provider.exceptions {
            expressions.insert(RegexBudgetKey::UrlException(case_insensitive_pattern_key(
                exception,
            )));
        }
    }
    for rule in &source.params {
        if let ParamMatcherSpec::Regex {
            pattern,
            subject,
            case_sensitive,
            requires_equals,
        } = &rule.matcher
        {
            expressions.insert(RegexBudgetKey::Parameter {
                pattern,
                subject: *subject,
                case_sensitive: *case_sensitive,
                requires_equals: *requires_equals,
            });
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
                    expressions.insert(RegexBudgetKey::Redirect(pattern));
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
            expressions.insert(RegexBudgetKey::Beacon(
                rule.raw_pattern.as_deref().unwrap_or_default(),
            ));
        }
    }
    for rule in &source.raw_rules {
        for scope in &rule.include {
            add_regex_budget_scope(&mut expressions, scope);
        }
        expressions.insert(RegexBudgetKey::Raw(&rule.pattern));
    }
    expressions.len()
}

fn add_regex_budget_scope<'a>(expressions: &mut HashSet<RegexBudgetKey<'a>>, scope: &'a ScopeSpec) {
    if !matches!(scope, ScopeSpec::Any) {
        expressions.insert(RegexBudgetKey::Scope(scope));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_segment_reuses_decoded_subjects_and_regex_set_results() {
        let segment = QuerySegment::new("utm%5Fsource=hello+world");
        assert_eq!(segment.subject(ParamSubject::RawName), "utm%5Fsource");
        assert_eq!(segment.subject(ParamSubject::DecodedName), "utm_source");
        assert_eq!(
            segment.subject(ParamSubject::DecodedPair),
            "utm_source=hello world"
        );

        let chunks = [RegexSetChunk {
            set: RegexSet::new([r"^utm_source$", r"^other$"]).unwrap(),
        }];
        assert!(segment.regex_matched(ParamSubject::DecodedName, &chunks, 0, 0));
        assert!(!segment.regex_matched(ParamSubject::DecodedName, &chunks, 0, 1));
        assert_eq!(
            segment
                .decoded_name_regex_matches
                .get()
                .unwrap()
                .iter()
                .filter(|matches| matches.get().is_some())
                .count(),
            1
        );
    }

    #[test]
    fn compact_provider_trie_handles_empty_and_overlapping_patterns() {
        let empty = DirectProviderTrie::new(&[]);
        empty.match_at("anything", 0, &mut []);

        let trie = DirectProviderTrie::new(&[("example", 0), ("example.com", 1), ("example", 2)]);
        let mut matched = [false; 3];
        trie.match_at("EXAMPLE.COM/path", 0, &mut matched);
        assert_eq!(matched, [true, true, true]);

        let mut partial = [false; 3];
        trie.match_at("prefix.example.com", 7, &mut partial);
        assert_eq!(partial, [true, true, true]);
    }

    #[test]
    fn regex_budget_uses_typed_deduplicated_keys() {
        let provider = |pattern: &str| ProviderIr {
            name: "provider".into(),
            global: false,
            complete: false,
            url_pattern: pattern.into(),
            exceptions: vec!["same".into()],
        };
        let parameter = |subject| ParamRuleIr {
            source: SourceKind::ClearUrls,
            provider: None,
            global: false,
            referral: false,
            exception: false,
            exception_all: false,
            matcher: ParamMatcherSpec::Regex {
                pattern: "same".into(),
                subject,
                case_sensitive: false,
                requires_equals: false,
            },
            include: vec![ScopeSpec::UrlGlob("*://example.test/*".into())],
            exclude: vec![ScopeSpec::Any],
            report_index: 0,
        };
        let source = SourceIr {
            providers: vec![provider("same"), provider("(?i)same")],
            params: vec![
                parameter(ParamSubject::RawName),
                parameter(ParamSubject::RawName),
                parameter(ParamSubject::DecodedName),
            ],
            ..SourceIr::default()
        };

        // Provider patterns normalize an existing `(?i)` prefix, while each
        // expression kind and structurally distinct parameter remain separate.
        assert_eq!(count_regex_rules(&source), 5);
    }

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

    /// The matcher used before Brave URL globs moved off `regex`.
    fn legacy_brave_glob_matches(pattern: &str, value: &str) -> bool {
        let mut expression = String::from("(?is)^");
        for character in pattern.chars() {
            match character {
                '*' => expression.push_str(".*"),
                '?' => expression.push('.'),
                _ => expression.push_str(&regex::escape(&character.to_string())),
            }
        }
        expression.push('$');
        Regex::new(&expression).unwrap().is_match(value)
    }

    /// The matcher used before AdGuard target expressions moved off `regex`.
    fn legacy_adguard_target_matches(pattern: &str, value: &str, match_case: bool) -> bool {
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

        let mut expression = if match_case {
            String::new()
        } else {
            String::from("(?i)")
        };
        if domain_anchor {
            expression.push_str("https?://(?:[^/?#]+\\.)?");
        } else if anchored_start {
            expression.push('^');
        }
        for character in pattern.chars() {
            match character {
                '*' => expression.push_str(".*"),
                '^' => expression.push_str("(?:[^A-Za-z0-9_.%-]|$)"),
                _ => expression.push_str(&regex::escape(&character.to_string())),
            }
        }
        if anchored_end {
            expression.push('$');
        }
        Regex::new(&expression).unwrap().is_match(value)
    }

    #[derive(Clone, Copy)]
    struct DeterministicAscii(u64);

    impl DeterministicAscii {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0
        }

        fn string(&mut self, alphabet: &[u8], max_len: usize) -> String {
            let len = self.next() as usize % (max_len + 1);
            (0..len)
                .map(|_| alphabet[self.next() as usize % alphabet.len()] as char)
                .collect()
        }
    }

    #[test]
    fn brave_glob_matcher_is_equivalent_to_legacy_regex_for_ascii_inputs() {
        let patterns = [
            "*",
            "*://*.example.com/*",
            "https://example.com/path?value=*",
            "HTTPS://EXAMPLE.COM/*",
            "?://?/*",
            "https://example.com/%2F*",
            "https://example.com/a?b",
            "https://example.com/literal.+()[]{}^$|\\*",
            "line?break",
        ];
        let values = [
            "",
            "https://example.com/",
            "HTTP://EXAMPLE.COM/path",
            "https://sub.example.com/path?value=%2F",
            "https://example.com/%2fencoded",
            "https://example.com/a?b",
            "https://example.com/aXb",
            "line\nbreak",
            "mailto:user@example.com",
        ];
        for pattern in patterns {
            for value in values {
                assert_eq!(
                    glob_matches(pattern, value),
                    legacy_brave_glob_matches(pattern, value),
                    "Brave glob mismatch: pattern={pattern:?}, value={value:?}"
                );
            }
        }

        let mut random = DeterministicAscii(0x6272_6176_652d_676c);
        let pattern_alphabet = b"abXY09*?./:%_-+&=#";
        let value_alphabet = b"abXY09./:%_-+&=#?";
        for _ in 0..10_000 {
            let pattern = random.string(pattern_alphabet, 18);
            let value = random.string(value_alphabet, 30);
            assert_eq!(
                glob_matches(&pattern, &value),
                legacy_brave_glob_matches(&pattern, &value),
                "generated Brave glob mismatch: pattern={pattern:?}, value={value:?}"
            );
        }
    }

    #[test]
    fn adguard_target_matcher_is_equivalent_to_legacy_regex_for_ascii_inputs() {
        let patterns = [
            "tracker",
            "|https://example.com/path|",
            "||example.com^",
            "||example.com/path*",
            "||sub.example.com^pixel",
            "example.com^",
            "*/collect?*",
            "|mailto:user@example.com|",
            "||example.com/%2F*",
            r"literal\\|",
        ];
        let values = [
            "",
            "https://example.com/",
            "http://sub.example.com/path",
            "HTTPS://EXAMPLE.COM/path",
            "https://example.com.evil/path",
            "https://notexample.com/path",
            "https://example.com/%2Fencoded",
            "https://proxy.invalid/?u=https://example.com/pixel",
            "mailto:user@example.com",
        ];
        for match_case in [false, true] {
            for pattern in patterns {
                for value in values {
                    assert_eq!(
                        adguard_target_matches(pattern, value, match_case),
                        legacy_adguard_target_matches(pattern, value, match_case),
                        "AdGuard mismatch: pattern={pattern:?}, value={value:?}, match_case={match_case}"
                    );
                }
            }
        }

        let mut random = DeterministicAscii(0x6164_6775_6172_642d);
        let body_alphabet = b"abXY09*^./:%_-+&=#?";
        let value_alphabet = b"abXY09./:%_-+&=#?";
        let bases = [
            "https://example.com/",
            "http://sub.example.com/",
            "HTTPS://EXAMPLE.COM/",
            "https://proxy.invalid/?url=https://example.com/",
            "mailto:user@example.com/",
        ];
        for iteration in 0..10_000 {
            let prefix = match random.next() % 3 {
                0 => "",
                1 => "|",
                _ => "||",
            };
            let mut body = random.string(body_alphabet, 16);
            // A target expression containing only its anchor marker is not a
            // valid AdGuard rule and made the legacy translator underflow too.
            if body.is_empty() {
                body.push('a');
            }
            let suffix = if random.next() % 4 == 0 { "|" } else { "" };
            let pattern = format!("{prefix}{body}{suffix}");
            let base = bases[random.next() as usize % bases.len()];
            let value = format!("{base}{}", random.string(value_alphabet, 24));
            let match_case = iteration % 2 == 0;
            assert_eq!(
                adguard_target_matches(&pattern, &value, match_case),
                legacy_adguard_target_matches(&pattern, &value, match_case),
                "generated AdGuard mismatch: pattern={pattern:?}, value={value:?}, match_case={match_case}"
            );
        }
    }

    #[test]
    fn provider_regex_set_preserves_provider_and_exception_mapping() {
        let ruleset = Ruleset::from_clearurls_str(
            r#"{"providers":{
                "alpha":{"urlPattern":"^https://alpha\\.example/","rules":["shared"],"exceptions":["keep=1"]},
                "beta":{"urlPattern":"^https://beta\\.example/","rules":["shared"],"exceptions":["keep=2"]}
            }}"#,
        )
        .unwrap();

        assert_eq!(
            ruleset.detect_provider("https://alpha.example/path"),
            Some("alpha")
        );
        assert_eq!(
            ruleset.detect_provider("https://beta.example/path"),
            Some("beta")
        );
        assert_eq!(ruleset.detect_provider("https://other.example/path"), None);
        assert!(ruleset.is_exception("https://alpha.example/path?keep=1"));
        assert!(!ruleset.is_exception("https://alpha.example/path?keep=2"));
        assert!(ruleset.is_exception("https://beta.example/path?keep=2"));
        assert_eq!(ruleset.stats().scopes, 2);
        assert_eq!(ruleset.stats().groups, 2);
    }

    #[test]
    fn direct_provider_matcher_is_equivalent_to_regex_for_supported_shapes() {
        let patterns = [
            r"^https?://example\.com/path",
            r"^https?:\/\/example\.com\/path\?",
            r"^https?://site\.com/path",
            r"^https?://(?:[a-z0-9-]+\.)*?example\.com/path",
            r"^https?:\/\/(?:[a-z0-9-]+\.)*?example\.com\/path",
        ];
        let values = [
            "https://example.com/path",
            "HTTPS://EXAMPLE.COM/PATH",
            "http://sub.example.com/path?x=1",
            "https://two.sub.example.com/path",
            "https://bad_.example.com/path",
            "https://exampleXcom/path",
            "https://example.comevil/path",
            "https://example.com.evil/path",
            "https://example.com:443/path",
            "https://u@example.com/path",
            "https://.example.com/path",
            "https://ſite.com/path",
            "ftp://example.com/path",
        ];
        for pattern in patterns {
            let direct = compile_provider_direct_pattern(pattern).unwrap();
            let regex = Regex::new(&format!("(?i){pattern}")).unwrap();
            for value in values {
                assert_eq!(
                    match &direct {
                        ProviderMatcher::Direct {
                            literals,
                            subdomains,
                            ..
                        } => literals.iter().any(|literal| provider_direct_matches(
                            literal,
                            *subdomains,
                            value
                        )),
                        ProviderMatcher::Regex(_) => unreachable!(),
                    },
                    regex.is_match(value),
                    "provider mismatch: pattern={pattern:?}, value={value:?}"
                );
            }
        }

        for pattern in [
            r"^https?://example.(com|net)",
            r"^https?://example\.[a-z]{2,}",
            r"https?://example\.com",
            r"^https?://(?:[a-z0-9-]+\.)*?example\.com/.*",
        ] {
            assert!(compile_provider_direct_pattern(pattern).is_none());
        }
    }

    #[test]
    fn redirect_prefilter_preserves_capture_and_source_order() {
        let ruleset = Ruleset::from_clearurls_str(
            r#"{"providers":{"redirector":{
                "urlPattern":"^https://redirect\\.example/",
                "redirections":[
                    "^https://redirect\\.example/out\\?first=([^&]+)",
                    "^https://redirect\\.example/out\\?.*second=([^&]+)"
                ]
            }}}"#,
        )
        .unwrap();

        assert_eq!(
            ruleset.redirect_target("https://redirect.example/out?first=one&second=two"),
            Some("one".into())
        );
        assert_eq!(
            ruleset.redirect_target("https://redirect.example/out?second=two"),
            Some("two".into())
        );
        assert_eq!(
            ruleset.redirect_target("https://redirect.example/other?first=one"),
            None
        );
        assert_eq!(ruleset.stats().redirect_rules, 2);
    }

    fn linear_redirect_target(ruleset: &Ruleset, url: &str) -> Option<RedirectTarget> {
        let parsed = Url::parse(url).ok()?;
        let provider_matches = match_provider_patterns(&ruleset.store, url);
        ruleset.store.redirects.iter().find_map(|rule| {
            scopes_match(
                &ruleset.store.scopes,
                &rule.include,
                &rule.exclude,
                url,
                &parsed,
                &provider_matches,
            )
            .then(|| extract_redirect_target(&rule.extractor, url, &parsed))
            .flatten()
            .map(|target| RedirectTarget {
                target,
                origin: rule.origin,
            })
        })
    }

    #[test]
    fn redirect_index_matches_linear_reference_for_adversarial_scopes() {
        let mut builder = RulesetBuilder::new(RuleLoadLimits::default());
        builder
            .add_source_str(
                "indexed-globs",
                r#"[
                    {"include":["*://first.example/*"],"exclude":["*://first.example/blocked*"],"action":"redirect","param":"first"},
                    {"include":["*://hint.example/*","*"],"exclude":[],"action":"redirect","param":"generic"},
                    {"include":["*://redirect.example:8443/*"],"exclude":[],"action":"redirect","param":"port"},
                    {"include":["*://user@userinfo.example/*"],"exclude":[],"action":"redirect","param":"userinfo"},
                    {"include":["*://[::1]/*"],"exclude":[],"action":"redirect","param":"ipv6"},
                    {"include":["*://ſite.example/*"],"exclude":[],"action":"redirect","param":"unicode"}
                ]"#,
                Some(RulePackFormat::BraveDebounce),
                None,
            )
            .unwrap();
        builder
            .add_source_str(
                "providers",
                r#"{"providers":{
                    "direct":{"urlPattern":"^https://redirect\\.example","redirections":["^https://redirect\\.example\\.evil/out\\?direct=([^&]+)"]},
                    "regex":{"urlPattern":"https://regex\\.example/","redirections":["^https://regex\\.example/out\\?regex=([^&]+)"]}
                }}"#,
                Some(RulePackFormat::ClearUrls),
                None,
            )
            .unwrap();
        let ruleset = builder.finish();

        let cases = [
            // Interleaved suffix and generic candidates retain source order.
            (
                "https://first.example/out?first=one&generic=two",
                Some("one"),
            ),
            // Excluding the earlier suffix candidate permits the generic rule.
            (
                "https://first.example/blocked?first=one&generic=two",
                Some("two"),
            ),
            // The unhinted half of an OR include forces a generic fallback.
            (
                "https://unrelated.example/out?generic=generic",
                Some("generic"),
            ),
            // Unsafe authorities must remain generic rather than form unusable host keys.
            ("https://redirect.example:8443/out?port=port", Some("port")),
            (
                "https://user@userinfo.example/out?userinfo=userinfo",
                Some("userinfo"),
            ),
            ("https://[::1]/out?ipv6=ipv6", Some("ipv6")),
            ("https://ſite.example/out?unicode=unicode", Some("unicode")),
            // A direct provider is a raw prefix, not a host-bound suffix.
            (
                "https://redirect.example.evil/out?direct=direct",
                Some("direct"),
            ),
            // Providers outside the structural fast path remain generic candidates.
            ("https://regex.example/out?regex=regex", Some("regex")),
            // Candidate lookup is defensive for normalized host variants.
            ("HTTPS://FIRST.EXAMPLE/out?first=upper", Some("upper")),
            ("https://first.example./out?first=dot", None),
            ("https://sub.first.example/out?first=sub", None),
        ];
        for (url, expected) in cases {
            let indexed = ruleset.redirect_target_with_origin(url);
            let linear = linear_redirect_target(&ruleset, url);
            assert_eq!(indexed, linear, "redirect index diverged for {url:?}");
            assert_eq!(
                indexed.as_ref().map(|target| target.target.as_str()),
                expected,
                "unexpected redirect result for {url:?}"
            );
        }
    }

    #[test]
    fn google_redirect_fast_path_matches_capture_regex() {
        let regex = Regex::new(&format!("(?i){GOOGLE_SEARCH_REDIRECT_PATTERN}")).unwrap();
        let values = [
            "https://www.google.com/url?q=https://destination.example/path&source=mail",
            "HTTP://GOOGLE.CO.UK/url?x=1&url=http://destination.example&q=https://later.example",
            "https://google.foo1.google.com/url?notq=https://destination.example",
            "https://google.com/url?q=ftp://destination.example&q=https://later.example",
            "https://google.com/url?q=http",
            "https://google.com.evil/url?q=https://destination.example",
            "https://bad_.google.com/url?q=https://destination.example",
            "https://google.com/search?q=https://destination.example",
        ];
        for value in values {
            let expected = regex
                .captures(value)
                .and_then(|captures| captures.get(1).map(|matched| matched.as_str().to_string()));
            assert_eq!(
                extract_google_search_redirect(value),
                expected,
                "Google redirect mismatch for {value:?}"
            );
        }
    }

    #[test]
    fn literal_clearurls_fast_path_keeps_meta_patterns_on_regex_path() {
        let ruleset = Ruleset::from_clearurls_str(
            r#"{"providers":{"globalRules":{"urlPattern":"^https?://","rules":["Literal_Name","regex.+"]}}}"#,
        )
        .unwrap();

        assert_eq!(ruleset.stats().exact_param_rules, 1);
        assert_eq!(ruleset.stats().regex_param_rules, 1);
        assert!(ruleset.param_is_tracking("https://example.test/", "literal_name", true, false));
        assert!(ruleset.param_is_tracking("https://example.test/", "regex-value", true, false));
    }

    #[test]
    fn degenerate_adguard_anchors_do_not_underflow() {
        assert!(adguard_target_matches("|", "", false));
        assert!(!adguard_target_matches("|", "https://example.test/", false));
        assert!(!adguard_target_matches(
            "||",
            "https://example.test/",
            false
        ));
        assert!(!adguard_target_matches("||", "HTTPS://example.test/", true));

        let ruleset = Ruleset::from_adguard_str("||$removeparam=tracking").unwrap();
        assert!(!ruleset.param_is_tracking(
            "https://example.test/?tracking=1",
            "tracking",
            true,
            false
        ));
    }
}

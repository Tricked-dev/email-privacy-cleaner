# Rule-engine refactor plan

This document is the implementation contract for the rule-engine refactor. The
goal is a smaller, immutable runtime store with source-specific semantics,
bounded loading, and compatibility evidence. Work is complete only when the
acceptance gates at the end are either passed or explicitly documented as
blocked by external infrastructure.

## Non-negotiable invariants

1. Existing built-in cleaning remains behaviorally compatible, except for a
   separately approved fix. Characterization tests and differential fixtures
   are added before changing matching behavior.
2. A rule is a scoped action group: include scope, exclude scope, action, and
   deterministic order travel together. Exceptions are never a global flat
   carve-out and cannot suppress unrelated actions from another source.
3. Source semantics remain distinct:
   - ClearURLs names are percent-decoded and case-insensitive, including
     parameters without `=`.
   - Brave Clean URLs names are raw, exact, case-sensitive, and require `=`.
   - AdGuard `$removeparam` can match the supported normalized `name=value`
     subject, with explicit exception and modifier semantics.
4. Disabled providers are filtered before semantic deduplication. Provenance
   is retained only in bounded statistics/explanations, never in the dedup key.
5. Redirect precedence is deterministic and follows source/provider order; no
   hash-map iteration may choose the winner.
6. URL scope is computed once per URL and reused for every query parameter.
   Runtime state is immutable and safe to share through one `Arc`.
7. A source that exceeds byte, normalized-rule, or regex budgets is rejected
   atomically. Local and HTTPS sources use the same limits, and message
   processing never performs network I/O.
8. Unsupported syntax is skipped only where the adapter explicitly defines it
   as unsupported. It is never approximated into a broader matcher.

## Compatibility decisions recorded up front

- `rawRules` are public and callable but are not part of the ordinary cleaning
  path. Activating them requires a separate approved change.
- ClearURLs provider exceptions retain their current URL-wide behavior inside
  the ClearURLs adapter unless dedicated compatibility tests approve a change.
- The public `Ruleset` facade is retained. A `RulesetBuilder` owns merging,
  disabling, deduplication, and final compilation. Public compiled-store
  `merge`/`disable` behavior is either migrated/deprecated or backed by compact
  canonical definitions; compiled indexes are never concatenated.
- Brave browser preferences are skipped and counted because a mail cleaner
  cannot faithfully apply browser state such as de-AMP.
- Automatic AdGuard import accepts explicit `$image` rules only. Modifierless
  blocking rules require an explicit per-source `usage = "mail-beacon"` hint;
  filename or URL naming is never treated as proof of email intent.
- External beacon rules affect only image/CSS image call sites. Existing hidden,
  1x1, layout, and path heuristics remain independent.

## Phases

### 0. Repository contract and baseline

- Record the current branch/worktree and read repository instructions.
- Fix CI triggers from `main` to the actual default branch `master`.
- Add characterization tests for built-in transformations, exceptions, provider
  and redirect order, no-value parameters, encoded keys, sender policies, and
  `List-Unsubscribe` protection.
- Add baseline build/match/message measurements and a deterministic generated
  URL corpus.
- Add a counting-loader test proving each configured HTTPS source is fetched
  once, and fix the TOML/CLI/milter double-finalization path.
- Decide and test that `rawRules` remain an explicit API-only operation and
  whether redirect unwrapping is independently gated from exceptions.

### 1. Source loading, normalized IR, and reporting

- Introduce `RuleSource`, source-purpose/format metadata, `SourceIr`, resource
  limits, and a `RulesetBuilder`.
- Use the pipeline: bounded read -> shape detection -> temporary parser/AST ->
  normalized IR -> source-limit validation -> global deduplicating builder.
- Drop source bytes, AST, and IR after merge. Keep only bounded reports and
  diagnostic samples.
- Add `RuleLoadReport`, per-source `SourceReport`, and final `RuleStoreStats`,
  with optional JSON output for `rule-stats`/`check-rule-pack` diagnostics.
- Move ClearURLs parsing behind an adapter without changing its current
  matching and exception behavior.

### 2. Immutable indexed runtime

- Implement scoped action groups, compact scope/action IDs, semantic dedup keys,
  deterministic ordering, and explicit parameter subjects/modes.
- Classify safe literals structurally using `regex-syntax` (exact, prefix,
  bounded finite alternatives); retain other expressions as regex.
- Compile match-only regexes in bounded/chunked sets, splitting oversized
  aggregates. Keep individual regexes for captures, replacements, extraction,
  and raw rules.
- Build domain exact/suffix indexes plus generic fallback indexes. Do not clone
  one Brave parameter set into every domain bucket.
- Add `Ruleset::context_for` and reuse its immutable candidate IDs across the
  query loop. Compile extra parameters and pixel domains into immutable data
  where practical.
- Verify `Arc::ptr_eq` for sender-specific policies and run concurrent matching
  without locks or runtime mutation.

### 3. Brave Clean URLs and Debounce

- Test and implement the supported URLPattern subset first.
- Preserve raw, case-sensitive Clean URLs query-key semantics and `=`
  requirement.
- Model Debounce with explicit `RedirectExtractor` variants for query params,
  path regex/concatenation, path templates, base64url, and scheme prepending.
- Handle include/exclude URL scopes, all current supported actions, strict
  ambiguity behavior, capture/template validation, and deterministic order.
- Skip/report browser-pref rules. Apply Brave-specific same-site and
  registrable-domain validation only to Brave-derived redirects.

### 4. Strict AdGuard subset and mail beacons

- Implement a tokenizer and modifier allowlist for comments/metadata, safe
  target patterns, `$removeparam=name`, supported regex `$removeparam`,
  `$image`, `$match-case`, positive target-domain constraints, and scoped `@@`
  exceptions.
- Skip entire rules containing naked remove-all, inverted removeparam,
  unsupported modifiers, browser-context modifiers, or unrepresentable domain
  scopes. Never approximate them.
- Match beacon rules against both the original raw `src` and parsed host/path;
  use domain indexes for host suffixes and glob/regex or safe literal indexes
  for path/full-URL patterns.
- Keep external beacon behavior limited to image/CSS image contexts.

### 5. Limits, docs, benchmarks, and packaging

- Default limits: 5 MiB per source, 25 MiB total, 32 sources, 50,000 external
  normalized atoms, 10,000 retained regex actions, plus hard pattern,
  expansion, chunk, compiled-size, and diagnostic-sample bounds.
- Add reproducible fixed-seed large-pack generation and release RSS checks via
  `/usr/bin/time -v`; benchmark build and matching throughput with Criterion or
  an equivalent diagnostic.
- Target startup RSS <256 MiB for five recommended packs, compiled runtime
  memory <128 MiB, and throughput >=90% of baseline unless a measured
  regression is justified.
- Update README, config example, CLI help, module documentation, and
  `nix/module.nix`.
- Keep the binary's built-in list small and manually maintained in
  `rules/builtin.json`. Keep external packs optional, and support them through
  the configured external-pack formats, local paths, HTTPS sources, and
  Nix-prefetched store paths.

## Acceptance gates

1. Built-in-only transformations match the pre-refactor characterization set.
2. All five supported source families load from local input and HTTPS, with
   each source fetched at most once.
3. ClearURLs, Brave, and AdGuard subject/case/encoding semantics have separate
   regression tests.
4. Exceptions are action- and scope-aware and cannot disable unrelated rules.
5. Domain/path scope is evaluated once per URL, then reused for parameters.
6. Safe parameter rules produce no per-rule regex objects; match-only regexes
   are bounded sets; capture/replacement rules remain individual.
7. Resource limits are atomic and shared by local/remote loading; diagnostics
   are bounded; message processing performs no network I/O.
8. Sender clones share the compiled store by `Arc::ptr_eq`; concurrent matching
   is lock-free from the runtime’s perspective.
9. CI runs fmt, Clippy, all-feature/no-default-feature tests on Rust 1.75 and
   stable, then `nix flake check`. Use `rule-stats` for manual and benchmark
   diagnostics.
10. The final branch is committed and pushed, with the exact SHA and unresolved
    CI/deploy state reported separately.

## Work discipline

TDD is mandatory for every behavior or architectural contract in this change:

1. Add or extend a focused test that fails for the current implementation and
   states the intended behavior.
2. Implement the smallest complete change that makes that test pass.
3. Run the focused test, then the relevant module/integration suite.
4. Refactor only while the tests are green, preserving the test as a regression
   contract.

Tests must cover both positive and negative cases for source-specific matching,
scope, exceptions, budgets, ordering, and compatibility. A benchmark or manual
inspection is not a substitute for a failing-then-passing test. Every phase
must leave the tree formatted and testable. No generated runtime
store is built by concatenating compiled stores. No source is partially
accepted after a resource-budget failure. Any behavior change outside the
explicit decisions above gets its own test and is called out before merging.

## Detailed design contract

The sections below expand the summary above. They are normative where they
define source semantics, exception scope, resource behavior, or runtime
ownership.

### Rule groups and exceptions

The normalized representation must model a rule as a scoped action group, not
as independent positive rules plus a global exception collection:

~~~rust
struct RuleGroup {
    include_scopes: Box<[ScopeId]>,
    exclude_scopes: Box<[ScopeId]>,
    action: ActionId,
    order: u32,
}
~~~

The actual type may add matcher IDs and source-specific behavior flags, but
include scopes, exclude scopes, action, and deterministic order must remain
associated.

The adapters must preserve these differences:

- A Brave exclude belongs only to that particular include/parameter or
  Debounce entry.
- AdGuard @@ can negate one exact removeparam action, one regex removeparam
  action, or all supported removeparam actions matching a URL.
- The existing ClearURLs implementation treats a matching provider exception
  as a URL-wide carve-out before parameter cleaning. Preserve that behavior in
  the ClearURLs adapter unless a separately approved compatibility change
  changes it.
- An exception from one pack must not suppress a semantically unrelated action
  imported from another pack.

Semantic deduplication uses:

~~~text
action + matcher semantics + include scope + exclude scope + behavior flags
~~~

Provenance is not part of the key. Keep only compact source/provider IDs and
bounded counts for diagnostics and explanations. Apply disabled_providers
before adding rules to the global deduplicating builder so a duplicate in an
enabled provider cannot disappear because another copy came from a disabled
provider.

Redirect precedence remains deterministic source/provider order plus the first
matching redirect. Store an explicit order and never let hash-map iteration
choose the winner.

### Parameter subjects

The following semantics must not be collapsed into one lowercased decoded
set:

| Format | Matcher input | Case and encoding | Equality behavior |
| --- | --- | --- | --- |
| Existing ClearURLs path | Percent-decoded parameter name | Case-insensitive regex | Matching parameters are removed even without an equals sign. |
| Brave Clean URLs | Raw query key | Exact and case-sensitive | A key is removed only when its query segment contains an equals sign. Encoded and decoded spellings stay distinct. |
| AdGuard subset | Exact name or normalized name=value | Depends on rule form | Regex forms may inspect the value; exceptions and remove-all behavior are explicit. |

Use explicit matcher subjects:

~~~rust
enum ParamSubject {
    RawName,
    DecodedName,
    DecodedPair, // name=value
}

struct ParamMatcher {
    raw_exact_cs: HashSet<Box<str>>,
    decoded_exact_ci: HashSet<Box<str>>,
    raw_prefixes_cs: Box<[Box<str>]>,
    decoded_prefixes_ci: Box<[Box<str>]>,
    name_regexes: Box<[RegexSetChunk]>,
    pair_regexes: Box<[RegexSetChunk]>,
    requires_equals: bool,
}
~~~

The exact storage may differ, but source subject, case, decoding, equals
requirements, and value matching must survive normalization.

Incoming query names are already string slices. Do not use HashSet<Symbol> for
every incoming name unless profiling justifies a frozen interner. Interned
numeric IDs are useful for rule-group and scope references, but interning
message data would introduce hot-path allocation or mutation.

### Regex classification and compilation

Classify expressions structurally, preferably with regex-syntax:

1. A finite ASCII literal expression becomes one or more exact strings.
2. A literal followed by unrestricted dot-star becomes a prefix.
3. Bounded alternatives such as ga_(source|medium|campaign) expand to exact
   strings under a small expansion cap.
4. Everything else remains a regex, subject to pattern and source budgets.

Do not determine prefixes by checking how the source string happens to end.

Validate individual patterns first. Match-only patterns use bounded,
chunked RegexSets. If an aggregate is too large, recursively split the chunk.
A single invalid pattern or oversized aggregate must not invalidate every other
valid match-only pattern.

Individual Regex values remain appropriate for:

- redirect extraction requiring captures;
- rawRules replacement or removal;
- Brave path extraction;
- path templates;
- any action requiring pattern identity or captures.

An individual unsupported rule may be skipped under the adapter contract. A
source that exceeds its configured regex or normalized-rule budget is rejected
as a whole so that its positive rules cannot survive without their exclusions.

### Brave Debounce extractor model

Debounce needs a real extractor model rather than adaptation to ClearURLs
capture-group rules:

~~~rust
enum RedirectExtractor {
    ClearUrlsCapture {
        regex: Regex,
    },
    QueryParam {
        names: Box<[Box<str>]>,
        decode: DecodeMode,
        prepend_scheme: Option<Scheme>,
    },
    PathRegex {
        regex: Regex,
        assembly: CaptureAssembly,
    },
}

enum DecodeMode {
    Direct,
    Base64Url,
    ExistingAutoDecode, // compatibility for current project rules
}

enum CaptureAssembly {
    Concatenate,
    Template(Box<str>),
}
~~~

Support the current upstream action forms:

- redirect;
- base64,redirect;
- regex-path;
- regex-path-template;
- prepend_scheme;
- include and exclude URL patterns;
- browser preferences, only as explicitly skipped and reported rules.

For regex-path, apply the regex to the path and concatenate all capture
groups. For regex-path-template, substitute placeholders $1 through $9 and
validate that every placeholder corresponds exactly to an available capture
group. Apply strict regex and destination validation.

Rules containing a browser preference are skipped and counted because a
preference such as de-AMP cannot be translated faithfully into mail behavior.

Ambiguity means no rewrite:

- multiple destination parameters with different values;
- multiple alternate names with different destinations;
- invalid base64url;
- missing captures or template placeholders;
- a destination that requires guessing.

Brave same-site and registrable-domain checks apply only to Brave-derived
redirects. Existing ClearURLs and built-in redirect behavior keeps its current
validation.

### AdGuard subset and mail purpose

The first AdGuard adapter supports only:

- comments and metadata;
- a deliberate target URL subset using star, double-pipe, separator, and
  beginning/end-anchor semantics;
- exact removeparam=name;
- non-inverted removeparam=regex, matched against the supported name=value
  subject;
- @@ exceptions for those same forms;
- image rules in image/beacon context;
- match-case as a separate mode if implemented;
- positive target-domain constraints that can be interpreted conservatively.

Skip the entire rule when it contains:

- naked removeparam removing every parameter;
- inverted removeparam;
- important, badfilter, redirect, script, cosmetic, or replacement semantics;
- referrer, first-party, or third-party modifiers;
- negated, regex, or wildcard domain scopes that cannot be represented
  faithfully;
- any unknown modifier.

Do not approximate unsupported syntax. AdGuard domain constraints generally
refer to the originating or referrer domain, while email HTML has no faithful
browser document-origin equivalent. A conservative target-only subset may be
documented, but sender domain must not silently become browser referrer domain.

The Mail Tracking Protection list is a separate purpose: it contains many
modifierless patterns and ordinary plus percent-encoded URL forms intended to
survive mail-provider proxying. Do not infer that purpose from a filename or
URL.

The initial policy is:

1. Automatic mode imports only explicit image rules.
2. A structured source may set usage = "mail-beacon" to allow modifierless
   blocking rules.
3. An arbitrary AdGuard source never receives mail-beacon semantics implicitly.

Keep the existing rule_packs and rule_pack_urls string arrays. Add an optional
structured source form for format and purpose overrides:

~~~toml
[[rule_sources]]
url = "https://example.invalid/mail-tracking.txt"
format = "adguard"
usage = "mail-beacon"
~~~

Beacon matching tests both the original raw src and parsed host/path
components. Use the domain index for host suffixes. Reserve Aho-Corasick for
safe literal path or full-URL fragments; wildcards, separators, and anchors
need glob or regex representations.

External beacon actions are wired only into img and CSS image call sites. They
must never neutralize ordinary anchor href links. Existing hidden, 1x1, layout,
and path heuristics remain independent fallbacks.

### Runtime facade and per-URL context

Keep Ruleset as the public facade because the crate exports it. Keep the
compiled RuleStore and format adapters private:

~~~rust
pub struct Ruleset {
    store: RuleStore,
    stats: RuleStoreStats,
    // bounded compatibility diagnostics
}

struct RuleStore {
    scopes: ScopeIndex,
    param_matchers: Box<[ParamMatcher]>,
    beacons: BeaconMatcher,
    redirects: RedirectIndex,
    raw_urls: RawUrlMatcher,
}
~~~

The completed Ruleset is published once in an Arc. effective_for_sender must
share the compiled store; add an Arc::ptr_eq regression test and a concurrent
matching test proving the runtime has no mutable state or locks.

The current public Ruleset merge and disable methods conflict with compile
once. Choose the RAM-first API unless compatibility requires otherwise:

- introduce RulesetBuilder;
- apply source merging and disabled providers before finish();
- deprecate compiled-store merge and disable methods;
- finalize one immutable store.

If those public methods cannot be deprecated, retain compact canonical rule
definitions and rebuild only when the compatibility method is called. Record
the extra memory and rebuild cost. Never append compiled indexes after the
fact.

Add a per-URL immutable context so provider scans are not repeated for each
query parameter:

~~~rust
let context = ruleset.context_for(raw_url, &parsed_url);

for parameter in parsed_query {
    if context.should_remove_parameter(&parameter, flags) {
        // remove
    }
}
~~~

The context selects candidate group IDs from global, exact-host, host-suffix,
and generic fallback indexes. Path and query scope checks run once per
candidate group. A Brave entry with hundreds of domains maps every domain to
one matcher or group ID; it does not clone the parameter set into every
domain bucket.

### Resource limits and atomic loading

Initial defaults:

~~~text
max_rule_pack_bytes       = 5242880
max_total_rule_pack_bytes = 26214400
max_rule_pack_sources     = 32
max_external_rules        = 50000
max_regex_rules           = 10000
~~~

The first value is the per-source decompressed-byte limit. Apply it equally to
local files and HTTPS bodies. Also limit regex pattern bytes, RegexSet chunk
and compiled size, finite-alternative expansion, capture/template complexity,
and diagnostic samples.

When a source crosses a byte, normalized-rule, or regex budget, reject that
source atomically. Do not retain its positive rules while losing exclusions.
Unsupported individual AdGuard syntax may be skipped only because the parser
explicitly defines that behavior.

The loader lifecycle is:

1. bounded source read;
2. content-shape detection;
3. temporary source AST or streaming parser;
4. normalized SourceIr;
5. source-limit validation;
6. merge into the global deduplicating builder;
7. drop source bytes, AST, and SourceIr;
8. freeze scopes and IDs after all sources;
9. compile matcher categories;
10. drop builder maps and temporary vectors;
11. publish Arc<Ruleset>.

Consume builder collections where possible. Freeze runtime vectors into boxed
slices and retain only compact IDs, final matchers, bounded stats, and bounded
diagnostic samples.

### Reporting

Add structured reporting instead of relying only on stderr:

~~~rust
struct SourceReport {
    source: SanitizedSourceId,
    format: Option<RulePackFormat>,
    bytes_read: usize,
    parsed_rules: usize,
    accepted_rules: usize,
    unsupported_rules: usize,
    duplicates: usize,
    failed_regexes: usize,
    skipped_reason: Option<SkipReason>,
}
~~~

RuleLoadReport contains per-source reports and global totals. RuleStoreStats
contains final exact, prefix, regex, domain, beacon, redirect, and raw-rule
counts. Log one summary per source plus global totals, sanitize credentials
and query secrets from source identifiers, and retain only capped samples of
unsupported or failed patterns.

Add a rule-stats or check-rule-pack CLI command with optional JSON output.
The command provides deterministic final statistics for manual and benchmark
diagnostics. Noisy timing measurements are published diagnostics rather than
brittle hard gates.

## Phase exit criteria

### Phase 0 exit

- The master-triggered CI workflow is corrected.
- The pre-refactor fixture, URL, message, sender-policy, exception, ordering,
  no-value, encoded-key, unsubscribe, and rawRules characterization suite is
  green.
- Baseline build, matching, message, memory, and deterministic corpus results
  are recorded.
- The counting-loader test proves one fetch per configured HTTPS source.
- The rawRules and redirect-exception decisions are recorded independently.

### Phase 1 exit

- ClearURLs loads through the adapter with the old transformations.
- Disabled providers are filtered before deduplication.
- Local and HTTPS readers enforce identical limits.
- Over-budget sources are rejected atomically.
- Source summaries and bounded diagnostics are available.

### Phase 2 exit

- Indexed scope candidates are selected once per URL.
- Safe exact, finite-alternative, and prefix rules do not allocate individual
  regex objects.
- Match-only regexes use bounded sets.
- Capture and replacement actions retain individual regexes.
- Sender policy clones pass Arc::ptr_eq and concurrent matching tests.

### Phase 3 exit

- Brave Clean URLs preserve raw case-sensitive parameter semantics.
- All supported Debounce extractors and exclusions have focused tests.
- Browser preferences are skipped and reported.
- Ambiguous redirects are left unchanged.
- Brave-only destination checks do not change existing redirect behavior.

### Phase 4 exit

- The AdGuard modifier allowlist and rejected syntax are tested.
- Supported exact, regex, exception, image, domain, and match-case cases pass.
- Modifierless rules require explicit mail-beacon purpose.
- Raw encoded beacon URLs and parsed host/path matching both work.
- Anchor links are never affected by external beacon actions.

### Phase 5 exit

- Release RSS and compiled-store memory are measured against the explicit
  targets.
- README, config example, CLI help, module documentation, and Nix module
  describe the supported sources, limits, purpose hints, and diagnostics.
- The binary contains only the small manually maintained built-in list;
  external packs remain optional and are loaded through the supported source
  configuration paths.

## Final performance and CI gates

Before implementation begins, record the baseline and use these initial
targets for the five recommended packs:

- peak startup RSS below 256 MiB;
- steady-state compiled-rule memory below 128 MiB;
- URL and message throughput at least 90 percent of baseline unless a
  measured regression is specifically justified.

CI must run format, Clippy, all-feature tests, no-default-feature tests, and
build checks on Rust 1.75 and stable, followed by nix flake check. Use the
`rule-stats` command for manual and benchmark diagnostics. Microbenchmark
timing is published with the pack set, build mode, machine, and measurement
tool, not used as a noisy hard gate.

# email-privacy-cleaner

A reusable **Rust library** plus a **milter daemon** that sanitise the
privacy-invasive parts of email, designed to run as a pre-queue milter for the
[Stalwart](https://stalw.art) mail server at the SMTP **DATA** stage (but usable
standalone via the CLI).

It performs these independent, deterministic, **offline** transformations:

1. **Tracking-pixel removal** — drops 1×1 / hidden / known-beacon `<img>` tags,
   and neutralises beacons hidden in CSS (`background-image: url(…)` in an
   inline `style`, the legacy `background="…"` attribute) when the URL is a
   known beacon host or is fetched by a hidden / 1×1 element.
2. **Hyperlink-auditing removal** — strips the `ping` attribute from `<a>`/
   `<area>`, which would otherwise fire a hidden POST beacon on every click.
3. **Tracking query-parameter stripping** — `utm_*`, `fbclid`, `gclid`,
   `mc_cid`, `_hsenc`, … (configurable, case-insensitive; `prefix*` supported).
4. **Vendor-specific URL cleaning** — host-scoped rules for Amazon (`pf_rd_*`,
   `tag`, …), YouTube (`si`), eBay (`_trkparms`), Twitter/X, LinkedIn, Reddit,
   TikTok and more, shipped in the built-in rule pack.
5. **First-stage ESP redirect unwrapping** — SendGrid, Mailchimp, Mandrill,
   Constant Contact, HubSpot, Customer.io, Iterable, Klaviyo, Mailgun,
   Brevo/Sendinblue, Postmark, SparkPost — **only** when the destination is
   explicitly embedded in the link and passes validation.

It is also **sender-aware**:

* **Per-sender policies** — config rules keyed by the `From:` domain can switch
  mode or toggle individual features per sender.
* **Sensitive-sender protection** — for built-in identity/payment/auth senders,
  link rewriting and redirect unwrapping are skipped so magic-login / 2FA /
  password-reset links never break (pixel removal still applies).
* **List-Unsubscribe handling** — the unsubscribe link is treated as sensitive
  and left byte-for-byte intact (its recipient token survives); its target can
  be surfaced in an `X-Privacy-Cleaner-Unsubscribe` header.

A network redirect resolver and HTTP(S) rule-pack fetching are compiled in by
default (the `network` cargo feature), but both stay **inert unless you opt in**
at runtime, and the resolver is heavily SSRF-guarded. See
[the note on the network feature](#note-on-the-network-feature) to build them
out entirely.

> No network access during cleaning. No JavaScript execution. No image
> fetching. Attachments are never altered. The per-message cleaning path is
> deterministic and bounded — suitable for the synchronous SMTP DATA stage.

## Crate layout

```
email_privacy_cleaner          (library crate)
├── config        CleanerConfig (TOML), sender policies, rule-pack loading
├── ruleset       ClearURLs-format rule engine (built-in + external packs)
├── url_clean     clean_url()              — query-param + vendor stripping
├── redirect      unwrap_redirect_url()    — offline ESP unwrapping
├── validate      destination validation + SSRF IP blocking
├── html          clean_html()             — lol_html-based rewriting
├── encoding      QP / base64 / charset re-encoding
├── mime          clean_message()          — byte-surgical MIME rewriting
├── network       optional resolver (feature = "network", off by default)
└── milter        Sendmail/Postfix milter-protocol server

binaries:
  email-privacy-cleaner   CLI (clean / explain / diff / print-trackers)
  email-privacy-milter    milter daemon
```

### Public API

```rust
use email_privacy_cleaner::{
    clean_message, clean_html, clean_url, unwrap_redirect_url, CleanerConfig,
};

let cfg = CleanerConfig::default();
let result = clean_message(raw_eml_bytes, &cfg)?;
// result.cleaned        -> full message incl. audit headers
// result.body           -> body region only (used by the milter for REPLBODY)
// result.audit_headers  -> Vec<(name, value)>
// result.stats          -> CleanStats { html_parts, urls_cleaned, .. }
```

## How body rewriting preserves the message

`mail-parser` records the byte offsets of every MIME part. We re-encode **only**
the `text/html` (and optionally `text/plain`) body parts and splice the new
bytes back into the original message in place — headers, MIME boundaries,
attachments and nested parts are preserved verbatim. Modified parts are
re-encoded using the part's original `Content-Transfer-Encoding`
(7bit / quoted-printable / base64) and declared charset.

Because the body is modified, an `X-Privacy-Cleaner-Body-Modified: yes` header
is added so downstream DKIM expectations are explicit (the body hash will change
when the cleaner is positioned before signing, or signatures should be applied
after cleaning).

## Audit headers

```
X-Privacy-Cleaner: email-privacy-cleaner/<version>
X-Privacy-Cleaner-Mode: enforce | report-only
X-Privacy-Cleaner-HTML-Parts: <n>
X-Privacy-Cleaner-URLs-Cleaned: <n>
X-Privacy-Cleaner-Redirects-Unwrapped: <n>
X-Privacy-Cleaner-Pixels-Removed: <n>          # incl. CSS background beacons
X-Privacy-Cleaner-Link-Pings-Stripped: <n>
X-Privacy-Cleaner-Body-Modified: yes | no
X-Privacy-Cleaner-Policy: default | sensitive-sender | custom:<domain>
X-Privacy-Cleaner-Unsubscribe: <url>       # when surface_unsubscribe + present
X-Privacy-Cleaner-Error: <short error>     # only on fail-open
```

## Build

```bash
cargo build --release
# binaries in target/release/{email-privacy-cleaner,email-privacy-milter}
# the `network` feature is on by default (see the note at the bottom)

# fully offline build (no networking code compiled in):
cargo build --release --no-default-features
```

## CLI usage

```bash
# Clean a full message
email-privacy-cleaner clean-message --config config.toml < raw.eml > cleaned.eml

# Clean an HTML fragment
email-privacy-cleaner clean-html --config config.toml < input.html > output.html

# Explain how one URL is treated (provider, unwrap, params)
email-privacy-cleaner explain-url "https://u1.ct.sendgrid.net/ls/click?url=https%3A%2F%2Fexample.com%2Fp%3Futm_source%3Dx"

# Explain a whole message: sender policy, per-link treatment, unsubscribe target
email-privacy-cleaner explain-message --config config.toml < raw.eml

# List the trackers detected in a message (params, ESP wrappers, pixels)
email-privacy-cleaner print-trackers < raw.eml

# Show a line diff between the original and cleaned message
email-privacy-cleaner diff-message < raw.eml

# Run the cleaner over a directory of *.eml fixtures and report
email-privacy-cleaner test-rules tests/fixtures/
```

`explain-message` example output:

```
sender:   news.example.com
policy:   default
effective: clean_query_params=true unwrap_redirects=true vendor_rules=true remove_pixels=true mode=enforce
unsubscribe: https://news.example.com/u?uid=42&tok=SECRET, mailto:unsub@news.example.com
html-parts: 1
  [1] https://shop.example.com/sale?id=1&utm_source=news
      -> CLEAN (stripped ["utm_source"]) -> https://shop.example.com/sale?id=1
  [2] https://news.example.com/u?uid=42&tok=SECRET
      -> SENSITIVE (List-Unsubscribe) — left untouched
```

`explain-url` example output:

```
input:    https://u1.ct.sendgrid.net/ls/click?url=https%3A%2F%2Fexample.com%2Fp%3Futm_source%3Dx
provider: sendgrid
unwrapped: yes -> https://example.com/p
query-clean: no tracking params
final:    https://example.com/p
```

## Running the milter

```bash
email-privacy-milter --config config.toml
# or override the listen address:
email-privacy-milter --listen 127.0.0.1:11333
```

The daemon speaks the standard Sendmail/Postfix milter protocol (version 6),
negotiates the *add headers* and *replace body* actions, accumulates the
message at the DATA stage, runs the cleaner, then emits `SMFIR_REPLBODY` +
`SMFIR_ADDHEADER` modifications.

### Stalwart integration

Stalwart can call out to a milter at the DATA stage. Point it at the daemon's
listen address (TOML config sketch):

```toml
[session.data.milter."privacy"]
enable = true
hostname = "127.0.0.1"
port = 11333
options.version = 6
options.tls = false
```

(Consult the Stalwart docs for the exact key names in your version; the milter
itself requires no Stalwart-specific behaviour beyond standard milter v6.)

Recommended rollout:

1. Start in `mode = "report-only"` — headers are added, the body is untouched.
2. Inspect `X-Privacy-Cleaner-*` headers on delivered mail.
3. Switch to `mode = "enforce"` once satisfied.

### Failure behaviour

* `fail_open = true` (default): on an internal parser error the **original**
  message is passed through unchanged with an `X-Privacy-Cleaner-Error` header.
* `fail_open = false`: the milter returns a **tempfail** so the MTA retries.

## Configuration

See [`config.example.toml`](config.example.toml) for every option with its
default. Highlights:

| Key | Default | Meaning |
|-----|---------|---------|
| `mode` | `enforce` | `enforce` or `report-only` |
| `clean_html` | `true` | rewrite text/html parts |
| `clean_text_plain` | `false` | query-clean text/plain parts |
| `remove_pixels` | `true` | drop tracking pixels |
| `neutralize_css_beacons` | `true` | neutralise CSS `background-image` / `background=` beacons (needs `remove_pixels`) |
| `strip_link_ping` | `true` | strip the hyperlink-auditing `ping` attribute |
| `clean_query_params` | `true` | strip tracking params |
| `apply_vendor_rules` | `true` | host-scoped (non-global) rule-pack rules |
| `strip_referral_marketing` | `false` | also strip `referralMarketing` params |
| `unwrap_known_redirects` | `true` | offline ESP unwrapping |
| `protect_sensitive_senders` | `true` | skip link rewriting for auth/payment senders |
| `surface_unsubscribe` | `true` | add `X-Privacy-Cleaner-Unsubscribe` header |
| `sender_policies` | `[]` | per-sender overrides (first match wins) |
| `network_redirect_resolution` | `false` | opt-in network resolver |
| `preserve_original_href` | `false` | keep original in `data-original-href` (off by default — the attribute lives in the HTML body and gets carried into recipients' replies/forwards) |
| `fail_open` | `true` | pass-through vs tempfail on error |
| `max_message_size` | 50 MiB | hard input limit |
| `max_html_part_size` | 8 MiB | per-part HTML limit |
| `blocked_domains` | `[]` | links neutralised to `about:blank` |
| `extra_tracking_params` | `[]` | merged with built-ins (`prefix*` allowed) |
| `extra_pixel_domains` | `[]` | merged with built-ins |
| `keep_params` | `[]` | params never stripped, even if a rule matches (`prefix*`) |
| `exclude_domains` | `[]` | hosts left entirely untouched (suffix match) |
| `disabled_providers` | `[]` | rule-pack provider names to switch off |
| `rule_packs` | `[]` | external ClearURLs-format pack files to merge |
| `rule_pack_urls` | `[]` | pack URLs (`file://`/paths load offline; `http(s)` needs `network`) |

## Rule packs (ClearURLs format)

The default tracking params, vendor rules, ESP redirect unwrappers and known
beacon hosts ship as a **ClearURLs-format JSON document** compiled into the
binary ([`rules/builtin.json`](rules/builtin.json)) — original work under this
crate's MIT/Apache licence. The same parser loads **external packs** (file paths
via `rule_packs`, or URLs via `rule_pack_urls` with the `network` feature) and
**merges** them on top of the built-ins, so coverage can be extended without
code changes — including with the upstream [ClearURLs](https://clearurls.xyz)
`data.min.json`.

Supported per provider: `urlPattern`, `rules` (param-name regexes),
`referralMarketing`, `rawRules`, `exceptions`, `redirections` (capture group 1
is the embedded destination, always re-validated by `validate` before any link
is rewritten), and `completeProvider` (treated as a beacon-host signal for
tracking-pixel detection only — **never** used to neutralise an `<a>` link, so
click-throughs are never broken). Regexes compile with the linear-time `regex`
crate (no catastrophic backtracking); patterns using unsupported features (e.g.
lookaround in a third-party pack) are skipped individually while the rest of the
pack still loads.

> The upstream ClearURLs rules are copyleft (LGPL); this crate ships only the
> parser, not that data. Download it and point `rule_packs`/`rule_pack_urls` at
> it if you want it.

## Redirect unwrapping

Email platforms often replace normal links with a click-tracking URL. This
project handles those redirects in two layers:

* **Offline unwrapping** is the default path. It works when the redirect URL
  already contains the real destination in a query parameter or path fragment.
  Common examples are SendGrid-style links with a `url=...` value and similar
  ESP wrappers. The destination is decoded, validated, cleaned again for
  tracking parameters, and then written back into the message. No HTTP request
  is made.
* **Network redirect resolution** is for wrappers that do **not** expose the
  destination in the URL itself. Mailchimp `list-manage.com/track/click` links
  are the typical example: the only way to discover the final URL is to ask the
  tracking server for its HTTP `Location` redirect.

Network resolution is compiled in by the default `network` cargo feature, but
it is still off at runtime. To use it, enable it explicitly and list the domains
the resolver may contact:

```toml
network_redirect_resolution = true
allowlisted_redirect_domains = [
  "list-manage.com",
  "links.trusted-esp.com",
]
```

The allowlist is intentionally strict, but it applies to hosts the resolver is
allowed to **contact**, not to every possible final website. Each contacted
redirector hop must match `allowlisted_redirect_domains` by exact host or suffix
match. If an allowlisted redirector returns a `Location` pointing at an
off-allowlist destination, that destination can be accepted after validation and
written into the message, but it is not fetched. This makes network resolution
useful for ESP click links that jump to many different merchant/news sites
without turning the cleaner into a general-purpose web crawler.

Do not add broad entries such as `com` or `net`; that would allow contacting
far more hosts than intended. Prefer specific ESP redirector domains you trust
to receive HEAD requests from the cleaner.

The resolver uses `HEAD`, follows at most 5 redirects, applies the configured
timeout, sends no cookies or auth, executes no JavaScript, and re-checks each
hop for blocked private, loopback, link-local, metadata, and other internal IP
ranges. If any check fails, the original link is kept, apart from normal query
parameter cleaning.

## Security model

* **No network by default** — stage-1 unwrapping is purely string/decoding work.
* **Redirect destinations are validated** before a link is rewritten: http/https
  only, no userinfo, no control chars, valid host, no suspicious mixed-script
  (homograph) hostnames, and **literal private/loopback/link-local/metadata IPs
  are rejected** so a visible link is never pointed at internal infrastructure.
* **Nested URL-encoding** is decoded up to depth 3; `javascript:`, `file:`,
  `data:` destinations are always rejected.
* **Optional network resolver** (when explicitly enabled): contacts only
  allowlisted redirector hosts, HEAD-first, no cookies/auth/JS, never fetches
  images, max 5 redirects, per-request timeout, and re-checks contacted hosts
  against the SSRF blocklist on every hop. Off-allowlist final `Location`
  targets are validated but not fetched.
* **Bounded memory/CPU**: size limits on the message and each HTML part; the
  HTML rewriter (`lol_html`) is streaming.

## Testing

```bash
cargo test                  # unit + integration + milter-protocol tests
cargo clippy --all-targets
```

Fixture-based coverage (`tests/fixtures/*.eml` + `tests/integration.rs`) includes:
multipart/alternative, Mailchimp / SendGrid / HubSpot links, hidden 1×1 pixels,
CSS background-image beacons and the legacy `background=` attribute, hyperlink
`ping` stripping, a legitimate small logo (and visible background) that must
survive, magic login links that must not
break, malformed HTML, quoted-printable and base64 HTML parts, a non-UTF-8
(ISO-8859-1) charset, nested URL-encoding, malicious `javascript:`/`file:`
redirects, private-IP redirect destinations, attachment preservation, and a
full milter-protocol conversation over a real socket.

## Nix / NixOS

This repo ships a production-grade flake (`flake.nix` + `nix/`).

### Build & run

```bash
nix build                       # ./result/bin/{...} — network resolver enabled
nix run  .#milter -- --listen 127.0.0.1:11333
nix run  .#cli    -- explain-url "https://..."
```

The flake exposes a **single build target with the network resolver compiled
in**. To get a fully offline binary, override the cargo feature list:

```bash
nix build --impure --expr \
  '(builtins.getFlake (toString ./.)).packages.${builtins.currentSystem}.default.override { cargoFeatures = []; }'
# or from an overlay / nixpkgs:
#   pkgs.email-privacy-cleaner.override { cargoFeatures = [ ]; }
```

Builds use [crane](https://github.com/ipetkov/crane) with a pinned stable
toolchain. Release binaries are stripped, and the source tree and compiler
wrapper are scrubbed from / asserted absent in the runtime closure
(`remove-references-to` + `disallowedReferences`). There are **no native
runtime dependencies** in either case — the network resolver's TLS is
rustls/ring, not OpenSSL.

### Checks & dev shell

```bash
nix flake check     # clippy (-D warnings), rustfmt, full test suite, module build
nix develop         # dev shell: toolchain + rust-analyzer + cargo-audit/-edit
```

`direnv allow` will auto-enter the dev shell via `.envrc`.

### NixOS module

Add the flake and import the module:

```nix
{
  inputs.email-privacy-cleaner.url = "github:tricked-dev/email-privacy-cleaner";

  outputs = { nixpkgs, email-privacy-cleaner, ... }: {
    nixosConfigurations.mail = nixpkgs.lib.nixosSystem {
      modules = [
        email-privacy-cleaner.nixosModules.default
        {
          services.email-privacy-milter = {
            enable = true;
            listen = "127.0.0.1:11333";
            settings = {
              mode = "report-only";        # flip to "enforce" once verified
              remove_pixels = true;
              clean_query_params = true;
              extra_tracking_params = [ "my_custom_tracker" ];
              # Exclusions (carve-outs that override the rule pack):
              keep_params = [ "ref" ];
              exclude_domains = [ "intranet.example" ];
              disabled_providers = [ "amazon" ];
            };
            # Declaratively prefetch external ClearURLs-format packs into the
            # store (pinned by hash) and load them offline at runtime. Works
            # alongside `settings` AND `configFile`.
            rulePacks = [
              ./my-extra-rules.json
              {
                url = "https://rules2.clearurls.xyz/data.min.json";
                sha256 = "sha256-AAAA...";   # nix will tell you the real hash
              }
            ];
          };
        }
      ];
    };
  };
}
```

The module renders `settings` to a TOML config (or accepts a `configFile`) and
runs the daemon as a hardened, stateless systemd service (`DynamicUser`,
`ProtectSystem=strict`, locked-down syscall/address-family filters, no
capabilities, loopback-only egress when listening on localhost). `rulePacks` are
prefetched at build time and passed as `--rule-pack` arguments, so they compose
with either `settings` or `configFile` and need no runtime network. Point
Stalwart at the configured `listen` address as shown in
[Stalwart integration](#stalwart-integration).

## Note on the `network` feature

The `network` cargo feature is **enabled by default**, so a stock
`cargo build` / `nix build` compiles it in. It only adds *capability*, not
behaviour: everything it enables stays inert until you opt in. The per-message
cleaning path remains fully offline unless `network_redirect_resolution = true`
is set.

Building with `--no-default-features` drops the networking code entirely. The
only things unavailable in that build are:

* the optional network **redirect resolver** (`network_redirect_resolution`); and
* fetching `http(s)://` entries in `rule_pack_urls`.

Everything else is unchanged — including `file://` and local-path rule packs,
which still load offline. (The resolver is also off at runtime by default even
when compiled in, so a default build behaves identically until you flip
`network_redirect_resolution = true` or add an `http(s)://` rule-pack URL.)

## License

MIT OR Apache-2.0

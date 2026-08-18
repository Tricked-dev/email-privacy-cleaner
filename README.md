# email-privacy-cleaner

`email-privacy-cleaner` removes common email tracking mechanisms before a
message reaches the recipient. It can run as a pre-queue milter for
[Stalwart](https://stalw.art) or as a command-line tool for inspecting and
cleaning `.eml` files and HTML.

Cleaning is deterministic and offline by default:

- removes hidden, 1x1, and known-beacon images, including CSS background
  beacons;
- removes the `ping` attribute from links;
- strips global tracking parameters such as `utm_*`, `fbclid`, `gclid`,
  `mc_cid`, and `_hsenc`;
- applies host-specific rules for services such as Amazon, YouTube, eBay,
  Twitter/X, LinkedIn, Reddit, and TikTok;
- unwraps supported ESP click redirects when the destination is embedded in
  the URL, without contacting the redirector;
- preserves `List-Unsubscribe` targets and protects built-in authentication,
  identity, and payment senders from link rewriting;
- supports per-sender policies, exclusions, custom tracking parameters, and
  external rule packs; and
- adds `X-Privacy-Cleaner-*` audit headers so operators can see what happened.

No JavaScript is executed, no image is fetched, and attachments are not
altered. Optional startup rule-pack downloads and per-message redirect
resolution are described in [Network and offline behavior](#network-and-offline-behavior).

## What changes

### URL example

Before:

```text
https://shop.example/products/42?utm_source=newsletter&color=blue&fbclid=recipient123
```

After:

```text
https://shop.example/products/42?color=blue
```

The useful `color` parameter survives while `utm_source` and `fbclid` are
removed.

### Message example

A tracked message body can contain an ESP wrapper:

```eml
From: Store <store@shop.example>
To: User <user@example.org>
Content-Type: text/html; charset=utf-8

<a href="https://u1234.ct.sendgrid.net/ls/click?upn=abcdef&url=https%3A%2F%2Fwww.example.com%2Fdeals%3Futm_source%3Demail%26utm_campaign%3Dspring">See the deals</a>
```

The cleaned message keeps the visible destination and records the rewrite:

```eml
From: Store <store@shop.example>
To: User <user@example.org>
Content-Type: text/html; charset=utf-8
X-Privacy-Cleaner-Mode: enforce
X-Privacy-Cleaner-Redirects-Unwrapped: 1
X-Privacy-Cleaner-Body-Modified: yes
X-Privacy-Cleaner-Policy: default

<a href="https://www.example.com/deals">See the deals</a>
```

The full output also contains counts for inspected HTML parts, cleaned URLs,
removed pixels, and stripped link pings.

## Installation

The repository provides Nix packages for 64-bit Intel and ARM Linux and macOS,
a Cargo source build validated by Linux CI with Rust 1.75 and stable, and a
Linux container build. It does not define Homebrew, apt/dnf, crates.io, Windows,
or downloadable macOS binary installation paths.

### Nix: Linux and macOS

The flake exposes packages and apps for `x86_64-linux`, `aarch64-linux`,
`x86_64-darwin`, and `aarch64-darwin`:

```bash
nix profile install github:Tricked-dev/email-privacy-cleaner
email-privacy-cleaner --version
email-privacy-milter --help
```

Run without installing:

```bash
nix run github:Tricked-dev/email-privacy-cleaner#cli -- explain-url \
  'https://example.com/article?utm_source=email&id=42'
```

The default Nix app is the milter. The named `cli` and `milter` apps avoid any
ambiguity.

### Build from source with Cargo

Install Rust 1.75 or newer, then build and install both binaries from a checkout:

```bash
git clone https://github.com/Tricked-dev/email-privacy-cleaner.git
cd email-privacy-cleaner
cargo install --locked --path .
```

Linux is exercised directly by the Cargo workflows. The macOS package route
supported by repository configuration is Nix; there is no Windows CI or package
definition.

### Linux container

Build the checked-out source with the supplied multi-stage Dockerfile:

```bash
docker build --tag email-privacy-cleaner .
docker run --rm --publish 127.0.0.1:11333:11333 email-privacy-cleaner
```

The image runs as a non-root user, starts `email-privacy-milter`, and listens on
`0.0.0.0:11333` inside the container. Use the included CLI by overriding the
entrypoint:

```bash
docker run --rm -i \
  --entrypoint /usr/local/bin/email-privacy-cleaner \
  email-privacy-cleaner clean-message < raw.eml > cleaned.eml
```

The repository also defines a GHCR publishing workflow and a Linux x86_64
binary artifact, but a particular image tag or workflow artifact may not be
published. Building from the checkout is
the reproducible container installation path documented here.

## First run

Start with report-only mode so the cleaner adds audit headers without modifying
the message body:

```bash
cp config.example.toml config.toml
```

Change the first setting in `config.toml` to:

```toml
mode = "report-only"
```

Then inspect a message:

```bash
email-privacy-cleaner explain-message --config config.toml < raw.eml
email-privacy-cleaner clean-message --config config.toml < raw.eml > inspected.eml
```

Review the `X-Privacy-Cleaner-*` headers in `inspected.eml`. Switch to
`mode = "enforce"` only after representative authentication, payment,
newsletter, and unsubscribe messages behave as expected.

## CLI

The CLI reads messages or HTML from standard input and writes cleaned content
to standard output. Diagnostics and summaries go to standard error.

```bash
# Clean a complete RFC 5322 message.
email-privacy-cleaner clean-message --config config.toml < raw.eml > cleaned.eml

# Preview a line diff without replacing the source file.
email-privacy-cleaner diff-message --config config.toml < raw.eml

# Explain sender policy, links, pixels, unsubscribe handling, and audit headers.
email-privacy-cleaner explain-message --config config.toml < raw.eml

# Explain one URL.
email-privacy-cleaner explain-url \
  'https://example.com/article?utm_source=email&id=42'

# List trackers detected in a message.
email-privacy-cleaner print-trackers --config config.toml < raw.eml

# Clean an HTML fragment. --base-url can resolve relative links.
email-privacy-cleaner clean-html --config config.toml \
  --base-url 'https://example.com/news/' < input.html > output.html

# Inspect compiled rule counts and source diagnostics.
email-privacy-cleaner rule-stats --config config.toml
email-privacy-cleaner rule-stats --config config.toml --json

# Apply an additional local ClearURLs-format pack for this invocation.
email-privacy-cleaner --rule-pack /etc/email-privacy-cleaner/extra.json \
  explain-message --config config.toml < raw.eml
```

`--rule-pack` is global and repeatable. It augments packs from the config rather
than replacing them.

## Configuration

[`config.example.toml`](config.example.toml) is the authoritative, commented
list of settings and built-in defaults. All keys are optional.

| Setting | Default | Effect |
| --- | --- | --- |
| `mode` | `enforce` | Rewrites the body; use `report-only` to emit audit headers only. |
| `clean_html` | `true` | Cleans `text/html` MIME parts. |
| `clean_text_plain` | `false` | Also cleans obvious HTTP(S) URLs in `text/plain` parts. |
| `remove_pixels` | `true` | Removes likely image beacons. |
| `neutralize_css_beacons` | `true` | Removes beacon URLs from inline CSS/background attributes when pixel removal is enabled. |
| `strip_link_ping` | `true` | Removes hyperlink-auditing `ping` attributes. |
| `clean_query_params` | `true` | Removes global tracking parameters. |
| `apply_vendor_rules` | `true` | Applies host-scoped provider rules. |
| `strip_referral_marketing` | `false` | Also removes affiliate/referral parameters. |
| `unwrap_known_redirects` | `true` | Unwraps supported redirects offline when the destination is embedded. |
| `protect_sensitive_senders` | `true` | Skips link rewriting for built-in sensitive sender domains. |
| `surface_unsubscribe` | `true` | Adds the HTTP(S) unsubscribe target to an audit header. |
| `fail_open` | `true` | Passes the original message through with an error header on internal failure. |
| `max_message_size` | 50 MiB | Rejects processing beyond the total input limit. |
| `max_html_part_size` | 8 MiB | Skips oversized HTML parts and reports the skip. |
| `network_redirect_resolution` | `false` | Enables allowlisted per-message HTTP redirect resolution. |

Common customization:

```toml
extra_tracking_params = ["my_campaign_id", "mkt_*"]
extra_pixel_domains = ["beacon.example"]

# Carve-outs override built-in and external rules.
keep_params = ["ref"]
exclude_domains = ["intranet.example"]
disabled_providers = ["amazon"]

[[sender_policies]]
match_domains = ["accounts.example"]
no_modify = true
```

Patterns ending in `*` are prefix matches. Domain settings use suffix matching,
so `intranet.example` also covers its subdomains. Sender policies are evaluated
in order; the first match wins.

`preserve_original_href` and `debug_preserve_removed` are off by default. Both
place tracking material in the HTML body, where it can leak into replies and
forwards, so they are intended for deliberate debugging only.

## External rule packs

The binary includes an original built-in ruleset from
[`rules/builtin.json`](rules/builtin.json). External packs augment it; they do
not replace the built-ins. Supported inputs are:

- ClearURLs Rules JSON;
- Brave Clean URLs JSON;
- Brave Debounce JSON; and
- the supported AdGuard filter subset.

### Local pack: recommended

Download and review a pack separately, save it at a stable path, and configure
its format explicitly:

```toml
[[rule_pack_sources]]
source = "/etc/email-privacy-cleaner/clearurls.json"
format = "clear-urls"
```

Confirm that it loaded before starting the milter:

```bash
email-privacy-cleaner rule-stats --config config.toml
```

The `rule_packs = ["/path/to/pack.json"]` setting and the repeatable
`--rule-pack /path/to/pack.json` option are supported; both always interpret
the input as ClearURLs JSON.

### HTTPS source at startup

A default build includes HTTPS fetching capability. To fetch a pack once while
configuration is finalized at startup:

```toml
[[rule_pack_sources]]
url = "https://rules2.clearurls.xyz/data.min.json"
format = "clear-urls"
```

The source is not fetched per message. Duplicate source strings are collapsed,
and external loading is bounded by the `[rule_limits]` values documented in
[`config.example.toml`](config.example.toml). A failed or partially unsupported
source is reported through diagnostics; unsupported individual regexes are
skipped without discarding the rest of the pack.

For AdGuard input, modifierless image rules require an explicit purpose:

```toml
[[rule_pack_sources]]
source = "/etc/email-privacy-cleaner/mail-beacons.txt"
format = "adguard"
usage = "mail-beacon"
```

`mail-beacon` only admits applicable image-beacon rules. It does not turn
browser preferences or ordinary link rules into email rules.

### Reproducible NixOS pack setup

Prefetch a remote file and copy the reported `hash` into the module setting:

```bash
nix store prefetch-file --json \
  https://rules2.clearurls.xyz/data.min.json
```

```nix
services.email-privacy-milter.rulePacks = [
  {
    url = "https://rules2.clearurls.xyz/data.min.json";
    sha256 = "sha256-REPLACE-WITH-THE-REPORTED-HASH";
  }
];
```

Nix fetches the content by hash during the build and the daemon reads it from
the store at startup. This composes with either `settings` or `configFile` and
does not require rule-pack network access from the service.

External data is not bundled. Review its behavior and license before use; see
[Licensing](#licensing).

## Running the milter

The daemon speaks milter protocol version 6 over TCP. It accumulates a message
at the SMTP DATA stage, then requests body replacement and audit-header
additions from the MTA.

```bash
email-privacy-milter --config config.toml --listen 127.0.0.1:11333
```

`--listen` overrides the config value. `--rule-pack PATH` is repeatable and
augments configured ClearURLs-format packs.

### Stalwart

Point Stalwart's DATA-stage milter integration at the daemon. The existing
repository configuration uses this shape:

```toml
[session.data.milter."privacy"]
enable = true
hostname = "127.0.0.1"
port = 11333
options.version = 6
options.tls = false
```

Stalwart configuration keys can differ by release; check the documentation for
the deployed Stalwart version. The cleaner only requires a standard milter v6
connection.

Recommended rollout:

1. Run with `mode = "report-only"`.
2. Inspect delivered `X-Privacy-Cleaner-*` headers across representative mail.
3. Switch to `mode = "enforce"`.
4. Keep the cleaner before DKIM signing, or re-sign the modified message after
   cleaning.

With `fail_open = true` (the default), an internal processing error passes the
original body through and adds `X-Privacy-Cleaner-Error`. With `fail_open =
false`, the milter returns a temporary failure so the MTA can retry.

### NixOS service

The flake exports `nixosModules.default` and
`nixosModules.email-privacy-milter`:

```nix
{
  inputs.email-privacy-cleaner.url =
    "github:Tricked-dev/email-privacy-cleaner";

  outputs = { nixpkgs, email-privacy-cleaner, ... }: {
    nixosConfigurations.mail = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        email-privacy-cleaner.nixosModules.default
        {
          services.email-privacy-milter = {
            enable = true;
            listen = "127.0.0.1:11333";
            settings = {
              mode = "report-only";
              remove_pixels = true;
              clean_query_params = true;
            };
          };
        }
      ];
    };
  };
}
```

Use `configFile` instead of `settings` for a pre-written TOML file; setting both
is rejected. `openFirewall` defaults to `false`, which is appropriate for the
usual loopback connection. The module runs the daemon as a dynamic user with a
read-only filesystem, no capabilities, resource ceilings, and systemd network
restrictions. When listening on loopback, the service itself is restricted to
loopback networking; use `rulePacks` for build-time remote pack fetching.

## Audit headers

Every processed message receives the applicable subset of:

```text
X-Privacy-Cleaner: email-privacy-cleaner/<version>
X-Privacy-Cleaner-Mode: enforce | report-only
X-Privacy-Cleaner-HTML-Parts: <n>
X-Privacy-Cleaner-URLs-Cleaned: <n>
X-Privacy-Cleaner-Redirects-Unwrapped: <n>
X-Privacy-Cleaner-Pixels-Removed: <n>
X-Privacy-Cleaner-Link-Pings-Stripped: <n>
X-Privacy-Cleaner-Body-Modified: yes | no
X-Privacy-Cleaner-Policy: default | sensitive-sender | custom:<domain>
X-Privacy-Cleaner-Skipped-Oversized-Parts: <n>
X-Privacy-Cleaner-Cte-Mismatch-Parts: <n>
X-Privacy-Cleaner-Unencodable-Parts: <n>
X-Privacy-Cleaner-Unsubscribe: <url>
X-Privacy-Cleaner-Error: <short error>
```

Optional headers only appear when relevant. Values derived from input are
sanitized before being placed in headers.

## Network and offline behavior

The Cargo `network` feature is enabled in normal Cargo, Nix, and container
builds. It compiles capability; it does not enable network behavior by itself.

With the default configuration:

- cleaning does not make network requests;
- images are never fetched;
- known ESP redirects are only unwrapped when their destination is already
  encoded in the link; and
- built-in and local rule packs load without network access.

Two settings can introduce network access:

1. An HTTP(S) `rule_pack_sources` or `rule_pack_urls` entry is fetched once at
   startup.
2. `network_redirect_resolution = true` permits per-message HEAD requests to
   hosts in `allowlisted_redirect_domains`.

Network redirect resolution follows at most five redirects, sends no cookies
or authentication, executes no JavaScript, and validates every contacted hop
against private, loopback, link-local, metadata, and other blocked IP ranges.
An off-allowlist final `Location` may be accepted after URL validation, but it
is not fetched. If validation or resolution fails, the original destination is
kept apart from ordinary query-parameter cleaning.

Use narrow redirector domains:

```toml
network_redirect_resolution = true
allowlisted_redirect_domains = [
  "list-manage.com",
  "links.trusted-esp.example",
]
```

Do not allowlist broad suffixes such as `com` or `net`.

To compile networking code out entirely when installing from source:

```bash
cargo install --locked --path . --no-default-features
```

Local paths and `file://` rule packs continue to work in that build. HTTP(S)
pack fetching and network redirect resolution do not.

## Safety boundaries

- The default only rewrites `text/html`; `text/plain` cleaning is opt-in.
- MIME boundaries, attachments, and unmodified parts are preserved. Modified
  body parts are re-encoded using their original transfer encoding and declared
  charset when possible.
- Existing DKIM body signatures will no longer match a modified body. Place the
  cleaner before signing or re-sign afterward.
- `List-Unsubscribe` links are treated as sensitive and left unchanged. Their
  HTTP(S) target can be surfaced in an audit header.
- Built-in sensitive-sender protection reduces risk to login, 2FA, reset, and
  payment links, but it cannot know every sender. Use report-only rollout,
  `sender_policies`, `keep_params`, and `exclude_domains` for local exceptions.
- `blocked_domains` intentionally changes matching links to `about:blank`.
- `fail_open` protects mail flow from internal parser errors; it does not make
  an unsafe third-party rule pack safe.
- This is a tracker sanitizer, not an antivirus, spam filter, phishing detector,
  or guarantee that a destination is trustworthy.

## Licensing

The project code and built-in rules are available under either the
[MIT license](LICENSE-MIT) or the [Apache License 2.0](LICENSE-APACHE).

Third-party rule data is separate and is not bundled. ClearURLs Rules data is
LGPL-3.0, Brave list data is MPL-2.0, and the AdGuard corpus is GPL-3.0. Loading
an external pack does not relicense that data; review and comply with its own
terms when distributing or deploying it.

## Contributing and design

Development, test, benchmark, and release notes are in
[`CONTRIBUTING.md`](CONTRIBUTING.md). The rule-engine design detail lives in
[`RULESET_REFACTOR_PLAN.md`](RULESET_REFACTOR_PLAN.md).

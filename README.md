# email-privacy-cleaner

A reusable **Rust library** plus a **milter daemon** that sanitise the
privacy-invasive parts of email, designed to run as a pre-queue milter for the
[Stalwart](https://stalw.art) mail server at the SMTP **DATA** stage (but usable
standalone via the CLI).

It performs three independent, deterministic, **offline** transformations:

1. **Tracking-pixel removal** — drops 1×1 / hidden / known-beacon `<img>` tags.
2. **Tracking query-parameter stripping** — `utm_*`, `fbclid`, `gclid`,
   `mc_cid`, `_hsenc`, … (configurable, case-insensitive).
3. **First-stage ESP redirect unwrapping** — SendGrid, Mailchimp, Mandrill,
   Constant Contact, HubSpot, Customer.io, Iterable, Klaviyo, Mailgun,
   Brevo/Sendinblue, Postmark, SparkPost — **only** when the destination is
   explicitly embedded in the link and passes validation.

An optional, **opt-in** network redirect resolver exists behind the `network`
cargo feature; it is disabled by default and heavily SSRF-guarded.

> No network access. No JavaScript execution. No image fetching. Attachments
> are never altered. The cleaning path is deterministic and bounded — suitable
> for the synchronous SMTP DATA stage.

## Crate layout

```
email_privacy_cleaner          (library crate)
├── config        CleanerConfig (TOML), tracking-param / pixel-domain tables
├── url_clean     clean_url()              — query-param stripping
├── redirect      unwrap_redirect_url()    — offline ESP unwrapping
├── validate      destination validation + SSRF IP blocking
├── html          clean_html()             — lol_html-based rewriting
├── encoding      QP / base64 / charset re-encoding
├── mime          clean_message()          — byte-surgical MIME rewriting
├── network       optional resolver (feature = "network", off by default)
└── milter        Sendmail/Postfix milter-protocol server

binaries:
  email-privacy-cleaner   CLI
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
X-Privacy-Cleaner-Pixels-Removed: <n>
X-Privacy-Cleaner-Body-Modified: yes | no
X-Privacy-Cleaner-Error: <short error>     # only on fail-open
```

## Build

```bash
cargo build --release
# binaries in target/release/{email-privacy-cleaner,email-privacy-milter}

# with the optional network resolver compiled in:
cargo build --release --features network
```

## CLI usage

```bash
# Clean a full message
email-privacy-cleaner clean-message --config config.toml < raw.eml > cleaned.eml

# Clean an HTML fragment
email-privacy-cleaner clean-html --config config.toml < input.html > output.html

# Explain how one URL is treated (provider, unwrap, params)
email-privacy-cleaner explain-url "https://u1.ct.sendgrid.net/ls/click?url=https%3A%2F%2Fexample.com%2Fp%3Futm_source%3Dx"

# Run the cleaner over a directory of *.eml fixtures and report
email-privacy-cleaner test-rules tests/fixtures/
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
| `clean_query_params` | `true` | strip tracking params |
| `unwrap_known_redirects` | `true` | offline ESP unwrapping |
| `network_redirect_resolution` | `false` | opt-in network resolver |
| `preserve_original_href` | `true` | keep original in `data-original-href` |
| `fail_open` | `true` | pass-through vs tempfail on error |
| `max_message_size` | 50 MiB | hard input limit |
| `max_html_part_size` | 8 MiB | per-part HTML limit |
| `blocked_domains` | `[]` | links neutralised to `about:blank` |
| `extra_tracking_params` | `[]` | merged with built-ins |
| `extra_pixel_domains` | `[]` | merged with built-ins |

## Security model

* **No network by default** — stage-1 unwrapping is purely string/decoding work.
* **Redirect destinations are validated** before a link is rewritten: http/https
  only, no userinfo, no control chars, valid host, no suspicious mixed-script
  (homograph) hostnames, and **literal private/loopback/link-local/metadata IPs
  are rejected** so a visible link is never pointed at internal infrastructure.
* **Nested URL-encoding** is decoded up to depth 3; `javascript:`, `file:`,
  `data:` destinations are always rejected.
* **Optional network resolver** (when explicitly enabled): allowlist-only,
  HEAD-first, no cookies/auth/JS, never fetches images, max 5 redirects,
  per-request timeout, and re-checks resolved IPs against the SSRF blocklist on
  every hop.
* **Bounded memory/CPU**: size limits on the message and each HTML part; the
  HTML rewriter (`lol_html`) is streaming.

## Testing

```bash
cargo test                  # unit + integration + milter-protocol tests
cargo clippy --all-targets
```

Fixture-based coverage (`tests/fixtures/*.eml` + `tests/integration.rs`) includes:
multipart/alternative, Mailchimp / SendGrid / HubSpot links, hidden 1×1 pixels,
a legitimate small logo that must survive, magic login links that must not
break, malformed HTML, quoted-printable and base64 HTML parts, a non-UTF-8
(ISO-8859-1) charset, nested URL-encoding, malicious `javascript:`/`file:`
redirects, private-IP redirect destinations, attachment preservation, and a
full milter-protocol conversation over a real socket.

## Nix / NixOS

This repo ships a production-grade flake (`flake.nix` + `nix/`).

### Build & run

```bash
nix build                       # offline build -> ./result/bin/{...}
nix build .#email-privacy-cleaner-network   # with the opt-in network resolver
nix run  .#milter -- --listen 127.0.0.1:11333
nix run  .#cli    -- explain-url "https://..."
```

Builds use [crane](https://github.com/ipetkov/crane) with a pinned stable
toolchain. Release binaries are stripped, and the source tree and compiler
wrapper are scrubbed from / asserted absent in the runtime closure
(`remove-references-to` + `disallowedReferences`). The default build has **no
native runtime dependencies** (TLS in the `network` variant is rustls/ring, not
OpenSSL).

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
  inputs.email-privacy-cleaner.url = "github:tricked-dev/mail-milter";

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
            };
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
capabilities, loopback-only egress when listening on localhost). Point Stalwart
at the configured `listen` address as shown in
[Stalwart integration](#stalwart-integration).

## License

MIT OR Apache-2.0

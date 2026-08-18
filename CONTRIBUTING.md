# Contributing

Thank you for improving `email-privacy-cleaner`. This document covers the
development workflow, source layout, tests, diagnostics, and release automation.
End-user installation and operation belong in [`README.md`](README.md).

## Development environment

The repository pins its Rust toolchain and development tools with Nix:

```bash
nix develop
```

With nix-direnv installed, the checked-in [`.envrc`](.envrc) provides the same
shell after:

```bash
direnv allow
```

Cargo metadata declares Rust 1.75 as the minimum supported Rust version. CI
checks both 1.75 and stable on Linux. Contributors who do not use Nix must
install Rust, rustfmt, and Clippy themselves.

## Source map

```text
src/lib.rs                         public library entry points
src/config.rs                      TOML configuration and sender policies
src/ruleset.rs                     indexed rules and external source loading
src/url_clean.rs                   query and provider-specific URL cleaning
src/redirect.rs                    offline ESP redirect unwrapping
src/validate.rs                    URL and SSRF validation
src/html.rs                        streaming HTML rewriting
src/encoding.rs                    charset and transfer encoding handling
src/mime.rs                        byte-preserving MIME/message rewriting
src/network.rs                     optional network redirect resolver
src/milter.rs                      milter protocol server
src/bin/email-privacy-cleaner.rs   CLI
src/bin/email-privacy-milter.rs    daemon
rules/builtin.json                 built-in rules
tests/fixtures/                    synthetic message fixtures
```

The detailed rule-engine contract, supported external formats, limits, and
rule-engine rationale live in
[`RULESET_REFACTOR_PLAN.md`](RULESET_REFACTOR_PLAN.md). Keep design detail there
instead of duplicating it in general project files.

## Public library API

The package contains a reusable Rust library in addition to the two binaries:

```rust
use email_privacy_cleaner::{clean_message, CleanerConfig};

let config = CleanerConfig::default();
let result = clean_message(raw_eml_bytes, &config)?;

// result.cleaned: complete message with audit headers
// result.body: body region used by the milter for replacement
// result.audit_headers: generated header name/value pairs
// result.stats: cleaning counters
```

Body rewriting uses parser-provided MIME offsets and replaces only selected
body parts. Changes to parsing or encoding must preserve boundaries,
attachments, untouched parts, header safety, and the fail-open contract.

## Local checks

Enter `nix develop` first, then run the same Rust commands used by CI:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo build --locked --all-targets
cargo build --locked --no-default-features
cargo test --locked --all-features
cargo test --locked --no-default-features
```

The full Nix gate builds the package and evaluates the formatter, Clippy, test,
app, overlay, and module outputs:

```bash
nix flake check
```

Useful focused suites include:

```bash
cargo test --test integration
cargo test --test milter_protocol
cargo test --test rule_loading
cargo test --test rule_formats
cargo test --test rule_safety
```

No dedicated Markdown linter or link checker is configured in
the repository. For documentation changes, inspect rendered Markdown, verify
every relative path and command, and run:

```bash
git diff --check
```

## Tests and fixtures

Add synthetic `.eml` fixtures under [`tests/fixtures/`](tests/fixtures/) when a
behavior is best demonstrated end to end. Do not commit real recipient data,
live tokens, or private messages.

Regression coverage should protect both sides of a cleaning rule:

- the tracker or wrapper that must be removed;
- nearby legitimate parameters, links, images, MIME parts, and headers that
  must survive;
- report-only and enforce behavior when applicable;
- default-feature and `--no-default-features` builds for network-related work;
- malformed, oversized, incorrectly encoded, and fail-open inputs for parser or
  encoding changes; and
- milter protocol behavior when the daemon-facing contract changes.

External rule-pack changes should cover format detection or explicit format,
source limits, diagnostics, duplicate handling, unsupported regexes, provider
exceptions, and context restrictions. Ordinary anchor links must never inherit
image-beacon blocking behavior.

The programs in [`examples/`](examples/) are small reproductions for MIME,
quoted-printable, pixel, and header-edge investigations. They are developer
diagnostics, not supported end-user interfaces.

## Rule-engine baseline diagnostic

[`tests/rule_engine_baseline.rs`](tests/rule_engine_baseline.rs) contains an
ignored, fixed-seed synthetic workload for build, match, and full-message
baselines:

```bash
cargo test --test rule_engine_baseline -- \
  --ignored --nocapture --test-threads=1
```

It reports elapsed microseconds and deterministic work counts. Timing is a
diagnostic, not a stable assertion or a CI performance promise. Run it on a
quiet machine, record the toolchain and hardware, and compare multiple runs
when investigating a regression.

`email-privacy-cleaner rule-stats --json` reports compiled counts and bounded
source diagnostics for manual inspection and benchmark runs.

## Documentation changes

Keep [`README.md`](README.md) focused on operators and end users. Installation
claims must be backed by the available flake outputs, NixOS module, Cargo
metadata, binaries, Dockerfiles, or workflows. Do not imply that a registry
package, image tag, workflow artifact, or operating system is supported merely
because it would probably work.

When adding an option:

1. document every key and default in
   [`config.example.toml`](config.example.toml);
2. update the README only when the option matters to normal operation or
   safety;
3. keep detailed rule-engine design in
   [`RULESET_REFACTOR_PLAN.md`](RULESET_REFACTOR_PLAN.md); and
4. make examples use reserved domains and non-secret synthetic values.

## Release automation

The repository has two GitHub Actions workflows:

- [`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs the Rust matrix on
  Rust 1.75 and stable, followed by `nix flake check`. Its branch filters target
  `master`.
- [`.github/workflows/docker.yml`](.github/workflows/docker.yml) builds release
  binaries on Linux, pushes a GHCR image, and uploads an
  `email-privacy-cleaner-linux-x86_64` artifact. Its branch filter targets
  `main` and it also runs for `v*` tags.

That `master`/`main` difference is part of the repository workflow. Do not claim
that a default-branch push refreshed `latest` without checking an actual Docker
workflow run. Tags and registry publication are maintainer actions; a local
build or test does not establish that a release was published.

Before a release, maintainers should verify the version and package metadata in
[`Cargo.toml`](Cargo.toml), run the complete Rust and Nix gates, review
user-visible changes in the README, and confirm the resulting workflow and
registry state. Do not commit staged binaries produced for the container
workflow.

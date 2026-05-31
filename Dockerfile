# syntax=docker/dockerfile:1.7
#
# Multi-stage build for email-privacy-cleaner: a Rust toolchain image compiles
# the binaries, then a distroless cc image runs them. The default ENTRYPOINT
# is the milter daemon (binds to 0.0.0.0:11333 so it's reachable inside
# container networks); the CLI is also installed at /usr/local/bin and can be
# invoked by overriding the entrypoint.

# ---------- Builder ----------
FROM rust:1.83-bookworm AS builder

WORKDIR /build

# Layer 1: cache the dependency graph independently of the source. We copy
# manifests, stub out the binary targets, and run a release build so the cargo
# index + compiled dependencies live in their own image layer.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src/bin && \
    echo 'fn main() {}'        > src/bin/email-privacy-cleaner.rs && \
    echo 'fn main() {}'        > src/bin/email-privacy-milter.rs && \
    echo 'pub fn _stub() {}'   > src/lib.rs && \
    cargo build --release --locked && \
    rm -rf src \
           target/release/deps/email_privacy_cleaner* \
           target/release/deps/email_privacy* \
           target/release/email-privacy-cleaner \
           target/release/email-privacy-milter

# Layer 2: the real source. Only this layer changes when code changes.
COPY src/   src/
COPY rules/ rules/
RUN cargo build --release --locked && \
    strip target/release/email-privacy-cleaner \
          target/release/email-privacy-milter

# ---------- Runtime ----------
FROM gcr.io/distroless/cc-debian12:nonroot

# OCI labels — GHCR reads org.opencontainers.image.source/description for the
# package's docs panel.
LABEL org.opencontainers.image.title="email-privacy-cleaner" \
      org.opencontainers.image.description="Pre-queue email privacy milter for Stalwart Mail Server. Strips tracking pixels, cleans tracking query params, unwraps ESP redirect links. Includes a CLI for offline testing." \
      org.opencontainers.image.source="https://github.com/tricked-dev/email-privacy-cleaner" \
      org.opencontainers.image.documentation="https://github.com/tricked-dev/email-privacy-cleaner#readme" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0" \
      org.opencontainers.image.vendor="tricked-dev"

COPY --from=builder /build/target/release/email-privacy-milter  /usr/local/bin/email-privacy-milter
COPY --from=builder /build/target/release/email-privacy-cleaner /usr/local/bin/email-privacy-cleaner

# Milter protocol port. Stalwart connects here.
EXPOSE 11333

# Default: run the milter daemon, binding to all interfaces so the container
# is reachable from a sibling container on the same network. Override the
# entrypoint to use the CLI:
#   docker run --rm -i --entrypoint /usr/local/bin/email-privacy-cleaner \
#     ghcr.io/tricked-dev/email-privacy-cleaner clean-message < raw.eml
ENTRYPOINT ["/usr/local/bin/email-privacy-milter"]
CMD ["--listen", "0.0.0.0:11333"]

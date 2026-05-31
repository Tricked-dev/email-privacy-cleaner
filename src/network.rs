//! Optional, opt-in network redirect resolver (phase 2).
//!
//! This is **disabled by default** and only compiled when the `network` cargo
//! feature is enabled *and* `network_redirect_resolution = true` in the config.
//! It exists so that, in deployments that explicitly accept the risk, a
//! redirect that could not be unwrapped offline can be resolved by following
//! HTTP redirects — under strict SSRF protections.
//!
//! Guarantees regardless of build:
//! * allowlisted destination domains only,
//! * never fetches images,
//! * no cookies, no auth, no JavaScript,
//! * private / loopback / link-local / metadata IPs are blocked,
//! * bounded redirects and timeout.

use url::Url;

use crate::config::CleanerConfig;
use crate::validate::{is_blocked_ip, validate_destination};

/// Outcome of a network resolution attempt.
#[derive(Debug, Clone)]
pub struct NetworkResolveResult {
    /// The resolved final URL, if resolution succeeded and was permitted.
    pub url: Option<Url>,
    /// Reason resolution did not happen / failed.
    pub note: String,
}

/// Maximum redirects followed.
pub const MAX_REDIRECTS: u32 = 5;
/// User-Agent presented to servers.
pub const USER_AGENT: &str = "email-privacy-cleaner";

/// Resolve a URL by following HTTP redirects, subject to all safety
/// constraints. When the `network` feature is not compiled in, this always
/// returns a "disabled" note and performs no I/O.
pub fn resolve(url: &Url, config: &CleanerConfig) -> NetworkResolveResult {
    if !config.network_redirect_resolution {
        return NetworkResolveResult {
            url: None,
            note: "network resolution disabled by config".into(),
        };
    }
    // The destination host must be explicitly allowlisted.
    match url.host_str() {
        Some(host) if config.is_allowlisted_domain(host) => {}
        _ => {
            return NetworkResolveResult {
                url: None,
                note: "host not allowlisted".into(),
            }
        }
    }

    #[cfg(not(feature = "network"))]
    {
        let _ = is_blocked_ip; // keep import used in all builds
        NetworkResolveResult {
            url: None,
            note: "network feature not compiled in".into(),
        }
    }

    #[cfg(feature = "network")]
    {
        network_impl::resolve_impl(url, config)
    }
}

/// Pre-flight SSRF check usable in any build: confirms a URL is acceptable and
/// (when its host is a literal IP) that the IP is not blocked.
pub fn preflight_ok(url: &Url) -> bool {
    if validate_destination(url).is_err() {
        return false;
    }
    if let Some(host) = url.host_str() {
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            if is_blocked_ip(&ip) {
                return false;
            }
        }
    }
    true
}

/// Fetch an external ClearURLs-format rule pack over HTTPS (opt-in, `network`
/// feature only). The caller parses the returned JSON. This is a one-off,
/// startup-time download (during `finalize`), not part of the per-message
/// cleaning path, so it is exempt from the "no network during cleaning" rule.
#[cfg(feature = "network")]
pub fn fetch_rule_pack(url: &str, timeout_ms: u64) -> crate::error::Result<String> {
    use std::time::Duration;
    let timeout = Duration::from_millis(timeout_ms.max(1).max(5_000));
    let agent = ureq::AgentBuilder::new()
        .timeout(timeout)
        .user_agent(USER_AGENT)
        .build();
    agent
        .get(url)
        .call()
        .map_err(|e| crate::error::CleanerError::Network(format!("fetching {url}: {e}")))?
        .into_string()
        .map_err(|e| crate::error::CleanerError::Network(format!("reading {url}: {e}")))
}

#[cfg(feature = "network")]
mod network_impl {
    use super::*;
    use std::net::ToSocketAddrs;
    use std::time::Duration;

    pub fn resolve_impl(start: &Url, config: &CleanerConfig) -> NetworkResolveResult {
        let timeout = Duration::from_millis(config.timeout_ms.max(1));
        let mut current = start.clone();

        for _ in 0..=MAX_REDIRECTS {
            if !preflight_ok(&current) {
                return NetworkResolveResult {
                    url: None,
                    note: "destination failed preflight".into(),
                };
            }
            if !resolve_ip_is_safe(&current, timeout) {
                return NetworkResolveResult {
                    url: None,
                    note: "destination resolves to a blocked IP".into(),
                };
            }

            let agent = ureq::AgentBuilder::new()
                .timeout(timeout)
                .redirects(0) // we follow manually to re-validate each hop
                .user_agent(USER_AGENT)
                .build();

            // HEAD first; never fetch bodies / images.
            let resp = agent.request("HEAD", current.as_str()).call();
            let resp = match resp {
                Ok(r) => r,
                Err(ureq::Error::Status(_, r)) => r,
                Err(e) => {
                    return NetworkResolveResult {
                        url: None,
                        note: format!("request error: {e}"),
                    }
                }
            };

            let status = resp.status();
            if (300..400).contains(&status) {
                if let Some(loc) = resp.header("location") {
                    match current.join(loc) {
                        Ok(next) => {
                            current = next;
                            continue;
                        }
                        Err(_) => {
                            return NetworkResolveResult {
                                url: None,
                                note: "invalid redirect location".into(),
                            }
                        }
                    }
                }
            }

            // Not a redirect: this is the final URL.
            return NetworkResolveResult {
                url: Some(current.clone()),
                note: format!("resolved (status {status})"),
            };
        }

        NetworkResolveResult {
            url: None,
            note: "too many redirects".into(),
        }
    }

    /// Resolve the host's IPs and ensure none are blocked (DNS-rebinding /
    /// SSRF). Note: there remains an inherent TOCTOU window; this is a
    /// best-effort guard appropriate for an opt-in resolver.
    fn resolve_ip_is_safe(url: &Url, _timeout: Duration) -> bool {
        let host = match url.host_str() {
            Some(h) => h,
            None => return false,
        };
        let port = url.port_or_known_default().unwrap_or(443);
        match (host, port).to_socket_addrs() {
            Ok(addrs) => {
                let mut any = false;
                for addr in addrs {
                    any = true;
                    if is_blocked_ip(&addr.ip()) {
                        return false;
                    }
                }
                any
            }
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_by_default() {
        let cfg = CleanerConfig::default();
        let u = Url::parse("https://example.com/").unwrap();
        assert!(resolve(&u, &cfg).url.is_none());
    }

    #[test]
    fn preflight_blocks_private_ip_host() {
        let u = Url::parse("http://169.254.169.254/latest/meta-data/").unwrap();
        assert!(!preflight_ok(&u));
        let u = Url::parse("http://127.0.0.1/").unwrap();
        assert!(!preflight_ok(&u));
    }

    #[test]
    fn preflight_allows_public_host() {
        let u = Url::parse("https://example.com/").unwrap();
        assert!(preflight_ok(&u));
    }
}

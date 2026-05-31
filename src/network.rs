//! Optional, opt-in network redirect resolver (phase 2).
//!
//! This is **disabled by default** and only compiled when the `network` cargo
//! feature is enabled *and* `network_redirect_resolution = true` in the config.
//! It exists so that, in deployments that explicitly accept the risk, a
//! redirect that could not be unwrapped offline can be resolved by following
//! HTTP redirects — under strict SSRF protections.
//!
//! Guarantees regardless of build:
//! * allowlisted redirector domains only,
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
/// Maximum remote rule-pack response size.
pub const MAX_RULE_PACK_BYTES: u64 = 5 * 1024 * 1024;
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
    // The redirector host must be explicitly allowlisted before any network I/O.
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
    use std::io::Read;
    use std::time::Duration;
    let timeout = Duration::from_millis(timeout_ms.max(1));
    let agent = ureq::AgentBuilder::new()
        .timeout(timeout)
        .user_agent(USER_AGENT)
        .build();
    let resp = agent
        .get(url)
        .call()
        .map_err(|e| crate::error::CleanerError::Network(format!("fetching {url}: {e}")))?;
    let mut reader = resp.into_reader().take(MAX_RULE_PACK_BYTES + 1);
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .map_err(|e| crate::error::CleanerError::Network(format!("reading {url}: {e}")))?;
    if bytes.len() as u64 > MAX_RULE_PACK_BYTES {
        return Err(crate::error::CleanerError::Network(format!(
            "rule pack {url} exceeds {} bytes",
            MAX_RULE_PACK_BYTES
        )));
    }
    String::from_utf8(bytes)
        .map_err(|e| crate::error::CleanerError::Network(format!("decoding {url}: {e}")))
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
            // Only allowlisted redirector hosts are contacted. If an
            // allowlisted redirector points at an off-allowlist destination,
            // that Location may be returned as the final URL after validation,
            // but it is not fetched.
            match current.host_str() {
                Some(h) if config.is_allowlisted_domain(h) => {}
                _ => {
                    return NetworkResolveResult {
                        url: None,
                        note: "intermediate host not allowlisted".into(),
                    }
                }
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
                    match classify_redirect_location(&current, loc, config) {
                        Ok(RedirectHop::Follow(next)) => {
                            current = next;
                            continue;
                        }
                        Ok(RedirectHop::Final(final_url)) => {
                            return NetworkResolveResult {
                                url: Some(final_url),
                                note: "resolved to off-allowlist final location".into(),
                            };
                        }
                        Err(note) => {
                            return NetworkResolveResult {
                                url: None,
                                note: note.into(),
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

    #[derive(Debug)]
    enum RedirectHop {
        Follow(Url),
        Final(Url),
    }

    fn classify_redirect_location(
        current: &Url,
        location: &str,
        config: &CleanerConfig,
    ) -> Result<RedirectHop, &'static str> {
        let next = current
            .join(location)
            .map_err(|_| "invalid redirect location")?;
        if !preflight_ok(&next) {
            return Err("redirect location failed preflight");
        }
        match next.host_str() {
            Some(h) if config.is_allowlisted_domain(h) => Ok(RedirectHop::Follow(next)),
            Some(_) => Ok(RedirectHop::Final(next)),
            None => Err("redirect location missing host"),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn cfg() -> CleanerConfig {
            let mut c = CleanerConfig::default();
            c.network_redirect_resolution = true;
            c.allowlisted_redirect_domains = vec!["links.example".into()];
            c
        }

        #[test]
        fn off_allowlist_location_is_final_without_following() {
            let current = Url::parse("https://links.example/click/abc").unwrap();
            let hop = classify_redirect_location(
                &current,
                "https://shop.example/product?utm_source=news",
                &cfg(),
            )
            .unwrap();

            match hop {
                RedirectHop::Final(url) => {
                    assert_eq!(url.as_str(), "https://shop.example/product?utm_source=news");
                }
                RedirectHop::Follow(_) => panic!("off-allowlist destination must be final"),
            }
        }

        #[test]
        fn allowlisted_location_is_followed() {
            let current = Url::parse("https://links.example/click/abc").unwrap();
            let hop =
                classify_redirect_location(&current, "/next", &cfg()).expect("valid next hop");

            match hop {
                RedirectHop::Follow(url) => assert_eq!(url.as_str(), "https://links.example/next"),
                RedirectHop::Final(_) => panic!("allowlisted redirector should be followed"),
            }
        }

        #[test]
        fn private_ip_location_is_rejected() {
            let current = Url::parse("https://links.example/click/abc").unwrap();
            let err = classify_redirect_location(
                &current,
                "http://169.254.169.254/latest/meta-data/",
                &cfg(),
            )
            .unwrap_err();

            assert_eq!(err, "redirect location failed preflight");
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

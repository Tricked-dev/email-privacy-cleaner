//! Validation of URLs and unwrapped redirect destinations.
//!
//! These checks are deliberately conservative: a destination that fails any
//! check is rejected, and the caller falls back to keeping (a query-cleaned
//! version of) the original URL.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use url::{Host, Url};

/// Reason a destination URL was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectReason {
    /// Scheme was not http or https.
    BadScheme(String),
    /// URL contained a username or password component.
    HasUserinfo,
    /// URL contained control characters.
    ControlChars,
    /// Host was empty or otherwise invalid.
    InvalidHost,
    /// Hostname mixed incompatible scripts (likely a homograph attack).
    MixedScript,
    /// Host is a literal private / loopback / link-local / metadata IP.
    PrivateIp,
}

impl RejectReason {
    /// Short, header-safe label.
    pub fn label(&self) -> String {
        match self {
            RejectReason::BadScheme(s) => format!("bad-scheme:{s}"),
            RejectReason::HasUserinfo => "userinfo".into(),
            RejectReason::ControlChars => "control-chars".into(),
            RejectReason::InvalidHost => "invalid-host".into(),
            RejectReason::MixedScript => "mixed-script".into(),
            RejectReason::PrivateIp => "private-ip".into(),
        }
    }
}

/// Validate a destination URL produced by redirect unwrapping.
///
/// Returns `Ok(())` if the URL is acceptable, or `Err(reason)` otherwise.
pub fn validate_destination(url: &Url) -> Result<(), RejectReason> {
    // 1. Scheme must be http or https.
    match url.scheme() {
        "http" | "https" => {}
        other => return Err(RejectReason::BadScheme(other.to_string())),
    }

    // 2. No userinfo.
    if !url.username().is_empty() || url.password().is_some() {
        return Err(RejectReason::HasUserinfo);
    }

    // 3. No control characters anywhere in the serialized form.
    if url.as_str().chars().any(|c| c.is_control()) {
        return Err(RejectReason::ControlChars);
    }

    // 4. Host must be present and valid.
    let host = match url.host() {
        Some(h) => h,
        None => return Err(RejectReason::InvalidHost),
    };

    // 5. Reject suspicious mixed-script hostnames (homograph attacks), and
    //    literal IP hosts that point at private / internal ranges (so we never
    //    rewrite a visible link to target internal infrastructure).
    match &host {
        Host::Domain(domain) => {
            if domain.is_empty() {
                return Err(RejectReason::InvalidHost);
            }
            if is_suspicious_mixed_script(domain) {
                return Err(RejectReason::MixedScript);
            }
        }
        Host::Ipv4(ip) => {
            if is_blocked_ip(&IpAddr::V4(*ip)) {
                return Err(RejectReason::PrivateIp);
            }
        }
        Host::Ipv6(ip) => {
            if is_blocked_ip(&IpAddr::V6(*ip)) {
                return Err(RejectReason::PrivateIp);
            }
        }
    }

    Ok(())
}

/// Script families we care about for homograph detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Script {
    Latin,
    Cyrillic,
    Greek,
    Other,
}

fn script_of(c: char) -> Option<Script> {
    // Only classify "letter-like" characters; digits, hyphens and dots are
    // script-neutral.
    if c.is_ascii_digit() || c == '-' || c == '.' || c == '_' {
        return None;
    }
    match c {
        'a'..='z' | 'A'..='Z' => Some(Script::Latin),
        // Latin-1 supplement / Latin extended letters.
        '\u{00C0}'..='\u{024F}' => Some(Script::Latin),
        '\u{0370}'..='\u{03FF}' => Some(Script::Greek),
        '\u{0400}'..='\u{04FF}' | '\u{0500}'..='\u{052F}' => Some(Script::Cyrillic),
        c if c.is_alphabetic() => Some(Script::Other),
        _ => None,
    }
}

/// A hostname is suspicious when a single label mixes Latin with Cyrillic or
/// Greek letters. Pure non-Latin scripts (e.g. a fully Cyrillic IDN) are fine;
/// it is the *mixing* that signals a homograph attack such as `xn--`-style
/// `paypаl.com` (with a Cyrillic а).
fn is_suspicious_mixed_script(domain: &str) -> bool {
    for label in domain.split('.') {
        let mut has_latin = false;
        let mut has_cyr_or_greek = false;
        for c in label.chars() {
            match script_of(c) {
                Some(Script::Latin) => has_latin = true,
                Some(Script::Cyrillic) | Some(Script::Greek) => has_cyr_or_greek = true,
                _ => {}
            }
        }
        if has_latin && has_cyr_or_greek {
            return true;
        }
    }
    false
}

/// Returns `true` if the given IP address must never be contacted by the
/// network resolver (SSRF / DNS-rebinding protection).
pub fn is_blocked_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_ipv4(v4),
        IpAddr::V6(v6) => is_blocked_ipv6(v6),
    }
}

fn is_blocked_ipv4(ip: &Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_loopback()            // 127.0.0.0/8
        || ip.is_private()      // 10/8, 172.16/12, 192.168/16
        || ip.is_link_local()   // 169.254/16 (includes 169.254.169.254 metadata)
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()  // 0.0.0.0
        // Carrier-grade NAT 100.64.0.0/10
        || (o[0] == 100 && (o[1] & 0xC0) == 0x40)
        // Benchmarking 198.18.0.0/15
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
        // 192.0.0.0/24 (IETF protocol assignments)
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        // Multicast / reserved
        || ip.is_multicast()
        || o[0] >= 240
}

fn is_blocked_ipv6(ip: &Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return true;
    }
    let seg = ip.segments();
    // Unique local fc00::/7
    if (seg[0] & 0xFE00) == 0xFC00 {
        return true;
    }
    // Link-local fe80::/10
    if (seg[0] & 0xFFC0) == 0xFE80 {
        return true;
    }
    // IPv4-mapped ::ffff:0:0/96 — re-check the embedded v4 address.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_blocked_ipv4(&v4);
    }
    // IPv4-compatible (deprecated) ::a.b.c.d
    if let Some(v4) = ip.to_ipv4() {
        if seg[0..6].iter().all(|s| *s == 0) {
            return is_blocked_ipv4(&v4);
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_http_schemes() {
        for s in [
            "javascript:alert(1)",
            "file:///etc/passwd",
            "data:text/html,x",
        ] {
            let u = Url::parse(s).unwrap();
            assert!(validate_destination(&u).is_err(), "{s} should be rejected");
        }
    }

    #[test]
    fn rejects_userinfo() {
        let u = Url::parse("https://user:pass@example.com/").unwrap();
        assert_eq!(validate_destination(&u), Err(RejectReason::HasUserinfo));
    }

    #[test]
    fn accepts_plain_https() {
        let u = Url::parse("https://example.com/path?x=1").unwrap();
        assert!(validate_destination(&u).is_ok());
    }

    #[test]
    fn detects_mixed_script() {
        // "paypаl" — the 5th letter is Cyrillic U+0430.
        assert!(is_suspicious_mixed_script("payp\u{0430}l.com"));
        assert!(!is_suspicious_mixed_script("paypal.com"));
        assert!(!is_suspicious_mixed_script("example.co.uk"));
    }

    #[test]
    fn blocks_private_and_metadata_ips() {
        for ip in [
            "127.0.0.1",
            "10.0.0.5",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.169.254",
            "0.0.0.0",
            "100.64.0.1",
        ] {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(is_blocked_ip(&ip), "{ip} should be blocked");
        }
        let public: IpAddr = "93.184.216.34".parse().unwrap();
        assert!(!is_blocked_ip(&public));
    }

    #[test]
    fn blocks_ipv6_local() {
        for ip in ["::1", "fe80::1", "fc00::1", "::ffff:127.0.0.1"] {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(is_blocked_ip(&ip), "{ip} should be blocked");
        }
    }
}

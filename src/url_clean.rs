//! Tracking query-parameter removal.

use percent_encoding::percent_decode_str;
use url::Url;

use crate::config::CleanerConfig;

/// Outcome of [`clean_url`](crate::clean_url).
#[derive(Debug, Clone)]
pub struct UrlCleanResult {
    /// The cleaned URL (equal to the input when nothing changed).
    pub url: Url,
    /// Whether any parameter was removed.
    pub changed: bool,
    /// Names of the parameters that were removed.
    pub removed_params: Vec<String>,
}

/// Remove known tracking query parameters from `url`.
///
/// Parameter *names* are matched case-insensitively. The raw encoding of the
/// surviving parameters is preserved byte-for-byte so we don't accidentally
/// re-encode values (which could break signed/magic links).
pub fn clean_url(url: &Url, config: &CleanerConfig) -> UrlCleanResult {
    let query = match url.query() {
        Some(q) if !q.is_empty() => q,
        _ => {
            return UrlCleanResult {
                url: url.clone(),
                changed: false,
                removed_params: Vec::new(),
            }
        }
    };

    let mut kept: Vec<&str> = Vec::new();
    let mut removed: Vec<String> = Vec::new();

    for segment in query.split('&') {
        if segment.is_empty() {
            continue;
        }
        let key_raw = segment.split('=').next().unwrap_or("");
        // Form-decode the key for matching: '+' -> space, then percent-decode.
        let key_plus = key_raw.replace('+', " ");
        let key = percent_decode_str(&key_plus).decode_utf8_lossy();

        if config.is_tracking_param(&key) {
            removed.push(key.into_owned());
        } else {
            kept.push(segment);
        }
    }

    if removed.is_empty() {
        return UrlCleanResult {
            url: url.clone(),
            changed: false,
            removed_params: Vec::new(),
        };
    }

    let mut out = url.clone();
    if kept.is_empty() {
        out.set_query(None);
    } else {
        out.set_query(Some(&kept.join("&")));
    }

    UrlCleanResult {
        url: out,
        changed: true,
        removed_params: removed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> CleanerConfig {
        let mut c = CleanerConfig::default();
        c.finalize();
        c
    }

    #[test]
    fn removes_utm_and_keeps_real_params() {
        let u =
            Url::parse("https://shop.example.com/p?id=42&utm_source=news&utm_medium=email&q=hi")
                .unwrap();
        let r = clean_url(&u, &cfg());
        assert!(r.changed);
        assert_eq!(r.url.as_str(), "https://shop.example.com/p?id=42&q=hi");
        assert_eq!(r.removed_params.len(), 2);
    }

    #[test]
    fn case_insensitive_match() {
        let u = Url::parse("https://e.com/?UTM_Source=x&Keep=1").unwrap();
        let r = clean_url(&u, &cfg());
        assert_eq!(r.url.as_str(), "https://e.com/?Keep=1");
    }

    #[test]
    fn removes_all_params() {
        let u = Url::parse("https://e.com/path?fbclid=abc").unwrap();
        let r = clean_url(&u, &cfg());
        assert!(r.changed);
        assert_eq!(r.url.as_str(), "https://e.com/path");
    }

    #[test]
    fn preserves_value_encoding() {
        // The kept parameter's value must not be re-encoded.
        let u = Url::parse("https://e.com/?token=a%2Bb%2Fc&utm_id=9").unwrap();
        let r = clean_url(&u, &cfg());
        assert_eq!(r.url.as_str(), "https://e.com/?token=a%2Bb%2Fc");
    }

    #[test]
    fn no_query_is_noop() {
        let u = Url::parse("https://e.com/path").unwrap();
        let r = clean_url(&u, &cfg());
        assert!(!r.changed);
    }
}

//! Content-transfer-encoding helpers used when re-emitting a modified body part.
//!
//! The goal is to re-encode a modified text part using the *same* CTE the part
//! originally declared, so the `Content-Transfer-Encoding` header stays valid
//! and the MIME structure is preserved.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use mail_parser::Encoding;

/// Re-encode `content` (raw UTF-8/bytes of the cleaned body) using `encoding`.
///
/// `line_ending` is the CRLF/LF sequence detected from the surrounding message
/// and is used when wrapping base64/quoted-printable output.
pub fn encode_body(content: &[u8], encoding: Encoding, line_ending: &[u8]) -> Vec<u8> {
    match encoding {
        Encoding::None => content.to_vec(),
        Encoding::Base64 => encode_base64(content, line_ending),
        Encoding::QuotedPrintable => encode_quoted_printable(content, line_ending),
    }
}

/// Base64-encode, wrapping at 76 characters per RFC 2045.
fn encode_base64(content: &[u8], line_ending: &[u8]) -> Vec<u8> {
    let encoded = STANDARD.encode(content);
    let bytes = encoded.as_bytes();
    let mut out = Vec::with_capacity(encoded.len() + encoded.len() / 76 * line_ending.len());
    for (i, chunk) in bytes.chunks(76).enumerate() {
        if i > 0 {
            out.extend_from_slice(line_ending);
        }
        out.extend_from_slice(chunk);
    }
    out
}

/// Quoted-printable encode, wrapping at 76 columns with soft line breaks.
///
/// Implemented locally (rather than via the `quoted_printable` crate's encoder)
/// so we have full control over the line ending used for soft breaks.
fn encode_quoted_printable(content: &[u8], line_ending: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(content.len() + content.len() / 3);
    let mut line_len = 0usize;

    // Emit a soft line break ("=" + EOL) to stay within 76 columns.
    let soft_break = |out: &mut Vec<u8>, line_len: &mut usize| {
        out.push(b'=');
        out.extend_from_slice(line_ending);
        *line_len = 0;
    };

    let mut i = 0;
    while i < content.len() {
        let b = content[i];

        // Preserve existing newlines as hard line breaks. `\r\n`, lone `\n`,
        // and lone `\r` are all treated as one line break — we never emit
        // `=0D` for a CR that is part of a hard CRLF, because the QP decoder
        // would then yield `\r\r\n` (a real bug if the original message used
        // CRLF body line endings, which is the norm).
        if b == b'\r' && i + 1 < content.len() && content[i + 1] == b'\n' {
            out.extend_from_slice(line_ending);
            line_len = 0;
            i += 2;
            continue;
        }
        if b == b'\n' {
            out.extend_from_slice(line_ending);
            line_len = 0;
            i += 1;
            continue;
        }

        let needs_encoding = match b {
            b'=' => true,
            // Printable ASCII range (except '=').
            0x21..=0x7E => false,
            b' ' | b'\t' => {
                // Space/tab only need encoding at end of line; handle below.
                false
            }
            b'\r' => {
                // Lone CR (not part of CRLF): encode it.
                true
            }
            _ => true,
        };

        // Space/tab at end of content or before newline must be encoded.
        let is_ws = b == b' ' || b == b'\t';
        let ws_at_eol =
            is_ws && (i + 1 >= content.len() || content[i + 1] == b'\n' || content[i + 1] == b'\r');

        if needs_encoding || ws_at_eol {
            if line_len + 3 > 75 {
                soft_break(&mut out, &mut line_len);
            }
            out.push(b'=');
            out.extend_from_slice(format!("{b:02X}").as_bytes());
            line_len += 3;
        } else {
            if line_len + 1 > 75 {
                soft_break(&mut out, &mut line_len);
            }
            out.push(b);
            line_len += 1;
        }
        i += 1;
    }

    out
}

/// Re-encode a UTF-8 string back into the message part's declared charset.
///
/// `mail-parser` always hands us decoded UTF-8, so before applying the CTE we
/// must convert back to the part's original charset, otherwise a declared
/// `iso-8859-1` part would end up containing UTF-8 bytes (mojibake).
///
/// Returns `None` when the charset is unknown *and* the content is not pure
/// ASCII — in that case the caller should leave the part untouched rather than
/// risk corrupting it.
pub fn reencode_charset(s: &str, charset: Option<&str>) -> Option<Vec<u8>> {
    let cs = charset.unwrap_or("utf-8").trim().to_ascii_lowercase();
    match cs.as_str() {
        "" | "utf-8" | "utf8" | "us-ascii" | "ascii" => Some(s.as_bytes().to_vec()),
        "iso-8859-1" | "latin1" | "latin-1" | "l1" | "iso8859-1" | "iso_8859-1" | "cp819" => {
            // Map each char to a single byte where the code point fits in a
            // byte.
            let mut out = Vec::with_capacity(s.len());
            for c in s.chars() {
                let cp = c as u32;
                if cp <= 0xFF {
                    out.push(cp as u8);
                } else {
                    out.push(b'?');
                }
            }
            Some(out)
        }
        "windows-1252" | "cp1252" | "win-1252" => {
            let (bytes, _, _) = encoding_rs::WINDOWS_1252.encode(s);
            Some(bytes.into_owned())
        }
        _ => {
            // WHATWG encoding index, so legacy charsets (windows-1256, koi8-r,
            // shift_jis, …) re-encode instead of disabling the rewrite. The
            // `output_encoding` check excludes UTF-16 and `replacement`, which
            // WHATWG maps to UTF-8 output — writing that into a part declaring
            // UTF-16 would corrupt it.
            if let Some(enc) = encoding_rs::Encoding::for_label(cs.as_bytes()) {
                if std::ptr::eq(enc, enc.output_encoding()) {
                    let (bytes, _, _) = enc.encode(s);
                    return Some(bytes.into_owned());
                }
            }
            if s.is_ascii() {
                Some(s.as_bytes().to_vec())
            } else {
                None
            }
        }
    }
}

/// Decode raw part bytes using the part's declared charset, for the
/// CTE-mismatch recovery path in [`crate::mime`]. Strict: `None` if the bytes
/// aren't valid in that charset, rather than feeding U+FFFD into the rewriter.
pub fn decode_charset(bytes: &[u8], charset: Option<&str>) -> Option<String> {
    let cs = charset.unwrap_or("utf-8").trim().to_ascii_lowercase();
    if let Some(enc) = encoding_rs::Encoding::for_label(cs.as_bytes()) {
        return enc
            .decode_without_bom_handling_and_without_replacement(bytes)
            .map(|c| c.into_owned());
    }
    std::str::from_utf8(bytes).ok().map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latin1_reencode() {
        let s = "caf\u{00e9}"; // café
        let bytes = reencode_charset(s, Some("iso-8859-1")).unwrap();
        assert_eq!(bytes, vec![b'c', b'a', b'f', 0xE9]);
    }

    #[test]
    fn windows_1252_reencode_maps_typographic_chars() {
        let s = "\u{20ac}\u{201c}quoted\u{201d}";
        let bytes = reencode_charset(s, Some("windows-1252")).unwrap();
        assert_eq!(
            bytes,
            vec![0x80, 0x93, b'q', b'u', b'o', b't', b'e', b'd', 0x94]
        );
    }

    #[test]
    fn unknown_charset_ascii_ok_nonascii_skipped() {
        assert!(reencode_charset("plain ascii", Some("not-a-charset")).is_some());
        assert!(reencode_charset("caf\u{00e9}", Some("not-a-charset")).is_none());
    }

    #[test]
    fn whatwg_labels_reencode_instead_of_giving_up() {
        // Previously anything outside utf-8/latin-1/windows-1252 was dropped,
        // which silently disabled the rewrite for the whole part.
        let bytes = reencode_charset("\u{645}\u{631}\u{62d}\u{628}\u{627}", Some("windows-1256"))
            .expect("windows-1256 must be encodable");
        assert_eq!(bytes, vec![0xE3, 0xD1, 0xCD, 0xC8, 0xC7]);
        assert!(reencode_charset("\u{3053}", Some("shift_jis")).is_some());
    }

    #[test]
    fn utf16_output_is_refused() {
        // WHATWG maps utf-16 to utf-8 for output; writing utf-8 into a part
        // that declares utf-16 would corrupt it, so non-ASCII must be refused.
        assert!(reencode_charset("caf\u{00e9}", Some("utf-16")).is_none());
        assert!(reencode_charset("caf\u{00e9}", Some("utf-16le")).is_none());
    }

    #[test]
    fn decode_charset_roundtrips_legacy_bytes() {
        let s = decode_charset(&[0xE3, 0xD1, 0xCD, 0xC8, 0xC7], Some("windows-1256")).unwrap();
        assert_eq!(s, "\u{645}\u{631}\u{62d}\u{628}\u{627}");
        // Invalid in the declared charset -> refuse rather than emit U+FFFD.
        assert!(decode_charset(&[0xFF, 0xFE, 0x00], Some("utf-8")).is_none());
    }

    #[test]
    fn base64_roundtrip() {
        let data = b"Hello, world! This is a reasonably long string to force wrapping across multiple base64 lines for testing.";
        let enc = encode_body(data, Encoding::Base64, b"\r\n");
        // Each line must be <= 76 chars.
        for line in enc.split(|&b| b == b'\n') {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            assert!(line.len() <= 76);
        }
        let joined: Vec<u8> = enc
            .into_iter()
            .filter(|&b| b != b'\r' && b != b'\n')
            .collect();
        let dec = STANDARD.decode(joined).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn qp_encodes_equals_and_high_bytes() {
        let data = "a=b\u{00e9}".as_bytes(); // 'é' is two UTF-8 bytes
        let enc = encode_body(data, Encoding::QuotedPrintable, b"\r\n");
        let s = String::from_utf8(enc).unwrap();
        assert!(s.contains("=3D")); // '='
        assert!(s.contains("=C3=A9")); // é
    }

    #[test]
    fn qp_roundtrip_via_decoder() {
        let data = b"Some <html> with = signs and a long line aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa end.";
        let enc = encode_body(data, Encoding::QuotedPrintable, b"\r\n");
        let dec = quoted_printable::decode(&enc, quoted_printable::ParseMode::Robust).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn none_is_passthrough() {
        let data = b"<p>hi</p>";
        assert_eq!(encode_body(data, Encoding::None, b"\r\n"), data);
    }

    #[test]
    fn qp_preserves_crlf_round_trip() {
        // Regression: the old encoder emitted "=0D\r\n" for CRLF input, which
        // decoded to "\r\r\n" — silently doubling the CR on every line break.
        let data = b"line one\r\nline two\r\nline three\r\n";
        let enc = encode_body(data, Encoding::QuotedPrintable, b"\r\n");
        let dec = quoted_printable::decode(&enc, quoted_printable::ParseMode::Robust).unwrap();
        assert_eq!(
            dec, data,
            "QP encoder must not double-encode CR in CRLF line breaks"
        );
        // The encoded form must not contain "=0D" — every CR here is part of a
        // hard break and must be emitted as a literal newline only.
        assert!(
            !String::from_utf8_lossy(&enc).contains("=0D"),
            "expected no =0D in encoded form, got: {:?}",
            enc
        );
    }

    #[test]
    fn qp_still_encodes_lone_cr() {
        // A CR that is *not* part of CRLF must still be encoded so it survives.
        let data = b"a\rb";
        let enc = encode_body(data, Encoding::QuotedPrintable, b"\r\n");
        let dec = quoted_printable::decode(&enc, quoted_printable::ParseMode::Robust).unwrap();
        assert_eq!(dec, data);
        assert!(String::from_utf8_lossy(&enc).contains("=0D"));
    }

    #[test]
    fn qp_lf_input_normalizes_to_crlf_on_decode() {
        // RFC 2045 §6.7 rule #4: a hard line break in QP source represents a
        // CRLF in the original data, regardless of what byte sequence the
        // *encoder* emitted for the break. So an LF-only source that we emit
        // with an LF line ending will come back as CRLF after a QP round-trip.
        // This is QP itself doing the normalization, not a bug in our encoder.
        // Capture it here so the contract is explicit.
        let data = b"line one\nline two\n";
        let enc = encode_body(data, Encoding::QuotedPrintable, b"\n");
        let dec = quoted_printable::decode(&enc, quoted_printable::ParseMode::Robust).unwrap();
        assert_eq!(dec, b"line one\r\nline two\r\n");
    }
}

use email_privacy_cleaner::encoding::*;
use mail_parser::Encoding;

fn check(label: &str, data: &[u8]) {
    let enc = encode_body(data, Encoding::QuotedPrintable, b"\r\n");
    let dec = quoted_printable::decode(&enc, quoted_printable::ParseMode::Robust).unwrap();
    let ok = dec == data;
    println!(
        "{label:30}: input {:?} -> encoded {:?} -> decoded {:?}  round-trip ok: {ok}",
        data,
        String::from_utf8_lossy(&enc),
        dec
    );
    if !ok {
        eprintln!("  MISMATCH for {label}");
    }
}

fn main() {
    check("trailing CR no LF", b"foo\r");
    check("leading CR no LF", b"\rfoo");
    check("CR CR LF", b"a\r\r\nb");
    check("CR LF CR LF", b"a\r\nb\r\n");
    check("just LF", b"a\nb");
    check("CR alone in middle", b"a\rb\nc");
    check("empty", b"");
    check("only CRLF", b"\r\n");
    check("only LF", b"\n");
    check("UTF-8 high byte + CRLF", "caf\u{00e9}\r\n".as_bytes());
    // Long line with hard break at column 76.
    let mut long = vec![b'a'; 100];
    long.extend_from_slice(b"\r\n");
    long.extend_from_slice(b"end");
    check("long line then CRLF", &long);
}

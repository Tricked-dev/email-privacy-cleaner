// Repro for QP encoder handling of CRLF in input
use email_privacy_cleaner::encoding::*;
use mail_parser::Encoding;

fn main() {
    // Simulate body part with literal CRLF (as decoded by mail-parser from a hard line break)
    let body = b"line one\r\nline two\r\n";
    let enc = encode_body(body, Encoding::QuotedPrintable, b"\r\n");
    println!("input bytes:    {:?}", body);
    println!("encoded:        {:?}", enc);
    println!("encoded text:   {}", String::from_utf8_lossy(&enc));
    let dec = quoted_printable::decode(&enc, quoted_printable::ParseMode::Robust).unwrap();
    println!("decoded back:   {:?}", dec);
    println!("roundtrip ok?:  {}", dec == body);
}

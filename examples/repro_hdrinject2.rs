use email_privacy_cleaner::{clean_message, CleanerConfig};
use mail_parser::MessageParser;

fn main() {
    // Properly-folded List-Unsubscribe (continuation = CRLF + WSP).
    // Per RFC 5322, the CRLF + WSP within a folded header field is logically equivalent to a single SP.
    let raw: Vec<u8> = b"From: a@b.c\r\nList-Unsubscribe: <https://a.example/u\r\n ?id=1>\r\nContent-Type: text/plain\r\n\r\nhi\r\n".to_vec();
    let m = MessageParser::default().parse(&raw).unwrap();
    if let Some(v) = m.header_raw("List-Unsubscribe") {
        println!("header_raw bytes: {:?}", v.as_bytes());
        println!("header_raw text:  {:?}", v);
    } else {
        println!("no List-Unsubscribe");
    }
    let mut cfg = CleanerConfig::default();
    cfg.finalize();
    let r = clean_message(&raw, &cfg).unwrap();
    println!(
        "--- cleaned text ---\n{}",
        String::from_utf8_lossy(&r.cleaned)
    );
    println!("--- raw bytes ---");
    for b in &r.cleaned {
        print!("{:02x} ", b);
    }
    println!();
}

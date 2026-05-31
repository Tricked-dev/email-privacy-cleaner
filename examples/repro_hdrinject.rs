use email_privacy_cleaner::{clean_message, CleanerConfig};

fn main() {
    // Attempt header injection through surface_unsubscribe.
    // RFC 5322 disallows raw CR/LF in headers, but a hostile MTA or a folded value
    // could let one through into mail-parser's raw_header.
    let raw: Vec<u8> = b"From: news@example.com\r\nList-Unsubscribe: <https://a.example/u?id=1\r\nX-Injected: yes>\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\nhi\r\n".to_vec();
    let mut cfg = CleanerConfig::default();
    cfg.finalize();
    let r = clean_message(&raw, &cfg).unwrap();
    println!("--- cleaned ---");
    println!("{}", String::from_utf8_lossy(&r.cleaned));
    println!("--- raw bytes ---");
    for b in &r.cleaned {
        print!("{:02x} ", b);
    }
    println!();
}

use email_privacy_cleaner::{clean_message, CleanerConfig};
use mail_parser::{MessageParser, PartType};

fn main() {
    let raw: Vec<u8> = b"From: news@example.com\r\nContent-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n<p>Hello</p>\r\n<a href=3D\"https://e.com/?utm_source=3Dx&amp;id=3D1\">link</a>\r\n<p>bye</p>\r\n".to_vec();
    let mut cfg = CleanerConfig::default();
    cfg.finalize();
    let r = clean_message(&raw, &cfg).unwrap();
    println!("modified: {}", r.modified);
    println!("--- cleaned message (printable) ---");
    println!("{}", String::from_utf8_lossy(&r.cleaned));
    println!("--- bytes (only HTML body region) ---");
    let m = MessageParser::default().parse(&r.cleaned).unwrap();
    for &id in &m.html_body {
        if let Some(p) = m.part(id) {
            if let PartType::Html(s) = &p.body {
                println!("decoded again: {:?}", s.as_bytes());
            }
        }
    }
}

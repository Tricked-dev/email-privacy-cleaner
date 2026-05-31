use email_privacy_cleaner::{clean_message, CleanerConfig};
use mail_parser::{MessageParser, PartType};

fn main() {
    // Real text/plain with QP and CRLF + a URL that contains a tracker.
    let raw: Vec<u8> = b"From: a@b.c\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nHello,\r\nClick https://e.com/p?utm_source=3Dx&id=3D1 today.\r\nThanks.\r\n".to_vec();

    let mut cfg = CleanerConfig::default();
    cfg.clean_text_plain = true;
    cfg.finalize();
    let r = clean_message(&raw, &cfg).unwrap();
    println!("--- cleaned ---");
    println!("{}", String::from_utf8_lossy(&r.cleaned));
    println!("--- decoded body ---");
    let m = MessageParser::default().parse(&r.cleaned).unwrap();
    for &id in &m.text_body {
        if let Some(p) = m.part(id) {
            if let PartType::Text(s) = &p.body {
                println!("{:?}", s.as_bytes());
                println!("{}", s);
            }
        }
    }
}

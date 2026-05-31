use mail_parser::{MessageParser, PartType};

fn main() {
    let raw = b"From: a@b.c\r\nContent-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n<p>line one</p>\r\n<p>line two</p>\r\n";
    let m = MessageParser::default().parse(raw).unwrap();
    for &id in &m.html_body {
        if let Some(p) = m.part(id) {
            if let PartType::Html(s) = &p.body {
                println!("html part bytes:   {:?}", s.as_bytes());
                let has_cr = s.as_bytes().contains(&13u8);
                println!("contains CR?:      {}", has_cr);
            }
        }
    }
    let raw2 = b"From: a@b.c\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nfirst=0D=0A\r\nsecond=0D=0A\r\n";
    let m2 = MessageParser::default().parse(raw2).unwrap();
    for &id in &m2.text_body {
        if let Some(p) = m2.part(id) {
            if let PartType::Text(s) = &p.body {
                println!("text part bytes:   {:?}", s.as_bytes());
            }
        }
    }
    let raw3 = b"From: a@b.c\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>line one</p>\r\n<p>line two</p>\r\n";
    let m3 = MessageParser::default().parse(raw3).unwrap();
    for &id in &m3.html_body {
        if let Some(p) = m3.part(id) {
            if let PartType::Html(s) = &p.body {
                println!("7bit html bytes:   {:?}", s.as_bytes());
            }
        }
    }
}

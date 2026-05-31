//! End-to-end test of the milter protocol implementation: we act as the MTA
//! (client), drive a full DATA-stage conversation, and assert that the milter
//! replies with a body replacement and the audit headers.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use email_privacy_cleaner::{config::CleanerConfig, milter};

fn write_packet(s: &mut TcpStream, cmd: u8, data: &[u8]) {
    let len = (data.len() + 1) as u32;
    s.write_all(&len.to_be_bytes()).unwrap();
    s.write_all(&[cmd]).unwrap();
    s.write_all(data).unwrap();
}

fn read_packet(s: &mut TcpStream) -> (u8, Vec<u8>) {
    let mut len = [0u8; 4];
    s.read_exact(&mut len).unwrap();
    let len = u32::from_be_bytes(len) as usize;
    let mut buf = vec![0u8; len];
    s.read_exact(&mut buf).unwrap();
    (buf[0], buf[1..].to_vec())
}

#[test]
fn full_milter_conversation_modifies_and_adds_headers() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    // Server: handle exactly one connection.
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut cfg = CleanerConfig::default();
        cfg.preserve_original_href = false;
        cfg.finalize();
        let _ = milter::handle_connection(stream, &cfg);
    });

    let mut c = TcpStream::connect(addr).unwrap();

    // OPTNEG: version=6, actions=all, protocol=0.
    let mut optneg = Vec::new();
    optneg.extend_from_slice(&6u32.to_be_bytes());
    optneg.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
    optneg.extend_from_slice(&0u32.to_be_bytes());
    write_packet(&mut c, b'O', &optneg);
    let (cmd, data) = read_packet(&mut c);
    assert_eq!(cmd, b'O', "expected OPTNEG reply");
    assert_eq!(data.len(), 12);

    // MAIL FROM.
    write_packet(&mut c, b'M', b"<sender@example.com>\0");
    assert_eq!(read_packet(&mut c).0, b'c');

    // Headers.
    let headers: &[(&str, &str)] = &[
        ("From", "sender@example.com"),
        ("Subject", "milter e2e"),
        ("MIME-Version", "1.0"),
        ("Content-Type", "text/html; charset=utf-8"),
    ];
    for (name, value) in headers {
        let mut d = Vec::new();
        d.extend_from_slice(name.as_bytes());
        d.push(0);
        d.extend_from_slice(value.as_bytes());
        d.push(0);
        write_packet(&mut c, b'L', &d);
        assert_eq!(read_packet(&mut c).0, b'c');
    }

    // End of headers.
    write_packet(&mut c, b'N', &[]);
    assert_eq!(read_packet(&mut c).0, b'c');

    // Body with a tracking link + 1x1 pixel.
    let body = br#"<a href="https://e.example/?utm_source=x&id=1">y</a><img src="https://t.example.net/o.gif" width="1" height="1" alt="">"#;
    write_packet(&mut c, b'B', body);
    assert_eq!(read_packet(&mut c).0, b'c');

    // End of message → expect modifications then a final continue.
    write_packet(&mut c, b'E', &[]);

    let mut replbody = Vec::new();
    let mut add_headers = Vec::new();
    loop {
        let (cmd, data) = read_packet(&mut c);
        match cmd {
            b'b' => replbody.extend_from_slice(&data),
            b'h' => add_headers.push(data),
            b'c' => break,
            other => panic!("unexpected response: {}", other as char),
        }
    }

    // The replacement body must be cleaned.
    let body_str = String::from_utf8_lossy(&replbody);
    assert!(
        !body_str.contains("o.gif"),
        "pixel should be removed: {body_str}"
    );
    assert!(!body_str.contains("utm_source"), "param should be stripped");
    assert!(body_str.contains("id=1"));

    // Audit headers added (7 of them), including the signature header.
    assert_eq!(add_headers.len(), 7);
    let names: Vec<String> = add_headers
        .iter()
        .map(|d| {
            let nul = d.iter().position(|&b| b == 0).unwrap();
            String::from_utf8_lossy(&d[..nul]).into_owned()
        })
        .collect();
    assert!(names.contains(&"X-Privacy-Cleaner".to_string()));
    assert!(names.contains(&"X-Privacy-Cleaner-Pixels-Removed".to_string()));

    // Quit and join.
    write_packet(&mut c, b'Q', &[]);
    drop(c);
    server.join().unwrap();
}

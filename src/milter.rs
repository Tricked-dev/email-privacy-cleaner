//! Minimal Sendmail/Postfix **milter protocol** server, sufficient for
//! Stalwart's milter client at the SMTP DATA stage.
//!
//! The MTA is the client; this process is the milter (server). We negotiate
//! the ability to add headers and replace the body, accumulate the message's
//! headers and body, and at end-of-message run the cleaner and emit the
//! modifications (`SMFIR_REPLBODY` + `SMFIR_ADDHEADER`).
//!
//! Failure handling honours the config: on an internal parser error we either
//! fail-open (return the original body untouched, add `X-Privacy-Cleaner-Error`)
//! or tempfail.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use crate::config::CleanerConfig;
use crate::{clean_message_fail_open, CleanerResult};

// ---- Commands sent by the MTA ----
const SMFIC_ABORT: u8 = b'A';
const SMFIC_BODY: u8 = b'B';
const SMFIC_CONNECT: u8 = b'C';
const SMFIC_MACRO: u8 = b'D';
const SMFIC_BODYEOB: u8 = b'E';
const SMFIC_HELO: u8 = b'H';
const SMFIC_HEADER: u8 = b'L';
const SMFIC_MAIL: u8 = b'M';
const SMFIC_EOH: u8 = b'N';
const SMFIC_OPTNEG: u8 = b'O';
const SMFIC_QUIT: u8 = b'Q';
const SMFIC_QUIT_NC: u8 = b'K';
const SMFIC_RCPT: u8 = b'R';
const SMFIC_DATA: u8 = b'T';
const SMFIC_UNKNOWN: u8 = b'U';

// ---- Responses sent by the milter ----
const SMFIR_ADDHEADER: u8 = b'h';
const SMFIR_REPLBODY: u8 = b'b';
const SMFIR_CONTINUE: u8 = b'c';
const SMFIR_TEMPFAIL: u8 = b't';
const SMFIR_OPTNEG: u8 = b'O';

// ---- Action flags (what the milter may do) ----
const SMFIF_ADDHDRS: u32 = 0x01;
const SMFIF_CHGBODY: u32 = 0x02;

// Milter protocol version we speak.
const MILTER_VERSION: u32 = 6;

// Max body bytes per SMFIR_REPLBODY packet.
const REPLBODY_CHUNK: usize = 60_000;

/// Per-message accumulation state.
#[derive(Default)]
struct MessageState {
    headers: Vec<(Vec<u8>, Vec<u8>)>,
    body: Vec<u8>,
    bytes_seen: usize,
    over_limit: bool,
}

impl MessageState {
    fn reset(&mut self) {
        self.headers.clear();
        self.body.clear();
        self.bytes_seen = 0;
        self.over_limit = false;
    }

    /// Reconstruct the raw RFC 5322 message from accumulated headers + body.
    fn reconstruct(&self) -> Vec<u8> {
        let mut raw = Vec::with_capacity(
            self.body.len()
                + self
                    .headers
                    .iter()
                    .map(|(n, v)| n.len() + v.len() + 4)
                    .sum::<usize>(),
        );
        for (name, value) in &self.headers {
            raw.extend_from_slice(name);
            raw.extend_from_slice(b": ");
            raw.extend_from_slice(value);
            raw.extend_from_slice(b"\r\n");
        }
        raw.extend_from_slice(b"\r\n");
        raw.extend_from_slice(&self.body);
        raw
    }

    fn add_header(&mut self, name: Vec<u8>, value: Vec<u8>, config: &CleanerConfig) {
        // Defence in depth: an upstream MTA that lets CR/LF leak into the
        // milter `value` would let us reconstruct a message with smuggled
        // headers (the bytes would be emitted verbatim by `reconstruct`).
        // Replace any control byte that isn't tab with a space.
        let value: Vec<u8> = value
            .into_iter()
            .map(|b| {
                if b == b'\t' || !(b < 0x20 || b == 0x7F) {
                    b
                } else {
                    b' '
                }
            })
            .collect();
        let name: Vec<u8> = name
            .into_iter()
            .filter(|b| !matches!(*b, 0..=0x20 | b':' | 0x7F))
            .collect();
        if name.is_empty() {
            return;
        }
        let len = name.len().saturating_add(value.len()).saturating_add(4);
        if self.would_exceed(len, config) {
            self.over_limit = true;
            return;
        }
        self.bytes_seen += len;
        self.headers.push((name, value));
    }

    fn add_body(&mut self, data: &[u8], config: &CleanerConfig) {
        if self.would_exceed(data.len(), config) {
            self.over_limit = true;
            return;
        }
        self.bytes_seen += data.len();
        self.body.extend_from_slice(data);
    }

    fn would_exceed(&self, additional: usize, config: &CleanerConfig) -> bool {
        self.over_limit
            || self
                .bytes_seen
                .saturating_add(additional)
                .saturating_add(2) // final header/body separator added by reconstruct()
                > config.max_message_size
    }
}

/// Negotiated capabilities for the current connection.
#[derive(Clone, Copy)]
struct Caps {
    can_addhdrs: bool,
    can_chgbody: bool,
}

/// Bind and serve the milter protocol on `config.listen`, one thread per
/// connection. Blocks forever.
pub fn run(config: CleanerConfig) -> crate::error::Result<()> {
    let mut cfg = config;
    cfg.finalize();
    let listen = cfg.listen.clone();
    let cfg = Arc::new(cfg);

    let listener = TcpListener::bind(&listen)?;
    eprintln!(
        "email-privacy-milter {} listening on {} (mode={}, fail_open={})",
        crate::VERSION,
        listen,
        cfg.mode.as_str(),
        cfg.fail_open
    );

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let cfg = Arc::clone(&cfg);
                std::thread::spawn(move || {
                    if let Err(e) = handle_connection(stream, &cfg) {
                        if e.kind() != io::ErrorKind::UnexpectedEof {
                            eprintln!("milter connection error: {e}");
                        }
                    }
                });
            }
            Err(e) => eprintln!("accept error: {e}"),
        }
    }
    Ok(())
}

/// Handle a single milter connection.
pub fn handle_connection(mut stream: TcpStream, config: &CleanerConfig) -> io::Result<()> {
    stream.set_nodelay(true).ok();
    let mut state = MessageState::default();
    let mut caps = Caps {
        can_addhdrs: true,
        can_chgbody: true,
    };

    loop {
        let (cmd, data) = match read_packet(&mut stream)? {
            Some(p) => p,
            None => return Ok(()), // clean EOF
        };

        match cmd {
            SMFIC_OPTNEG => {
                caps = negotiate(&mut stream, &data)?;
            }
            SMFIC_MACRO => { /* no response */ }
            SMFIC_CONNECT | SMFIC_HELO | SMFIC_RCPT | SMFIC_DATA | SMFIC_UNKNOWN | SMFIC_EOH => {
                write_packet(&mut stream, SMFIR_CONTINUE, &[])?;
            }
            SMFIC_MAIL => {
                // New transaction.
                state.reset();
                write_packet(&mut stream, SMFIR_CONTINUE, &[])?;
            }
            SMFIC_HEADER => {
                if let Some((name, value)) = parse_two_strings(&data) {
                    state.add_header(name, value, config);
                }
                write_packet(&mut stream, SMFIR_CONTINUE, &[])?;
            }
            SMFIC_BODY => {
                state.add_body(&data, config);
                write_packet(&mut stream, SMFIR_CONTINUE, &[])?;
            }
            SMFIC_BODYEOB => {
                handle_eom(&mut stream, &state, config, caps)?;
                state.reset();
            }
            SMFIC_ABORT => {
                state.reset();
                // No response to ABORT.
            }
            SMFIC_QUIT | SMFIC_QUIT_NC => {
                return Ok(());
            }
            _ => {
                // Unknown command: be permissive.
                write_packet(&mut stream, SMFIR_CONTINUE, &[])?;
            }
        }
    }
}

/// Respond to option negotiation.
fn negotiate(stream: &mut TcpStream, data: &[u8]) -> io::Result<Caps> {
    // data: version(u32) actions(u32) protocol(u32)
    let mta_actions = if data.len() >= 8 {
        u32::from_be_bytes([data[4], data[5], data[6], data[7]])
    } else {
        u32::MAX
    };

    let want = SMFIF_ADDHDRS | SMFIF_CHGBODY;
    let actions = want & mta_actions;

    // protocol = 0 → don't skip any stage (we need headers + body + eom).
    let protocol: u32 = 0;

    let mut reply = Vec::with_capacity(12);
    reply.extend_from_slice(&MILTER_VERSION.to_be_bytes());
    reply.extend_from_slice(&actions.to_be_bytes());
    reply.extend_from_slice(&protocol.to_be_bytes());
    write_packet(stream, SMFIR_OPTNEG, &reply)?;

    Ok(Caps {
        can_addhdrs: actions & SMFIF_ADDHDRS != 0,
        can_chgbody: actions & SMFIF_CHGBODY != 0,
    })
}

/// End-of-message: run the cleaner and emit modifications.
fn handle_eom(
    stream: &mut TcpStream,
    state: &MessageState,
    config: &CleanerConfig,
    caps: Caps,
) -> io::Result<()> {
    if state.over_limit {
        write_packet(stream, SMFIR_TEMPFAIL, &[])?;
        return Ok(());
    }

    let raw = state.reconstruct();

    match clean_message_fail_open(&raw, config) {
        Ok(result) => {
            if result.modified && !caps.can_chgbody {
                write_packet(stream, SMFIR_TEMPFAIL, &[])?;
            } else {
                emit_modifications(stream, &result, caps)?;
                write_packet(stream, SMFIR_CONTINUE, &[])?;
            }
        }
        Err(_) => {
            // fail_open = false → tempfail on internal parser errors.
            write_packet(stream, SMFIR_TEMPFAIL, &[])?;
        }
    }
    Ok(())
}

fn emit_modifications(
    stream: &mut TcpStream,
    result: &CleanerResult,
    caps: Caps,
) -> io::Result<()> {
    // Replace the body only when we actually modified it. `result.modified`
    // already reflects the effective (possibly per-sender) mode, so we don't
    // re-check the global mode here.
    if result.modified && caps.can_chgbody {
        for chunk in result.body.chunks(REPLBODY_CHUNK) {
            write_packet(stream, SMFIR_REPLBODY, chunk)?;
        }
    }

    // Add audit headers.
    if caps.can_addhdrs {
        for (name, value) in &result.audit_headers {
            let mut buf = Vec::with_capacity(name.len() + value.len() + 2);
            buf.extend_from_slice(name.as_bytes());
            buf.push(0);
            buf.extend_from_slice(value.as_bytes());
            buf.push(0);
            write_packet(stream, SMFIR_ADDHEADER, &buf)?;
        }
    }
    Ok(())
}

// ---- wire helpers ----

/// Read one milter packet: a 4-byte big-endian length, then `len` bytes whose
/// first byte is the command. Returns `Ok(None)` on a clean EOF before any
/// bytes of a new packet.
fn read_packet(stream: &mut TcpStream) -> io::Result<Option<(u8, Vec<u8>)>> {
    let mut len_buf = [0u8; 4];
    if !read_exact_or_eof(stream, &mut len_buf)? {
        return Ok(None);
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 {
        return Ok(Some((0, Vec::new())));
    }
    // Guard against absurd allocations.
    if len > 256 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "milter packet too large",
        ));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    let cmd = buf[0];
    let data = buf[1..].to_vec();
    Ok(Some((cmd, data)))
}

/// Like `read_exact`, but returns `Ok(false)` if EOF occurs *before any* byte
/// is read (a clean connection close between packets).
fn read_exact_or_eof(stream: &mut TcpStream, buf: &mut [u8]) -> io::Result<bool> {
    let mut read = 0;
    while read < buf.len() {
        match stream.read(&mut buf[read..]) {
            Ok(0) => {
                if read == 0 {
                    return Ok(false);
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "eof mid-packet",
                ));
            }
            Ok(n) => read += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

fn write_packet(stream: &mut TcpStream, cmd: u8, data: &[u8]) -> io::Result<()> {
    let len = (data.len() + 1) as u32;
    let mut out = Vec::with_capacity(5 + data.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.push(cmd);
    out.extend_from_slice(data);
    stream.write_all(&out)
}

/// Parse two consecutive NUL-terminated byte strings (e.g. a header name and
/// value) from `data`.
fn parse_two_strings(data: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let nul = data.iter().position(|&b| b == 0)?;
    let name = data[..nul].to_vec();
    let rest = &data[nul + 1..];
    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    let value = rest[..end].to_vec();
    Some((name, value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconstruct_builds_valid_message() {
        let mut s = MessageState::default();
        let cfg = CleanerConfig::default();
        s.add_header(b"Subject".to_vec(), b"Hi".to_vec(), &cfg);
        s.add_header(b"Content-Type".to_vec(), b"text/plain".to_vec(), &cfg);
        s.add_body(b"hello world\r\n", &cfg);
        let raw = s.reconstruct();
        let text = String::from_utf8(raw).unwrap();
        assert!(text.starts_with("Subject: Hi\r\nContent-Type: text/plain\r\n\r\nhello"));
    }

    #[test]
    fn message_state_counts_headers_toward_limit() {
        let mut cfg = CleanerConfig::default();
        cfg.max_message_size = 20;
        let mut s = MessageState::default();
        s.add_header(b"Very-Long-Header".to_vec(), b"value".to_vec(), &cfg);
        assert!(s.over_limit);
        assert!(s.headers.is_empty());
    }

    #[test]
    fn message_state_rejects_oversized_body_chunk_before_append() {
        let mut cfg = CleanerConfig::default();
        cfg.max_message_size = 10;
        let mut s = MessageState::default();
        s.add_body(b"123456789", &cfg);
        assert!(s.over_limit);
        assert!(s.body.is_empty());
    }

    #[test]
    fn parse_two_strings_works() {
        let (n, v) = parse_two_strings(b"X-Foo\0bar\0").unwrap();
        assert_eq!(n, b"X-Foo");
        assert_eq!(v, b"bar");
    }

    #[test]
    fn eom_tempfails_when_body_change_capability_is_missing() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut cfg = CleanerConfig::default();
            cfg.preserve_original_href = false;
            cfg.finalize();

            let mut state = MessageState::default();
            state.add_header(b"From".to_vec(), b"sender@example.com".to_vec(), &cfg);
            state.add_header(
                b"Content-Type".to_vec(),
                b"text/html; charset=utf-8".to_vec(),
                &cfg,
            );
            state.add_body(
                br#"<a href="https://e.example/?utm_source=x&id=1">x</a>"#,
                &cfg,
            );

            handle_eom(
                &mut stream,
                &state,
                &cfg,
                Caps {
                    can_addhdrs: true,
                    can_chgbody: false,
                },
            )
        });

        let mut client = TcpStream::connect(addr).unwrap();
        let (cmd, data) = read_packet(&mut client).unwrap().unwrap();
        assert_eq!(cmd, SMFIR_TEMPFAIL);
        assert!(data.is_empty());
        server.join().unwrap().unwrap();
    }

    #[test]
    fn eom_tempfails_after_accumulated_size_limit() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut cfg = CleanerConfig::default();
            cfg.max_message_size = 10;
            cfg.finalize();
            let mut state = MessageState::default();
            state.add_body(b"123456789", &cfg);
            assert!(state.over_limit);
            handle_eom(
                &mut stream,
                &state,
                &cfg,
                Caps {
                    can_addhdrs: true,
                    can_chgbody: true,
                },
            )
        });

        let mut client = TcpStream::connect(addr).unwrap();
        let (cmd, data) = read_packet(&mut client).unwrap().unwrap();
        assert_eq!(cmd, SMFIR_TEMPFAIL);
        assert!(data.is_empty());
        server.join().unwrap().unwrap();
    }
}

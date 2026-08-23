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
use std::sync::{Arc, Condvar, Mutex};

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

    fn add_header(&mut self, mut name: Vec<u8>, mut value: Vec<u8>, max_message_size: usize) {
        // Defence in depth: an upstream MTA that lets CR/LF leak into the
        // milter `value` would let us reconstruct a message with smuggled
        // headers (the bytes would be emitted verbatim by `reconstruct`).
        // Replace any control byte that isn't tab with a space.
        for byte in &mut value {
            if *byte != b'\t' && (*byte < 0x20 || *byte == 0x7F) {
                *byte = b' ';
            }
        }
        name.retain(|byte| !matches!(*byte, 0..=0x20 | b':' | 0x7F));
        if name.is_empty() {
            return;
        }
        let len = name.len().saturating_add(value.len()).saturating_add(4);
        if self.would_exceed(len, max_message_size) {
            self.over_limit = true;
            return;
        }
        self.bytes_seen += len;
        self.headers.push((name, value));
    }

    fn add_body(&mut self, data: &[u8], max_message_size: usize) {
        if self.would_exceed(data.len(), max_message_size) {
            self.over_limit = true;
            return;
        }
        self.bytes_seen += data.len();
        self.body.extend_from_slice(data);
    }

    fn would_exceed(&self, additional: usize, max_message_size: usize) -> bool {
        self.over_limit
            || self
                .bytes_seen
                .saturating_add(additional)
                .saturating_add(2) // final header/body separator added by reconstruct()
                > max_message_size
    }
}

enum PreparedConfigState {
    Loading,
    Ready(Arc<CleanerConfig>),
    Failed,
}

struct PreparedConfig {
    state: Mutex<PreparedConfigState>,
    ready: Condvar,
}

impl PreparedConfig {
    fn loading() -> Self {
        Self {
            state: Mutex::new(PreparedConfigState::Loading),
            ready: Condvar::new(),
        }
    }

    fn publish(&self, config: Option<CleanerConfig>) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        *state = match config {
            Some(config) => PreparedConfigState::Ready(Arc::new(config)),
            None => PreparedConfigState::Failed,
        };
        self.ready.notify_all();
    }

    fn wait(&self) -> io::Result<Arc<CleanerConfig>> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        loop {
            match &*state {
                PreparedConfigState::Loading => {
                    state = self
                        .ready
                        .wait(state)
                        .unwrap_or_else(|error| error.into_inner());
                }
                PreparedConfigState::Ready(config) => return Ok(Arc::clone(config)),
                PreparedConfigState::Failed => {
                    return Err(io::Error::other("rule preparation failed"));
                }
            }
        }
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
    let listen = config.listen.clone();
    let max_message_size = config.max_message_size;
    let (listener, activated) = acquire_listener(&listen)?;
    let prepared = Arc::new(PreparedConfig::loading());
    eprintln!(
        "email-privacy-milter {} listening on {} (socket={}, rules=loading)",
        crate::VERSION,
        listen,
        if activated { "systemd" } else { "bound" },
    );
    let preparation = Arc::clone(&prepared);
    std::thread::spawn(move || {
        let prepared = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut config = config;
            config.finalize();
            config
        }))
        .ok();
        preparation.publish(prepared);
    });

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let prepared = Arc::clone(&prepared);
                std::thread::spawn(move || {
                    if let Err(e) = handle_connection_preparing(stream, max_message_size, &prepared)
                    {
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

fn acquire_listener(listen: &str) -> crate::error::Result<(TcpListener, bool)> {
    #[cfg(unix)]
    if let Some(listener) = systemd_listener()? {
        return Ok((listener, true));
    }
    Ok((TcpListener::bind(listen)?, false))
}

#[cfg(unix)]
fn systemd_listener() -> crate::error::Result<Option<TcpListener>> {
    use std::os::fd::FromRawFd;

    let listen_fds = std::env::var("LISTEN_FDS").ok();
    let listen_pid = std::env::var("LISTEN_PID").ok();
    let Some(fd) = systemd_activation_fd(
        listen_fds.as_deref(),
        listen_pid.as_deref(),
        std::process::id(),
    )?
    else {
        return Ok(None);
    };

    std::env::remove_var("LISTEN_PID");
    std::env::remove_var("LISTEN_FDS");
    std::env::remove_var("LISTEN_FDNAMES");

    // SAFETY: systemd's socket activation contract places the first inherited
    // descriptor at fd 3. The matching LISTEN_PID check above ensures these
    // variables describe this process rather than stale parent state.
    let listener = unsafe { TcpListener::from_raw_fd(fd) };
    listener.local_addr()?;
    Ok(Some(listener))
}

#[cfg(unix)]
fn systemd_activation_fd(
    listen_fds: Option<&str>,
    listen_pid: Option<&str>,
    process_id: u32,
) -> crate::error::Result<Option<i32>> {
    let Some(fds) = listen_fds else {
        return Ok(None);
    };
    let fds = fds.parse::<u32>().map_err(|_| {
        crate::error::CleanerError::Config("invalid systemd LISTEN_FDS value".into())
    })?;
    if fds == 0 {
        return Ok(None);
    }
    let listen_pid = listen_pid.and_then(|value| value.parse::<u32>().ok());
    if listen_pid != Some(process_id) {
        return Ok(None);
    }
    if fds != 1 {
        return Err(crate::error::CleanerError::Config(format!(
            "systemd passed {fds} sockets; exactly one is required"
        )));
    }
    Ok(Some(3))
}

/// Handle a single milter connection.
pub fn handle_connection(stream: TcpStream, config: &CleanerConfig) -> io::Result<()> {
    let prepared = PreparedConfig {
        state: Mutex::new(PreparedConfigState::Ready(Arc::new(config.clone()))),
        ready: Condvar::new(),
    };
    handle_connection_preparing(stream, config.max_message_size, &prepared)
}

fn handle_connection_preparing(
    mut stream: TcpStream,
    max_message_size: usize,
    prepared: &PreparedConfig,
) -> io::Result<()> {
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
                    state.add_header(name, value, max_message_size);
                }
                write_packet(&mut stream, SMFIR_CONTINUE, &[])?;
            }
            SMFIC_BODY => {
                state.add_body(&data, max_message_size);
                write_packet(&mut stream, SMFIR_CONTINUE, &[])?;
            }
            SMFIC_BODYEOB => {
                let config = prepared.wait()?;
                handle_eom(&mut stream, &state, &config, caps)?;
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
    if data.is_empty() {
        let length = len.to_be_bytes();
        return stream.write_all(&[length[0], length[1], length[2], length[3], cmd]);
    }
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
    use crate::config::{RulePackFormat, RulePackSource};
    use std::time::Duration;

    #[cfg(unix)]
    #[test]
    fn systemd_activation_contract_requires_one_socket_for_this_process() {
        assert_eq!(systemd_activation_fd(None, None, 42).unwrap(), None);
        assert_eq!(
            systemd_activation_fd(Some("0"), Some("42"), 42).unwrap(),
            None
        );
        assert_eq!(
            systemd_activation_fd(Some("1"), Some("41"), 42).unwrap(),
            None
        );
        assert_eq!(
            systemd_activation_fd(Some("1"), Some("42"), 42).unwrap(),
            Some(3)
        );

        let multiple = systemd_activation_fd(Some("2"), Some("42"), 42).unwrap_err();
        assert!(multiple.to_string().contains("exactly one"));
        let invalid = systemd_activation_fd(Some("invalid"), Some("42"), 42).unwrap_err();
        assert!(invalid.to_string().contains("invalid systemd LISTEN_FDS"));
    }

    #[test]
    fn negotiation_runs_while_rules_are_preparing() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let prepared = Arc::new(PreparedConfig::loading());
        let server_prepared = Arc::clone(&prepared);
        let max_message_size = CleanerConfig::default().max_message_size;
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            handle_connection_preparing(stream, max_message_size, &server_prepared)
        });

        let mut client = TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut negotiation = Vec::new();
        negotiation.extend_from_slice(&6u32.to_be_bytes());
        negotiation.extend_from_slice(&u32::MAX.to_be_bytes());
        negotiation.extend_from_slice(&0u32.to_be_bytes());
        write_packet(&mut client, SMFIC_OPTNEG, &negotiation).unwrap();
        assert_eq!(read_packet(&mut client).unwrap().unwrap().0, SMFIR_OPTNEG);

        prepared.publish(Some(CleanerConfig::default()));
        write_packet(&mut client, SMFIC_QUIT, &[]).unwrap();
        server.join().unwrap().unwrap();
    }

    #[test]
    fn eom_waits_for_and_uses_the_finalized_rules() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let prepared = Arc::new(PreparedConfig::loading());
        let server_prepared = Arc::clone(&prepared);
        let max_message_size = CleanerConfig::default().max_message_size;
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            handle_connection_preparing(stream, max_message_size, &server_prepared)
        });

        let mut client = TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();

        let mut negotiation = Vec::new();
        negotiation.extend_from_slice(&6u32.to_be_bytes());
        negotiation.extend_from_slice(&u32::MAX.to_be_bytes());
        negotiation.extend_from_slice(&0u32.to_be_bytes());
        write_packet(&mut client, SMFIC_OPTNEG, &negotiation).unwrap();
        assert_eq!(read_packet(&mut client).unwrap().unwrap().0, SMFIR_OPTNEG);

        write_packet(&mut client, SMFIC_MAIL, b"<sender@example.com>\0").unwrap();
        assert_eq!(read_packet(&mut client).unwrap().unwrap().0, SMFIR_CONTINUE);
        for (name, value) in [
            (b"From".as_slice(), b"sender@example.com".as_slice()),
            (b"MIME-Version".as_slice(), b"1.0".as_slice()),
            (
                b"Content-Type".as_slice(),
                b"text/html; charset=utf-8".as_slice(),
            ),
        ] {
            let mut header = Vec::new();
            header.extend_from_slice(name);
            header.push(0);
            header.extend_from_slice(value);
            header.push(0);
            write_packet(&mut client, SMFIC_HEADER, &header).unwrap();
            assert_eq!(read_packet(&mut client).unwrap().unwrap().0, SMFIR_CONTINUE);
        }
        write_packet(
            &mut client,
            SMFIC_BODY,
            br#"<a href="https://example.test/?worker_token=secret&id=1">x</a>"#,
        )
        .unwrap();
        assert_eq!(read_packet(&mut client).unwrap().unwrap().0, SMFIR_CONTINUE);
        write_packet(&mut client, SMFIC_BODYEOB, &[]).unwrap();

        let error = read_packet(&mut client).unwrap_err();
        assert!(
            matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ),
            "EOM unexpectedly completed before rules were ready: {error}"
        );

        let mut config = CleanerConfig::default();
        config.rule_pack_sources.push(RulePackSource {
            source: "in-memory".into(),
            format: Some(RulePackFormat::ClearUrls),
            usage: None,
        });
        config
            .finalize_with_loader(&mut |_| {
                Ok(br#"{"providers":{"test":{"urlPattern":"^https?://","rules":["worker_token"]}}}"#.to_vec())
            })
            .unwrap();
        prepared.publish(Some(config));

        let mut replacement = Vec::new();
        loop {
            let (command, data) = read_packet(&mut client).unwrap().unwrap();
            match command {
                SMFIR_REPLBODY => replacement.extend_from_slice(&data),
                SMFIR_ADDHEADER => {}
                SMFIR_CONTINUE => break,
                other => panic!("unexpected EOM response: {}", other as char),
            }
        }
        let replacement = String::from_utf8(replacement).unwrap();
        assert!(!replacement.contains("worker_token"), "{replacement}");
        assert!(replacement.contains("id=1"), "{replacement}");

        write_packet(&mut client, SMFIC_QUIT, &[]).unwrap();
        server.join().unwrap().unwrap();
    }

    #[test]
    fn rule_preparation_failure_wakes_waiters() {
        let prepared = Arc::new(PreparedConfig::loading());
        let waiter_prepared = Arc::clone(&prepared);
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        let waiter = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            result_tx.send(waiter_prepared.wait()).unwrap();
        });

        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        prepared.publish(None);
        let error = result_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("rule preparation waiter remained blocked")
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(error.to_string().contains("rule preparation failed"));
        waiter.join().unwrap();
    }

    #[test]
    fn reconstruct_builds_valid_message() {
        let mut s = MessageState::default();
        let cfg = CleanerConfig::default();
        s.add_header(b"Subject".to_vec(), b"Hi".to_vec(), cfg.max_message_size);
        s.add_header(
            b"Content-Type".to_vec(),
            b"text/plain".to_vec(),
            cfg.max_message_size,
        );
        s.add_body(b"hello world\r\n", cfg.max_message_size);
        let raw = s.reconstruct();
        let text = String::from_utf8(raw).unwrap();
        assert!(text.starts_with("Subject: Hi\r\nContent-Type: text/plain\r\n\r\nhello"));
    }

    #[test]
    fn message_state_counts_headers_toward_limit() {
        let mut cfg = CleanerConfig::default();
        cfg.max_message_size = 20;
        let mut s = MessageState::default();
        s.add_header(
            b"Very-Long-Header".to_vec(),
            b"value".to_vec(),
            cfg.max_message_size,
        );
        assert!(s.over_limit);
        assert!(s.headers.is_empty());
    }

    #[test]
    fn message_state_rejects_oversized_body_chunk_before_append() {
        let mut cfg = CleanerConfig::default();
        cfg.max_message_size = 10;
        let mut s = MessageState::default();
        s.add_body(b"123456789", cfg.max_message_size);
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
            state.add_header(
                b"From".to_vec(),
                b"sender@example.com".to_vec(),
                cfg.max_message_size,
            );
            state.add_header(
                b"Content-Type".to_vec(),
                b"text/html; charset=utf-8".to_vec(),
                cfg.max_message_size,
            );
            state.add_body(
                br#"<a href="https://e.example/?utm_source=x&id=1">x</a>"#,
                cfg.max_message_size,
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
            state.add_body(b"123456789", cfg.max_message_size);
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

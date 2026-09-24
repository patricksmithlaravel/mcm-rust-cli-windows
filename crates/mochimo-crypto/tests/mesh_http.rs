#![cfg(all(feature = "mesh-http", not(miri)))]
//! The HTTP transport, exercised against a loopback listener this file
//! controls: the real `ureq` client, real sockets, no network. Every case
//! records the raw request the listener saw and asserts it, so the claim is
//! not "ureq works" but "this transport puts these bytes on the wire and
//! reports these classes when the other end misbehaves".
//!
//! Gated on `mesh-http` (on for every test target through the crate's
//! dev-dependency on itself) and `not(miri)` for the sockets. What this file
//! cannot see: TLS, which nothing in the board exercises; the one live TLS
//! run is `examples/mesh_probe.rs`, by hand.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use mochimo_crypto::mesh::http::UreqTransport;
use mochimo_crypto::mesh::{codec, MeshClient, Transport, MAX_RECON_RESPONSE_BYTES};
use mochimo_crypto::{Error, TransportKind};

const TAG: [u8; 20] = [0x9f; 20];

/// What the listener does after it has read one request.
enum Behaviour {
    /// Write these bytes, then close.
    Reply(Vec<u8>),
    /// Close without writing anything: the shape a panicking handler
    /// produces on the middleware (measured; `net/http` recovers per
    /// connection and drops it).
    Close,
    /// Sit on the connection for this long, then close.
    Hold(Duration),
}

/// One request's worth of loopback server. Returns the base URL, a channel
/// that yields the raw request bytes the server read, and the thread.
fn serve_once(behaviour: Behaviour) -> (String, mpsc::Receiver<Vec<u8>>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("bind: {e}"));
    let port = listener.local_addr().unwrap_or_else(|e| panic!("local_addr: {e}")).port();
    let (tx, rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|e| panic!("accept: {e}"));
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap_or_else(|e| panic!("read timeout: {e}"));
        let request = read_request(&mut stream);
        let _ = tx.send(request);
        match behaviour {
            Behaviour::Reply(bytes) => {
                let _ = stream.write_all(&bytes);
                let _ = stream.flush();
            }
            Behaviour::Close => {}
            Behaviour::Hold(d) => thread::sleep(d),
        }
        let _ = stream.shutdown(std::net::Shutdown::Both);
    });
    (format!("http://127.0.0.1:{port}"), rx, handle)
}

/// Reads one HTTP/1.1 request: headers to the blank line, then
/// `Content-Length` bytes of body.
fn read_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    let header_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        let n = stream.read(&mut chunk).unwrap_or(0);
        if n == 0 {
            return buf;
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).to_ascii_lowercase();
    let content_length: usize = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    while buf.len() < header_end + content_length {
        let n = stream.read(&mut chunk).unwrap_or(0);
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    buf
}

fn response(status: u16, reason: &str, body: &[u8], extra: &str) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

fn transport(base: &str) -> UreqTransport {
    UreqTransport::with_timeouts(base, Duration::from_millis(500), Duration::from_millis(800))
        .unwrap_or_else(|e| panic!("transport: {e}"))
}

/// The request as the listener saw it, split into the request line, the
/// lowercase header block, and the body.
fn split(raw: &[u8]) -> (String, String, Vec<u8>) {
    let i = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or_else(|| panic!("no header terminator in {} bytes", raw.len()));
    let head = String::from_utf8_lossy(&raw[..i]).into_owned();
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or("").to_owned();
    let headers = lines.map(|l| l.to_ascii_lowercase()).collect::<Vec<_>>().join("\n");
    (request_line, headers, raw[i + 4..].to_vec())
}

#[test]
fn loopback_post_carries_the_body_unchanged_and_returns_the_reply() {
    let canned = br#"{"result":{"address":"0x9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f0102030405060708090a0b0c0d0e0f1011121314","amount":42},"idempotent":true}"#;
    let (base, rx, handle) = serve_once(Behaviour::Reply(response(200, "OK", canned, "")));
    let t = transport(&base);
    let body = codec::request_tag_resolve(&TAG);
    let reply = t.post("/call", &body).unwrap_or_else(|e| panic!("post: {e}"));
    assert_eq!(reply, canned.to_vec(), "the transport altered the response body");

    let raw = rx.recv_timeout(Duration::from_secs(5)).unwrap_or_else(|e| panic!("no request seen: {e}"));
    let (line, headers, seen) = split(&raw);
    assert_eq!(line, "POST /call HTTP/1.1");
    assert!(headers.contains("content-type: application/json"), "headers:\n{headers}");
    assert!(headers.contains("accept: application/json"), "headers:\n{headers}");
    assert!(headers.contains(&format!("content-length: {}", body.len())), "headers:\n{headers}");
    // Spelled out rather than built from `CARGO_PKG_NAME`: a test that
    // derives its expectation the way the code does compares the header to
    // itself. This is the wire value, and it is pinned as one.
    assert!(headers.contains("user-agent: mochimo-crypto/"), "headers:\n{headers}");
    assert_eq!(seen, body, "the transport altered the request body");
    handle.join().unwrap_or_else(|_| panic!("server thread panicked"));

    // And through the client: the same bytes parse to the ledger entry.
    let (base, _rx, handle) = serve_once(Behaviour::Reply(response(200, "OK", canned, "")));
    let client = MeshClient::new(transport(&base));
    let entry = client.resolve_tag(&TAG).unwrap_or_else(|e| panic!("resolve_tag: {e}"));
    assert_eq!(entry.balance, 42);
    assert!(entry.address.starts_with(&TAG));
    handle.join().unwrap_or_else(|_| panic!("server thread panicked"));
    println!("  loopback transport: 1 request line, 4 headers and {} body bytes asserted", body.len());
}

#[test]
fn error_object_with_a_200_status_is_reported_as_a_mesh_error() {
    let canned = br#"{"code":4,"message":"Account not found","retriable":true}"#;
    let (base, _rx, handle) = serve_once(Behaviour::Reply(response(200, "OK", canned, "")));
    let client = MeshClient::new(transport(&base));
    let err = client.resolve_tag(&TAG).err().unwrap_or_else(|| panic!("an error object parsed as a ledger entry"));
    assert_eq!(err, Error::Mesh { code: 4, retriable: true });
    handle.join().unwrap_or_else(|_| panic!("server thread panicked"));
    println!("  loopback error object: code 4 reported through a 200");
}

#[test]
fn non_200_status_is_reported_by_status_with_the_body_unread() {
    let (base, _rx, handle) = serve_once(Behaviour::Reply(response(500, "Internal Server Error", b"boom", "")));
    let t = transport(&base);
    let err = t.post("/call", b"{}").err().unwrap_or_else(|| panic!("a 500 returned a body"));
    assert_eq!(err, Error::HttpStatus { status: 500 });
    handle.join().unwrap_or_else(|_| panic!("server thread panicked"));

    let (base, _rx, handle) = serve_once(Behaviour::Reply(response(413, "Request Entity Too Large", b"Request too large\n", "")));
    let err = transport(&base).post("/call", b"{}").err().unwrap_or_else(|| panic!("a 413 returned a body"));
    assert_eq!(err, Error::HttpStatus { status: 413 });
    handle.join().unwrap_or_else(|_| panic!("server thread panicked"));
    println!("  loopback statuses: 500 and 413 reported by status, 2 bodies unread");
}

#[test]
fn oversize_response_is_refused_at_the_cap() {
    // `/call` is a reconciliation endpoint, so the cap that applies is the
    // tight one. The cap is the path's, not the transport's: the same body
    // under `/block` is inside the history cap and would be read.
    let big = vec![b'x'; MAX_RECON_RESPONSE_BYTES + 1];
    let (base, _rx, handle) = serve_once(Behaviour::Reply(response(200, "OK", &big, "")));
    let err = transport(&base).post("/call", b"{}").err().unwrap_or_else(|| panic!("an oversize body was returned"));
    assert!(
        matches!(err, Error::PayloadTooLarge { what: "response body", max, .. } if max == MAX_RECON_RESPONSE_BYTES),
        "{err:?}"
    );
    handle.join().unwrap_or_else(|_| panic!("server thread panicked"));
    println!("  loopback cap: a {}-byte body refused at {MAX_RECON_RESPONSE_BYTES} on /call", big.len());
}

#[test]
fn redirects_are_never_followed() {
    let (base, _rx, handle) = serve_once(Behaviour::Reply(response(
        302,
        "Found",
        b"",
        "Location: http://127.0.0.1:1/elsewhere\r\n",
    )));
    let err = transport(&base).post("/call", b"{}").err().unwrap_or_else(|| panic!("a redirect produced a body"));
    assert!(
        matches!(err, Error::Transport { kind: TransportKind::Redirect, .. }) || err == Error::HttpStatus { status: 302 },
        "a 302 must surface as a redirect refusal or as its status, never be followed: {err:?}"
    );
    handle.join().unwrap_or_else(|_| panic!("server thread panicked"));
    println!("  loopback redirect: 1 302 not followed ({err:?})");
}

#[test]
fn a_dropped_connection_is_a_transport_error_not_a_body() {
    let (base, _rx, handle) = serve_once(Behaviour::Close);
    let err = transport(&base).post("/call", b"{}").err().unwrap_or_else(|| panic!("a dropped connection returned a body"));
    assert!(
        matches!(
            err,
            Error::Transport {
                kind: TransportKind::Connect | TransportKind::Io(_) | TransportKind::Protocol,
                ..
            }
        ),
        "{err:?}"
    );
    handle.join().unwrap_or_else(|_| panic!("server thread panicked"));
    println!("  loopback drop: 1 closed connection reported as {err:?}");
}

#[test]
fn a_silent_server_times_out() {
    let (base, _rx, handle) = serve_once(Behaviour::Hold(Duration::from_secs(3)));
    let err = transport(&base).post("/call", b"{}").err().unwrap_or_else(|| panic!("a silent server returned a body"));
    assert!(
        matches!(err, Error::Transport { kind: TransportKind::Timeout, .. }),
        "{err:?}"
    );
    handle.join().unwrap_or_else(|_| panic!("server thread panicked"));
    println!("  loopback timeout: 1 held connection reported as {err:?}");
}

#[test]
fn a_refused_connection_is_reported_by_kind() {
    // Bind to learn a free port, release it, then connect to it.
    let port = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("bind: {e}"));
        l.local_addr().unwrap_or_else(|e| panic!("local_addr: {e}")).port()
    };
    // Its own timeouts, not `transport`'s. The kind asserted below is the
    // platform's report of the refusal, and when that report comes is the
    // platform's too: at once on Linux and macOS, while Windows retries a
    // connect the port refused before it gives up. Measured on a Windows
    // runner: with `transport`'s 500 ms the refusal was still unreported when
    // the timeout ran out, and the error was `Timeout`. Five seconds is far
    // past those retries, so what this asserts is the classification and not
    // which of two clocks ran out first; on a platform that refuses at once
    // it costs nothing.
    let err = UreqTransport::with_timeouts(
        &format!("http://127.0.0.1:{port}"),
        Duration::from_secs(5),
        Duration::from_secs(6),
    )
    .unwrap_or_else(|e| panic!("transport: {e}"))
    .post("/call", b"{}")
    .err()
    .unwrap_or_else(|| panic!("a refused connection returned a body"));
    assert!(
        matches!(err, Error::Transport { kind: TransportKind::Connect, .. }),
        "{err:?}"
    );
    println!("  loopback refused: 1 closed port reported as {err:?}");
}

#[test]
fn oversize_request_is_refused_before_any_socket_opens() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("bind: {e}"));
    listener.set_nonblocking(true).unwrap_or_else(|e| panic!("nonblocking: {e}"));
    let port = listener.local_addr().unwrap_or_else(|e| panic!("local_addr: {e}")).port();
    let body = vec![b'{'; mochimo_crypto::mesh::MAX_REQUEST_BYTES + 1];
    let err = transport(&format!("http://127.0.0.1:{port}"))
        .post("/call", &body)
        .err()
        .unwrap_or_else(|| panic!("an oversize request was sent"));
    assert!(matches!(err, Error::PayloadTooLarge { what: "request body", .. }), "{err:?}");
    thread::sleep(Duration::from_millis(50));
    assert!(
        listener.accept().is_err(),
        "the transport opened a connection for a body it must refuse"
    );
    println!("  loopback request cap: {} bytes refused, 0 connections opened", body.len());
}

#[test]
fn base_urls_are_checked_at_construction() {
    for bad in ["ftp://x", "http://", "http://h/path", "http://h?x", "http://h#f", "http://u@h", "h"] {
        let err = UreqTransport::new(bad).err().unwrap_or_else(|| panic!("{bad:?} was accepted"));
        assert!(
            matches!(err, Error::Transport { op: "base url", kind: TransportKind::Protocol }),
            "{bad:?}: {err:?}"
        );
    }
    let t = UreqTransport::new("http://127.0.0.1:1/").unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(t.base(), "http://127.0.0.1:1", "one trailing slash is stripped");

    let https = UreqTransport::new("https://example.invalid");
    if cfg!(feature = "mesh-https") {
        assert!(https.is_ok(), "https refused with a TLS provider compiled in: {:?}", https.err());
    } else {
        assert!(
            matches!(https, Err(Error::Transport { op: "base url", kind: TransportKind::Tls })),
            "https must be refused at construction without mesh-https: {:?}",
            https.err()
        );
    }
    println!("  base urls: 7 shapes refused, 1 slash stripped, https {}", if cfg!(feature = "mesh-https") { "accepted" } else { "refused" });
}

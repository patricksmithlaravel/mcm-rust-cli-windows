//! The HTTP transport: `ureq` over a base URL, with every choice that
//! touches safety made explicit and the failure classes mapped to
//! [`TransportKind`] without the message.
//!
//! * **No redirects.** A redirect would re-POST a signed image to a host the
//!   caller did not name.
//! * **Statuses are data.** The middleware's failures are 200s with an error
//!   object; a non-200 is reported as [`Error::HttpStatus`] with the body
//!   unread.
//! * **Bounded in both directions.** A request over the middleware's cap is
//!   refused before the socket opens; a response is read to at most
//!   the cap [`max_response_bytes`] gives that path, and the rest refused.
//! * **`https://` needs `mesh-https`.** Without a TLS provider compiled in,
//!   an `https://` base is refused at construction rather than discovered at
//!   the first request.
//!
//! What this file does not claim: TLS is exercised by nothing in the board
//! (the loopback tests in `tests/mesh_http.rs` speak plain HTTP); the one
//! live TLS run is `examples/mesh_probe.rs`, by hand.

use core::fmt;
use std::time::Duration;

use crate::error::{Error, Result, TransportKind};

use super::{max_response_bytes, Transport, MAX_REQUEST_BYTES};

/// [`Transport`] over `ureq`.
pub struct UreqTransport {
    base: String,
    agent: ureq::Agent,
}

impl UreqTransport {
    /// The connect timeout [`UreqTransport::new`] uses.
    pub const DEFAULT_CONNECT: Duration = Duration::from_secs(10);
    /// The whole-request timeout [`UreqTransport::new`] uses.
    pub const DEFAULT_GLOBAL: Duration = Duration::from_secs(30);

    /// A transport for `base` — `http://host[:port]` or `https://host`, no
    /// path, query or fragment; one trailing slash is stripped — with the
    /// default timeouts.
    pub fn new(base: &str) -> Result<UreqTransport> {
        Self::with_timeouts(base, Self::DEFAULT_CONNECT, Self::DEFAULT_GLOBAL)
    }

    /// [`UreqTransport::new`] with explicit connect and whole-request
    /// timeouts; the loopback tests use short ones.
    pub fn with_timeouts(base: &str, connect: Duration, global: Duration) -> Result<UreqTransport> {
        let base = base.strip_suffix('/').unwrap_or(base);
        let secure = if let Some(rest) = base.strip_prefix("https://") {
            Self::check_authority(rest)?;
            true
        } else if let Some(rest) = base.strip_prefix("http://") {
            Self::check_authority(rest)?;
            false
        } else {
            return Err(Error::Transport {
                op: "base url",
                kind: TransportKind::Protocol,
            });
        };
        if secure && !cfg!(feature = "mesh-https") {
            return Err(Error::Transport {
                op: "base url",
                kind: TransportKind::Tls,
            });
        }
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .timeout_connect(Some(connect))
            .timeout_global(Some(global))
            // `mochimo-crypto/<version>`, both halves read from the package
            // rather than typed, so the header cannot drift from what is
            // actually speaking. The name is the crate's and not the
            // binary's: this transport is library surface, and a dependent
            // driving it is not `tawara`. A node reading this header
            // learns which implementation sent the request, which is the only
            // thing a user agent is for here -- nothing in this tree, in the
            // recorded captures or in the middleware behaves differently on
            // the strength of it.
            .user_agent(concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION")))
            .build();
        Ok(UreqTransport {
            base: base.to_owned(),
            agent: ureq::Agent::new_with_config(config),
        })
    }

    /// `host[:port]` and nothing else: no path, query, fragment or userinfo.
    fn check_authority(rest: &str) -> Result<()> {
        let bad = rest.is_empty() || rest.bytes().any(|b| matches!(b, b'/' | b'?' | b'#' | b'@' | b' '));
        if bad {
            return Err(Error::Transport {
                op: "base url",
                kind: TransportKind::Protocol,
            });
        }
        Ok(())
    }

    /// The base URL this transport posts under.
    pub fn base(&self) -> &str {
        &self.base
    }
}

impl fmt::Debug for UreqTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UreqTransport").field("base", &self.base).finish_non_exhaustive()
    }
}

/// The class of a `ureq` failure, without its message.
fn classify(e: &ureq::Error) -> TransportKind {
    match e {
        ureq::Error::Timeout(_) => TransportKind::Timeout,
        ureq::Error::HostNotFound => TransportKind::Resolve,
        ureq::Error::ConnectionFailed => TransportKind::Connect,
        ureq::Error::Io(io) => match io.kind() {
            std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted => TransportKind::Connect,
            kind => TransportKind::Io(kind),
        },
        ureq::Error::TooManyRedirects | ureq::Error::RedirectFailed => TransportKind::Redirect,
        ureq::Error::Tls(_) => TransportKind::Tls,
        ureq::Error::Protocol(_) | ureq::Error::Http(_) | ureq::Error::BadUri(_) => TransportKind::Protocol,
        _ => TransportKind::Other,
    }
}

impl Transport for UreqTransport {
    fn post(&self, path: &str, body: &[u8]) -> Result<Vec<u8>> {
        if body.len() > MAX_REQUEST_BYTES {
            return Err(Error::PayloadTooLarge {
                what: "request body",
                max: MAX_REQUEST_BYTES,
                got: body.len(),
            });
        }
        let url = format!("{}{}", self.base, path);
        let mut response = self
            .agent
            .post(&url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .send(body)
            .map_err(|e| Error::Transport {
                op: "send",
                kind: classify(&e),
            })?;
        let status = response.status().as_u16();
        if status != 200 {
            return Err(Error::HttpStatus { status });
        }
        // `limit` bounds the read; a body past it is `BodyExceedsLimit`,
        // reported as the size error it is rather than as a transport class.
        // The cap is the endpoint's: history replies scale with what they
        // report and the rest do not, so one number sized from either is wrong
        // for the other.
        let cap = max_response_bytes(path);
        let limit = u64::try_from(cap).unwrap_or(u64::MAX);
        response
            .body_mut()
            .with_config()
            .limit(limit)
            .read_to_vec()
            .map_err(|e| match e {
                ureq::Error::BodyExceedsLimit(_) => Error::PayloadTooLarge {
                    what: "response body",
                    max: cap,
                    got: cap + 1,
                },
                other => Error::Transport {
                    op: "read body",
                    kind: classify(&other),
                },
            })
    }
}

//! `mcm-wallet` — the binary.
//!
//! Thin on purpose: parse argv, get the seed if the store needs one, build the
//! transport, hand off to [`mochimo_crypto::cli::run`], print, exit. Every
//! decision the program makes is in `src/cli/`, where the tests can drive it
//! against a scriptable chain.
//!
//! # Why this lives under `src/` and not in a crate of its own
//!
//! `crates/mochimo-crypto/src/bin/` is inside `crates/*/src`, which is **every
//! existing scan's domain**: the route scan, the panic census, the
//! Debug-holder scan and the endian scan all cover this file with no change to
//! any of them. A separate crate would sit outside several of them, and this
//! is the precedent for choosing a module over a crate.
//!
//! `required-features = ["mesh-https"]` follows the `[[example]] mesh_probe`
//! precedent: no test target links this binary's graph, because building it
//! drags in rustls and `ring`'s C, which the test and Miri configurations
//! keep out. The command layer is under `native` alone and the tests run
//! there. **The default board does build and execute this binary** --
//! `tests/cli.rs`'s pty harness spawns `cargo build --features mesh-https
//! --bin mcm-wallet` as a subprocess and drives the result under a
//! pseudo-terminal -- in the one configuration that compiles any C, `ring`'s,
//! and in a subprocess.
//!
//! # Where the master seed comes from, and what that exposes
//!
//! **Out of the encrypted store, unlocked by a password prompt on the
//! controlling terminal**. Until then it was twenty-four words typed
//! on every invocation -- a decision working exactly as argued and
//! producing an interface nobody would use. The words are now what they are in
//! every other wallet: shown once at creation, written down, and the way back
//! in if the store is lost. They are not the login.
//!
//! **What that transfers, stated because it is a transfer and not a gain.**
//! Before this a stolen store file yielded every *imported* account outright --
//! the roots were in it in the clear -- and no derived account, the seed not
//! being in it. It now yields everything to whoever knows the password and
//! nothing to whoever does not, so password strength is part of the threat
//! model in a way it was not, which is why `cli::create::MIN_PASSWORD_LEN`
//! refuses rather than warns. The full argument is at
//! `keystore::crypt`'s head.
//!
//! The mnemonic prompt's rule survives almost intact: the crate still retains nothing
//! between calls, and the seed lives exactly as long as the handle that
//! decrypted it. What changed is where it comes from.
//!
//! The prompt itself was argued against the alternatives, all of which
//! leave the secret somewhere, and every one of those arguments applies to a
//! password unchanged:
//!
//! * **argv** — `ps` and `/proc/pid/cmdline` show it to the same user, and the
//!   shell writes it to history. At rest, and readable.
//! * **an environment variable** — `/proc/pid/environ`, every child process,
//!   and crash handlers; and it is normally set from a plaintext rc file, so
//!   it is at rest anyway.
//! * **a file** — plaintext at rest. The store is sealed under this
//!   password, so putting the password in a plaintext file hands back the
//!   whole of what the encryption bought — and it buys more than sealing
//!   the roots alone would have,
//!   because the body holds the master seed and the master derives *every*
//!   derived account, where an imported root is one account.
//!
//! What the prompt still exposes, stated rather than implied: the terminal
//! driver's input buffer, and this process's memory until the `Secret`
//! zeroizes — a core dump or an attached debugger inside that window sees it.
//! Neither is fixable here.
//!
//! **What exists before it becomes a `Secret`.**
//! `mnemonic::master_seed_from_phrase` takes a `&str`, so the read buffer is
//! this program's problem, and so is every buffer in front of it.
//! [`read_scrubbed_line`] reads the line, and whatever holds it on the way is
//! zeroized before it is released: the chunk each `read` fills, the line it
//! is gathered into, and the trimmed copy handed back. A buffer that grows by
//! reallocating leaves the old allocation holding the phrase, unzeroed, for
//! the allocator to hand to someone else -- so the line grows by hand -- and
//! a `BufReader` frees its own buffer the same way, which is why none is
//! used.
//!
//! **Read from `/dev/tty`, not stdin**, so that a pipe or a redirect cannot
//! supply the seed silently — the point of choosing a prompt is that the seed
//! never comes from something that can be recorded. On Windows the device is
//! the console's own buffers, `CONIN$` and `CONOUT$`, opened by name for the
//! same reason; the `console` module at the foot of this file is that arm,
//! and [`TERMINAL`] is the one place either is named in a message.
//!
//! **The cost, accepted rather than overlooked:** not scriptable. `balance`
//! prompts, because `Wallet::open` refuses a derived account with no master —
//! "a refusal, not a skip" — so there is no read-only mode to exempt. Testnet
//! is where scripting demand appears, and it runs on a
//! throwaway seed by the ordering condition already recorded.

// `std::process::exit` DOES NOT RUN DESTRUCTORS, and every scrub of key
// material in this program is a `Drop` -- `Zeroizing`, `Secret`, the keystore
// handle. A call to it anywhere below is therefore an exit path on which
// nothing is zeroized, and this program's whole memory-hygiene story is
// destructors.
//
// This file called it twice, in `main`, and was safe only by an ordering
// nothing stated: `run_from_argv` returned before either call, so everything
// it held was already dropped. That is a property of the current shape of
// `main` rather than of anything asserted, and a refactor that held a
// `Keystore` or a `Secret` across the call would have taken it away silently
// -- no test would have failed, because no test can observe a destructor that
// did not run.
//
// `main` now returns `ExitCode` instead. Returning from `main` drops
// everything it owns and then exits with the code, so the hygiene here is
// structural rather than incidental.
//
// THE DENY'S REACH, MEASURED RATHER THAN ASSUMED, because it is narrower than
// it looks. `clippy::exit` does not fire on a call inside `main` -- exiting
// from `main` is what the lint considers idiomatic, so it exempts it. Both
// halves of that were checked here by injecting a call and running the board's
// own clippy row: one inside `main` passes, one inside `run_from_argv` is an
// error at this attribute.
//
// So the two protections are different in kind and neither covers the other's
// ground. Every function in this binary but `main` is held by the lint, which
// is where an exit would do the most damage -- deep in a call stack holding a
// `Keystore`. `main` itself is held by its return type: it has no reason to
// call `exit` now that `ExitCode` carries the code out, and what it owns at
// the end is `argv` and a `Report`, neither of which is key material. That is
// a weaker guarantee than the lint gives the rest of the file, and it is
// written down rather than left to be inferred from the deny above it.
//
// The lint is a `restriction` one, off by default, which is why it is named
// explicitly rather than arriving with a group.
#![deny(clippy::exit)]

use std::io::{self, Write};
use std::process::ExitCode;

use mochimo_crypto::cli::create::{self as create_cmd, Terminal as _, ENTROPY_LEN};
use mochimo_crypto::cli::{self, args, Code};
use mochimo_crypto::keystore::Keystore;
use mochimo_crypto::mesh::http::UreqTransport;
use mochimo_crypto::mesh::{MeshClient, Transport};
use mochimo_crypto::{Error, TransportKind};
use zeroize::Zeroizing;

/// The size of every read a secret line is gathered from, and the room the
/// line starts with.
///
/// A 24-word BIP39 phrase is 24 × 8 + 23 ≈ 215 bytes, so 512 covers every
/// phrase with room to spare and no phrase makes the line grow. A password
/// can -- it has a floor and no ceiling -- and a line that outgrows this is
/// moved by [`read_scrubbed_line`] into a fresh buffer twice the size rather
/// than reallocated, and the one it leaves is zeroized.
const PHRASE_CAPACITY: usize = 512;

/// What a prompt says when the terminal reports end-of-file before a line
/// was typed. Zero bytes read is end of input, not an empty answer, and is
/// refused here, before anything is compared, in the same class as "no
/// terminal" -- so Ctrl-D at the password prompt is reported as the input it
/// was rather than as a wrong password.
#[cfg(unix)]
const END_OF_INPUT: &str =
    "end of input at the prompt: the terminal reported end-of-file (Ctrl-D) before a line was \
     typed, so nothing was read and nothing was compared. Type the answer and press Enter, or \
     run the command again.";
/// What a prompt says when the console reports end of input before a line
/// was typed, refused for the same reason as on Unix. The keys named are
/// Windows' own, because Unix's would send an operator to a key that ends
/// nothing at a console: a `Ctrl-Z` beginning the line, which the `console`
/// module's `CTRL_Z` makes the end of input, and `Ctrl-C`, whose read
/// returned no characters in the run at a Windows console that `FORK.md`
/// records.
#[cfg(windows)]
const END_OF_INPUT: &str =
    "end of input at the prompt: the console reported end of input (Ctrl-Z at the start of the \
     line, or Ctrl-C) before a line was typed, so nothing was read and nothing was compared. \
     Type the answer and press Enter, or run the command again.";

/// The device secrets are read from, as every message about it names it.
///
/// One constant rather than the path spelled in each message, because the
/// `Terminal` impl below serves both platforms: a message there that named
/// `/dev/tty` would name, on Windows, a device the program never opened.
#[cfg(unix)]
const TERMINAL: &str = "/dev/tty";
/// The device secrets are read from, as every message about it names it.
#[cfg(windows)]
const TERMINAL: &str = "the console (CONIN$ and CONOUT$)";

/// What a [`Tty`] reads and writes through: the terminal device by path on
/// Unix, the console's two buffers on Windows. Both are `Read`, `Write` and
/// `try_clone`, which is all the `Terminal` impl asks of it.
#[cfg(unix)]
type Device = std::fs::File;
#[cfg(windows)]
type Device = console::Console;

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let report = match run_from_argv(&argv) {
        Ok(r) => r,
        Err(usage) => {
            eprintln!("{usage}");
            return ExitCode::from(Code::Usage as u8);
        }
    };
    if report.code == Code::Ok {
        println!("{}", report.text);
    } else {
        eprintln!("{}", report.text);
    }
    // `as u8` is exact: `Code` is a four-variant enum over 0..=3, declared in
    // `cli::mod`, and the exit codes the pty harness pins are those same four.
    ExitCode::from(report.code as u8)
}

fn run_from_argv(argv: &[String]) -> Result<cli::Report, args::Usage> {
    let inv = match args::parse(argv)? {
        // Help is an outcome, not an error: it prints and exits 0.
        args::ParsedArgv::Help => {
            return Ok(cli::Report {
                text: args::HELP.to_string(),
                code: Code::Ok,
            })
        }
        args::ParsedArgv::Run(inv) => inv,
    };

    // **A supplied node is validated first, whatever the command**.
    // `UreqTransport::new` opens no socket -- it checks the scheme and the
    // authority and builds an agent -- so a URL this program cannot use is
    // refused before the password prompt and the key derivation, for all ten
    // verbs alike. Until this moved, `create --node <bad>` was accepted
    // silently (dispatched before the transport existed) and `address --node
    // <bad>` was refused AFTER Argon2id, for a command the help says needs no
    // node. The parser has already refused a reconciling command
    // with no `--node`, so `None` arrives only for the two that never dial and
    // becomes the refusing transport below; there is no command-awareness
    // here.
    let node = match &inv.node {
        Some(url) => match UreqTransport::new(url) {
            Ok(t) => Node::Named(t),
            Err(e) => {
                return Ok(cli::Report {
                    text: format!("cannot use node {url}: {e}"),
                    code: Code::StartupRefused,
                })
            }
        },
        None => Node::Absent,
    };

    // `create` is the one command with no store to open -- making one is the
    // point of it -- so it is dispatched before the open below.
    if let args::Command::Create { from_phrase } = inv.command {
        return Ok(run_create(&inv.dir, from_phrase));
    }
    // `submit` is the other command with no store to open: the artifact is
    // its input and the socket its only output, so it is dispatched before
    // the password prompt and the open below. The
    // parser still requires `--dir`, as it does for every verb; the
    // directory is not read, not created and not locked here.
    if let args::Command::Submit { artifact } = &inv.command {
        return Ok(cli::run_submit(&MeshClient::new(node), artifact));
    }

    // The four read-only verbs, on the same route and for the same reason:
    // the node is the whole input, so there is nothing to unlock. `--dir` is
    // parsed and not touched.
    if inv.command.opens_no_store() {
        return Ok(cli::run_explorer(&MeshClient::new(node), &inv.command));
    }

    // **The password, every command that opens a store**. It is not a
    // per-command decision beyond that: the file is encrypted, so nothing
    // -- not even the account list -- can be read without it. That is the
    // whole of the change, and the trade it rests on is at
    // `keystore::crypt`'s head.
    let password = match read_secret_line("password: ") {
        Ok(p) => p,
        Err(e) => {
            return Ok(cli::Report {
                text: e,
                code: Code::StartupRefused,
            })
        }
    };
    let nonce_seed = match os_bytes::<{ mochimo_crypto::keystore::NONCE_SEED_LEN }>() {
        Ok(b) => *b,
        Err(e) => {
            return Ok(cli::Report {
                text: e,
                code: Code::StartupRefused,
            })
        }
    };
    let store = match Keystore::open(
        std::path::Path::new(&inv.dir),
        &mochimo_crypto::keystore::Unlock {
            password: password.as_bytes(),
            nonce_seed,
        },
    ) {
        Ok(s) => s,
        Err(e) => {
            return Ok(cli::Report {
                text: format!("cannot open the keystore at {}: {e}", inv.dir),
                code: Code::StartupRefused,
            })
        }
    };

    Ok(cli::run(store, MeshClient::new(node), &inv.command))
}

/// The transport `cli::run` gets: a real one when `--node` was given, and
/// one that refuses every request when it was not.
///
/// `cli::run` takes a `MeshClient` for every command, including the two that
/// never use it, so an invocation with no node still has to hand one in.
/// This arm is what it hands in, and its `post` is unreachable for the two
/// commands allowed to omit the flag: `create` by construction (dispatched
/// before this exists, and `orchestrate` takes no client) and `address` by
/// measurement (`address_makes_no_request_at_all` counts the transport's
/// calls through a wrapper and finds none). That the arm itself never runs
/// is knowledge rather than a marker: a `[[bin]]`'s items are
/// not importable by any test target, so the pty subprocess is the only
/// thing that executes this type at all. If a later change made either
/// command dial, the operator meets a refusal naming the missing flag rather
/// than a request sent to nowhere -- the fail-closed direction, and the
/// reason this is an enum rather than a placeholder URL.
enum Node {
    Named(UreqTransport),
    Absent,
}

impl Transport for Node {
    fn post(&self, path: &str, body: &[u8]) -> mochimo_crypto::Result<Vec<u8>> {
        match self {
            Node::Named(t) => t.post(path, body),
            Node::Absent => Err(Error::Transport {
                op: "post with no --node given",
                kind: TransportKind::Other,
            }),
        }
    }
}

// `read_master` is gone. It prompted for twenty-four words and turned
// them into a `Secret` on EVERY command; the seed now comes out of the
// encrypted store, so nothing after `create` asks for a mnemonic. That
// closed with encryption at rest -- the two were one mechanism.
// `mnemonic::master_seed_from_phrase` is still reached, once, from
// `cli::create` on the `--from-phrase` path, which is the one place an
// operator genuinely has a phrase and no store.

/// The password prompt of the eight commands that open a store: one line
/// from the controlling terminal, echo off, the prompt on that terminal.
///
/// **The refusal comes before the read.** This once turned echo off,
/// prompted, read the line, and only then refused if echo had not actually
/// been disabled -- so in the one path built to keep the phrase off the screen,
/// the phrase was on the screen by the time the refusal printed. Refusing first
/// costs nothing and is the whole point of the path; [`open_terminal`] holds
/// that order through `?` on the guard.
///
/// # One impl, two callers
///
/// Both callers read through [`Tty`]'s own `read_secret_line`, on a terminal
/// from the same [`open_terminal`], and that is what keeps a prompt attached
/// to the question it asks. A second copy writing prompts with `eprint!`
/// would put them on stderr, where `mcm-wallet ... balance 2>/dev/null`
/// separates the prompt from what it asks about and the operator waits at a
/// silent screen -- the read-only-descriptor defect reached by redirection
/// rather than by a dead descriptor.
///
/// `eprint!` and `eprintln!` panic when stderr cannot be written, so a print
/// macro on this path makes `balance 2>&-` panic out of a binary whose parser
/// argues that panic-freedom is structural. The three print sites in this
/// file are `main`'s, on the report and the usage, and the containment scan's
/// ban covers everything outside it.
/// What establishes that the prompt reaches the screen is
/// `tests/cli.rs::pty::address_on_a_real_pty_needs_no_node_and_its_prompt_survives_a_redirected_stderr`,
/// which runs this path with stderr redirected inside a pty and finds the
/// prompt on the screen and not in the file; the scan's widened ban (no print
/// macro outside `main`) is the cheap early signal, not the proof.
fn read_secret_line(prompt: &str) -> Result<Zeroizing<String>, String> {
    let mut tty = open_terminal()?;
    tty.read_secret_line(prompt)
}

/// Terminal echo, off for as long as the guard lives.
///
/// Existing at all is the point: it makes *echo is off* a precondition the
/// caller cannot skip, and restores on drop so an early return cannot leave a
/// terminal silent. Done by `stty` rather than a `termios` dependency — the
/// only place the binary needs it, and a crate for one call is the shape
/// declined for `tempfile`.
#[cfg(unix)]
struct EchoGuard(std::fs::File);

#[cfg(unix)]
fn echo_off(tty: &std::fs::File) -> Result<EchoGuard, String> {
    let dup = tty
        .try_clone()
        .map_err(|e| format!("cannot duplicate /dev/tty: {e}"))?;
    let off = std::process::Command::new("stty")
        .arg("-echo")
        .stdin(std::process::Stdio::from(
            tty.try_clone()
                .map_err(|e| format!("cannot duplicate /dev/tty: {e}"))?,
        ))
        .status();
    if !matches!(off, Ok(s) if s.success()) {
        return Err(
            "refusing to read a secret with terminal echo on: the words would be visible and \
             may be kept in the terminal's scrollback. Nothing was read."
                .into(),
        );
    }
    Ok(EchoGuard(dup))
}

#[cfg(unix)]
impl EchoGuard {
    /// Turn echo back on **and say whether it worked**.
    ///
    /// `echo_off` refuses when `stty -echo` fails, so the direction that
    /// protects the *secret* is checked. The restore was not: `Drop` runs
    /// `stty echo` and discards the result, and its `if let Ok(dup)` arm skips
    /// the call entirely when the descriptor cannot be duplicated. That
    /// asymmetry is invisible until it bites, and when it bites it reproduces
    /// exactly the failure this ordering exists to prevent -- an operator
    /// typing three words into a terminal that shows nothing, and an `exit 3`.
    ///
    /// So the one caller that *depends* on echo being back — the confirmation
    /// — calls this through `?` and refuses **before** prompting. `Drop` stays
    /// as the best-effort backstop for every other path, where nothing is
    /// waiting to be read and a silent terminal is an annoyance rather than a
    /// lost store.
    fn restore(&self) -> Result<(), String> {
        let dup = self
            .0
            .try_clone()
            .map_err(|e| format!("cannot duplicate /dev/tty to restore terminal echo: {e}"))?;
        let on = std::process::Command::new("stty")
            .arg("echo")
            .stdin(std::process::Stdio::from(dup))
            .status();
        if !matches!(on, Ok(s) if s.success()) {
            return Err(
                "cannot turn terminal echo back on, so the confirmation would be typed blind. \
                 That is how the words get mistyped. Nothing further was read; run `stty echo` \
                 to restore your terminal."
                    .into(),
            );
        }
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for EchoGuard {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

/// `N` bytes from the OS CSPRNG.
///
/// `/dev/urandom` through `std::fs` rather than a crate. The library takes its
/// entropy as a parameter and can reach no generator, which is what keeps a
/// store image deterministic under fixed entropy, so supplying the bytes is
/// the binary's job. The command layer is under `native` alone, so `ring`'s
/// generator is not reachable either.
///
/// Opening a device by path is a platform decision and not an incidental
/// convenience: this is the Unix arm, `lib.rs` states the platforms, and the
/// same arm reads secrets from `/dev/tty` by path for the same reason. The
/// Windows arm is `console::os_bytes`. This is the operating system's
/// generator rather than a hand-rolled one, and every way it can fail is loud
/// -- `File::open` errors and a short `read_exact` errors -- so a weak draw is
/// never returned in place of a strong one.
///
/// **Generic over the width**, because the store now needs three
/// separate draws rather than one: the phrase entropy, the KDF salt and the
/// per-open nonce seed. They are separate draws and not one split three ways --
/// see `cli::create::CreateEntropy`.
#[cfg(unix)]
fn os_bytes<const N: usize>() -> Result<Zeroizing<[u8; N]>, String> {
    use std::io::Read;
    let mut buf = Zeroizing::new([0u8; N]);
    std::fs::File::open("/dev/urandom")
        .map_err(|e| format!("cannot open /dev/urandom: {e}"))?
        .read_exact(&mut buf[..])
        .map_err(|e| format!("cannot read /dev/urandom: {e}"))?;
    Ok(buf)
}

/// Everything `create` draws from the OS, in one value.
fn os_create_entropy() -> Result<Zeroizing<create_cmd::CreateEntropy>, String> {
    Ok(Zeroizing::new(create_cmd::CreateEntropy {
        phrase: *os_bytes::<{ ENTROPY_LEN }>()?,
        salt: *os_bytes::<{ mochimo_crypto::keystore::SALT_LEN }>()?,
        nonce_seed: *os_bytes::<{ mochimo_crypto::keystore::NONCE_SEED_LEN }>()?,
    }))
}

/// `create`: acquire the terminal, then hand off.
///
/// **Everything that decides is in `cli::create::run`.** This function exists
/// to supply two things the library cannot have — a real `/dev/tty` and the OS
/// generator — and its whole contribution to the ordering is that `acquire`
/// is passed rather than called late. See that function's note for why the
/// acquisition is first and what holding the guard longer costs.
fn run_create(dir: &str, from_phrase: bool) -> cli::Report {
    create_cmd::orchestrate(
        std::path::Path::new(dir),
        from_phrase,
        os_create_entropy,
        acquire_terminal,
    )
}

/// The controlling terminal, with echo already off.
///
/// Holds the echo guard for its whole life, so a `Tty` that exists is a
/// terminal that is both present and silent. The guard carries its own
/// duplicated descriptor, so field drop order here is not load-bearing.
struct Tty {
    file: Device,
    _echo: EchoGuard,
}

/// **Read AND write**. `File::open` is `O_RDONLY`, and a descriptor opened
/// that way fails every write from the impl below with `EBADF` -- each one
/// discarded by a `let _ =`, so `create` shows the operator nothing: no
/// password prompt, no phrase, no question, and then an exit 3 on a
/// confirmation nobody was asked, over a store whose only backup nobody saw.
/// Nothing but a terminal finds that, and `tests/cli.rs`'s pty harness is
/// what runs one on every board.
///
/// **The one place the terminal is opened**. `create` acquires it through
/// [`acquire_terminal`] and every other command through [`read_secret_line`],
/// and both are this function, so there is no second open for the next
/// read-only `File::open` to hide in.
#[cfg(unix)]
fn open_terminal() -> Result<Tty, String> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|e| {
            format!(
                "cannot open /dev/tty: {e}. This program reads secrets from the controlling \
                 terminal and there is none here -- it cannot be driven from a pipe, a cron job \
                 or a harness without one."
            )
        })?;
    let _echo = echo_off(&file)?;
    Ok(Tty { file, _echo })
}

/// `create`'s acquisition: [`open_terminal`], in its own words. The promise
/// every refusal from `create` keeps -- "Nothing was created." -- is appended
/// by `orchestrate` at the one seam every refusal goes through, so this does
/// not append it: a seam that renders the text verbatim leaves the sentence
/// to the caller, and an arm that forgets drops it.
fn acquire_terminal() -> Result<Tty, String> {
    open_terminal()
}

/// One line from `from`, trimmed -- or `None` when the input ends before any
/// byte of it arrives -- read so that **every buffer the line passes through
/// is zeroized before it is released**.
///
/// Both of [`Tty`]'s reads come through here, and what they need from it is
/// `BufRead::read_line`'s contract as it stands: zero bytes read is end of
/// input, which the caller refuses as [`END_OF_INPUT`]; bytes and then end
/// of input are a line; `Interrupted` is retried; any other error ends the
/// read with that error; and a line that is not UTF-8 is refused in the
/// words `std` refuses it in. So each message a caller builds from this is
/// the one it would build from `read_line`.
///
/// It is written over `Read` and names no device, so the Windows fork
/// (`FORK.md`'s Rep-1), which runs the same `Terminal` impl over a console
/// reader, can take it unchanged.
///
/// # Why not `BufReader`
///
/// A `BufReader` reads the device into a buffer of its own -- eight
/// kilobytes, from the heap -- and copies the line out of it. Dropping the
/// reader frees that buffer with the line still in it, and a
/// `Zeroizing<String>` on the far side scrubs its own copy and never sees
/// that one: reserving the string's capacity up front stops the string's
/// growth from leaving a copy, and does nothing about a reader in front of it
/// that keeps one. Nor can the reader be cleaned up after. It owns the
/// allocation and exposes only the part not yet consumed, and that by shared
/// reference, so there is no handle on the bytes to zeroize.
///
/// # Why a whole chunk per read, and not one byte
///
/// One byte per `read` would never consume past the newline, and it is
/// refused because `Read` promises nothing about a buffer that small being
/// accepted. A reader that transcodes needs room for a whole character per
/// call: the Windows fork's console reader turns UTF-16 into UTF-8 and
/// refuses any buffer shorter than six bytes -- read in that fork's source,
/// not run. `Read::bytes`, the ready-made form, trips
/// `clippy::unbuffered_bytes` on a `File` as well -- an error under the
/// board's `-D warnings` -- and the remedy the lint prints is the `BufReader`
/// this function exists to avoid.
///
/// For the same reason every `read` is offered the whole of `chunk`, never
/// the few bytes left at the end of a line that is filling up. What one read
/// delivers after the newline is dropped with `chunk`, zeroized, as a
/// `BufReader` dropped with bytes still buffered drops them. From this
/// program's terminal there is nothing to drop: a terminal in canonical mode
/// delivers at most one line per `read`, and `stty -echo` leaves the mode
/// canonical.
///
/// # Why the line grows by hand
///
/// `Vec`'s own growth reallocates, and a reallocation that moves frees the
/// allocation it moved out of with the line still in it; `zeroize`'s `Vec`
/// impl says of itself that it *"cannot ensure that previous reallocations
/// did not leave values on the heap"*. Refusing a line longer than a fixed
/// buffer is not the way out it looks like: a password has a floor
/// (`cli::create::MIN_PASSWORD_LEN`) and no ceiling, so a store `create`
/// sealed under a longer one would stop opening. So the line starts at
/// [`PHRASE_CAPACITY`], which no phrase outgrows, and past it moves into a
/// fresh `Zeroizing` buffer of twice the size, the old one scrubbed as it is
/// dropped. A `Vec<u8>` holds at most `isize::MAX` bytes, so the doubling
/// cannot overflow.
///
/// # What this establishes, and what it does not
///
/// Measured, with a global allocator that scanned every block as it was
/// freed, reading over a pipe -- one `read(2)` into the slice handed in, as
/// `File` reads `/dev/tty`. At 215, 600 and 9,000 bytes the `BufReader` path
/// freed an 8,192-byte block holding the line every time, and at 9,000 a
/// second, the string's outgrown allocation; this function freed none. The
/// same harness ran both over 300,000 scripted readers -- partial lines, end
/// of input, `Interrupted`, errors, invalid UTF-8, characters split across
/// reads, lines past the capacity -- and they agreed on every one; and a
/// reader refusing buffers under six bytes had a 1,500-byte line read from it
/// whole.
///
/// **Nothing on the board holds any of that.** The harness is not in this
/// repository. A `[[bin]]`'s items are importable by no test target, so
/// holding this on the board would mean moving the function into the library
/// as public surface, which is a larger change than this one and is not made
/// here. A `BufReader` put back here therefore turns nothing red:
/// `tests/cli.rs`'s pty harness drives these reads end to end and observes
/// what reaches the screen, not what reaches the allocator.
///
/// Out of reach entirely: the terminal driver's own buffers, which the module
/// doc names; whatever a `Read` implementation holds before it fills `chunk`
/// -- `File` holds nothing, its `read` being one system call into the slice;
/// and copies the compiler makes of a byte, in a register or a spilled stack
/// slot, which no `Drop` reaches.
fn read_scrubbed_line(mut from: impl io::Read) -> io::Result<Option<Zeroizing<String>>> {
    let mut chunk = Zeroizing::new([0u8; PHRASE_CAPACITY]);
    let mut line: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(PHRASE_CAPACITY));
    let mut ended = false;
    while !ended {
        let n = match from.read(&mut chunk[..]) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        for &byte in chunk.iter().take(n) {
            if line.len() == line.capacity() {
                let mut wider = Zeroizing::new(Vec::with_capacity(line.capacity() * 2));
                wider.extend_from_slice(&line);
                line = wider;
            }
            line.push(byte);
            if byte == b'\n' {
                ended = true;
                break;
            }
        }
    }
    if line.is_empty() {
        return Ok(None);
    }
    let text = std::str::from_utf8(&line).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "stream did not contain valid UTF-8",
        )
    })?;
    Ok(Some(Zeroizing::new(text.trim().to_string())))
}

impl create_cmd::Terminal for Tty {
    /// **To the terminal this `Tty` acquired, not to stdout**.
    ///
    /// It was `println!` once, and that quietly falsified two things at
    /// once. `/dev/tty` was acquired precisely so a phrase could not reach
    /// *"whatever captured stdout"* (in as many words) — and then the
    /// display went to stdout anyway, so `mcm-wallet ... create > seed.txt`
    /// wrote the twenty-four words into a plaintext file, which is the exact
    /// exposure `create`'s module doc enumerates. And the confirmation prompt
    /// goes to stderr, so under any redirection the operator was asked to read
    /// back words from a screen that had never shown them: an `exit 3` by
    /// construction, and the argument for echoing the confirmation —
    /// *the phrase is three lines above in the same scrollback* — was an
    /// argument about a screen the phrase might never have reached.
    ///
    /// Writing to `self.file` makes that premise true by construction: the
    /// phrase and the question now travel on the same descriptor, the one the
    /// operator is sitting in front of, and no shell redirection separates
    /// them.
    ///
    /// **The write's result is returned, not discarded**. This method
    /// once argued that a failed write need not be reported because *"the
    /// confirmation immediately afterwards is what establishes the operator
    /// actually read it, which is a stronger check than an `io::Result` on
    /// the write would be."* That reasoning is what failed: the confirmation
    /// is asked on the **same descriptor**, by design, so a descriptor that
    /// cannot be written fails both the display and the question together and
    /// the confirmation cannot see the failure it was supposed to catch. The
    /// two checks are complementary, not ordered by strength -- the `Result`
    /// catches the descriptor class (`EBADF`, `EIO`, a pty that went away),
    /// the confirmation catches the human class (present, could read it) --
    /// and `orchestrate` refuses on this `Err` before anything is written.
    fn show(&mut self, text: &str) -> Result<(), String> {
        use std::io::Write as _;
        let mut out = self
            .file
            .try_clone()
            .map_err(|e| format!("cannot write to {TERMINAL}: {e}"))?;
        out.write_all(text.as_bytes())
            .and_then(|()| out.write_all(b"\n"))
            .and_then(|()| out.flush())
            .map_err(|e| format!("cannot write to {TERMINAL}: {e}"))
    }

    /// The confirmation, **visible** — see the trait method's note for why
    /// echoing three words of a phrase that is three lines above costs
    /// nothing, and why consuming `self` is what keeps the acquisition's property.
    ///
    /// The implementation is the natural one rather than a careful one, and
    /// that is the design working: **releasing the echo guard is the whole
    /// mechanism.** `EchoGuard::drop` restores echo, which it was going to do
    /// when this `Tty` fell out of scope a few lines later; the only thing
    /// that changed is that the one caller who wants the answer visible drops
    /// it first. Nothing turns echo on by hand, so there is no second place
    /// for the two states to disagree, and no window a secret read could be
    /// added into later -- `self` is gone.
    fn read_visible_line(self, prompt: &str) -> Result<Zeroizing<String>, String> {
        let Tty { file, _echo } = self;
        // Restore echo, CHECKED, and refuse before prompting if it did not
        // work -- the whole contract of this method is that the answer is
        // visible, so an unverifiable restore is a precondition failure and
        // not a detail. `_echo` still drops afterwards, best-effort, which is
        // what every other path relies on.
        _echo.restore()?;
        drop(_echo);
        let mut term = file
            .try_clone()
            .map_err(|e| format!("cannot write to {TERMINAL}: {e}"))?;
        // The prompt's write is checked: a question that could not be
        // asked is a precondition failure of a method whose contract is that
        // the operator answers it, not a detail to read past.
        term.write_all(prompt.as_bytes())
            .and_then(|()| term.flush())
            .map_err(|e| format!("cannot write to {TERMINAL}: {e}"))?;
        let read = read_scrubbed_line(
            file.try_clone()
                .map_err(|e| format!("cannot read {TERMINAL}: {e}"))?,
        );
        match read {
            Ok(None) => Err(END_OF_INPUT.into()),
            Ok(Some(line)) => Ok(line),
            Err(e) => Err(format!("cannot read from {TERMINAL}: {e}")),
        }
    }

    /// The prompt goes to the acquired terminal too.
    ///
    /// It went to stderr, which is a process-wide stream and can be
    /// redirected: `create --from-phrase 2>log` asked for twenty-four words
    /// with nothing on screen. Same defect as `show`'s, on the other stream,
    /// and the containment scan now forbids both spellings inside this impl.
    fn read_secret_line(&mut self, prompt: &str) -> Result<Zeroizing<String>, String> {
        let mut term = self
            .file
            .try_clone()
            .map_err(|e| format!("cannot write to {TERMINAL}: {e}"))?;
        // Checked, as in `read_visible_line`. A password prompt that
        // never appeared reads a password typed blind, or waits forever on
        // an operator who was never asked.
        term.write_all(prompt.as_bytes())
            .and_then(|()| term.flush())
            .map_err(|e| format!("cannot write to {TERMINAL}: {e}"))?;
        let read = read_scrubbed_line(
            self.file
                .try_clone()
                .map_err(|e| format!("cannot read {TERMINAL}: {e}"))?,
        );
        // The newline after an echo-off read is cosmetic -- the operator's
        // Enter was not echoed -- so this one is the one write here whose
        // failure changes nothing that matters, and it stays best-effort.
        let _ = term.write_all(b"\n");
        match read {
            Ok(None) => Err(END_OF_INPUT.into()),
            Ok(Some(line)) => Ok(line),
            Err(e) => Err(format!("cannot read from {TERMINAL}: {e}")),
        }
    }
}

#[cfg(windows)]
use console::{open_terminal, os_bytes, EchoGuard};

/// The Windows console, in place of `/dev/tty`, `stty` and `/dev/urandom`.
///
/// **What stands in for what.** The device is the console's own input buffer
/// and active screen buffer, opened by name as `CONIN$` and `CONOUT$` -- the
/// Windows form of opening `/dev/tty` by path, and for the same reason:
/// neither is a standard stream, so a pipe or a redirect of stdin, stdout or
/// stderr supplies nothing and captures nothing. Echo is the input buffer's
/// `ENABLE_ECHO_INPUT` mode bit rather than `stty`. The generator is
/// `BCryptGenRandom` with the system-preferred provider, the documented
/// interface to the one Windows generator, rather than `/dev/urandom`.
///
/// **Why the reads and writes are `ReadConsoleW` and `WriteConsoleW`**, and
/// not `std::fs::File` over the same handles. `ReadFile` on a console returns
/// bytes in the console's input code page, so a password containing one
/// non-ASCII character would be different bytes on Windows than on Linux for
/// the same keystrokes -- and a store sealed on one would refuse the "same"
/// password on the other. The wide calls deliver UTF-16, which is transcoded
/// here, so a password's bytes are its UTF-8 on all three platforms. Output
/// goes the same way for the same reason in the other direction.
///
/// `Console` implements `Read` and `Write`, which is what lets the
/// `Terminal` impl above serve both platforms unchanged: its ordering -- the
/// refusal before the read, the checked restore before the visible prompt,
/// end of input refused as such -- is written once, and a fix to it reaches
/// Windows in the same commit it reaches Unix.
///
/// # What has run, and what is not established
///
/// **One person's run at a console, and no test.** It compiles and passes
/// clippy for `x86_64-pc-windows-msvc` from a macOS host, and the board on a
/// Windows runner builds it natively, but nothing on any board executes it:
/// `tests/cli.rs`'s pseudo-terminal harness, which establishes the Unix
/// arm's prompts, has no Windows counterpart. What has executed is one run of
/// the shipped binary, built from `e8d73aa`, by a person at a Windows 11
/// console on x86-64, in an elevated session; `FORK.md` records its results.
/// Against the five things this arm rests on:
///
/// * A line longer than one read arrives over several `ReadConsoleW` calls,
///   and a long phrase is one: at the sizes `READ_UNITS`'s doc gives, its 215
///   characters and CR LF take two. Joining them rests on the console keeping
///   the rest of a cooked line for the next call, as Microsoft's page on the
///   high-level console functions says -- "Unread characters are buffered
///   until the next read operation". **Run:** a 215-character phrase, read
///   over two calls, derived the destination macOS derives from it.
/// * `Ctrl-Z` ends the input only when it begins a line, and `Console` tells
///   a line's start by whether the read before it ended on the line feed a
///   cooked read hands back with the Enter that ends the line.
///   `SetConsoleMode`'s page documents, for `ENABLE_LINE_INPUT`, that a read
///   returns only once a carriage return is read; the line feed after it is
///   what `read_scrubbed_line` stops on, at a console as at a terminal, so the
///   test rests on nothing the shared reader does not. **Run:** a `Ctrl-Z`
///   beginning a line was refused as end of input, and one typed as the
///   170th character of a line was a character of that line.
/// * The console mode belongs to the console's input buffer, which the
///   parent shell shares. Restoring it is the guard's job on every path that
///   unwinds, and it is checked where a visible answer depends on it.
///   **Run:** the confirmation after the phrase echoed, and so did the shell
///   once `create` returned.
/// * `Ctrl-C` at a prompt: by Microsoft's documentation the default control
///   handler ends the process, which runs no destructor and would leave echo
///   off in that console -- the Unix arm's `SIGINT` gap in another shape,
///   which the README's limits carry for signals. **Run, from PowerShell:**
///   the prompt's read returned no characters, the refusal printed was the
///   end-of-input one, and the shell echoed afterwards, the guard having
///   restored the mode before that refusal. Whether the handler ended the
///   process after it, and whether the read returns first every time, is not
///   established.
/// * Under a terminal that is not a Windows console and hosts no
///   pseudo-console -- `mintty` without `winpty` -- `CONIN$` may open a
///   console nobody can see, and the prompt would wait for input nobody can
///   type. Windows Terminal, the classic console host and editors that host a
///   pseudo-console are the case this is written for. **Run:** through
///   `winpty` the prompt worked; what it did without is not recorded.
///
/// The same run carried a password with `ü`, `ß`, `ñ` and `ú`, and one with
/// two emoji, through the wide calls to the UTF-8 macOS sealed stores under,
/// and saw `BCryptGenRandom` return success for the three draws `create`
/// makes. It is one elevated session on one machine.
#[cfg(windows)]
mod console {
    use std::fs::File;
    use std::io::{self, Read, Write};
    use std::os::windows::io::AsRawHandle;
    use std::ptr;

    use windows_sys::Win32::Security::Cryptography::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG};
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, ReadConsoleW, SetConsoleMode, WriteConsoleW, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT,
    };
    use zeroize::Zeroizing;

    use super::Tty;

    /// The most UTF-16 units asked of one `ReadConsoleW`, whatever buffer a
    /// caller offers: a ceiling, and not the bound that binds. `Console::read`
    /// asks for a third of the buffer it is offered, less a unit, and
    /// `read_scrubbed_line` offers `PHRASE_CAPACITY` bytes, so one read takes
    /// at most 169 units, and one more when it ends on a high surrogate. A
    /// line longer than that arrives over several reads, which
    /// `read_scrubbed_line` joins: a twenty-four-word phrase can be 215
    /// characters and a CR LF, so a long one takes two. The module's list of
    /// what is not established says what the joining rests on.
    const READ_UNITS: usize = 4096;

    /// What a line beginning with `Ctrl-Z` means at a Windows console: end of
    /// input, as it is to `std`'s own console reader at the start of a line.
    /// It reaches the shared code as a zero-byte read, which is refused as
    /// `END_OF_INPUT`, since nothing came before it on the line.
    ///
    /// **The test is per line, not per read.** A line longer than one read
    /// arrives over several -- at the size `READ_UNITS`'s doc gives, the 170th
    /// character of a line with no surrogate pair before it begins the second
    /// -- and a `Ctrl-Z` that falls first in a later read is a character of
    /// the line, as a `Ctrl-Z` anywhere else in it is. `Console` knows whether
    /// a read begins a line from the read before it, so where a line breaks
    /// into reads, which the buffer `read_scrubbed_line` offers decides,
    /// decides nothing here.
    const CTRL_Z: u16 = 0x1A;

    /// Where a line ends, as `read_scrubbed_line` reads one: the line feed of
    /// the CR LF a cooked read hands back with the Enter that ends the line.
    const LF: u16 = 0x0A;

    /// The console's input buffer and active screen buffer.
    pub(super) struct Console {
        input: File,
        output: File,
        /// Whether the next read begins a line: set when the console is
        /// opened, cleared by a read that ends inside a line, and set again
        /// by one that ends on `LF`. `CTRL_Z`'s test asks it.
        ///
        /// A clone carries the flag of the handle it came from. Every clone
        /// this program takes is of a handle the `Terminal` impl never reads
        /// through, so each begins at a line's start, and `read_scrubbed_line`
        /// reads one clone to the end of one line and no further.
        at_line_start: bool,
    }

    impl Console {
        pub(super) fn try_clone(&self) -> io::Result<Console> {
            Ok(Console {
                input: self.input.try_clone()?,
                output: self.output.try_clone()?,
                at_line_start: self.at_line_start,
            })
        }

        fn read_units(&self, out: &mut [u16]) -> io::Result<usize> {
            let len = u32::try_from(out.len()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
            let mut read = 0u32;
            // SAFETY: `out` is `len` writable UTF-16 units, `read` is a valid
            // place for the count, and the input-control argument is
            // optional and null. The handle is `CONIN$`, which `input` owns.
            let ok = unsafe {
                ReadConsoleW(self.input.as_raw_handle(), out.as_mut_ptr().cast(), len, &mut read, ptr::null())
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(read as usize)
        }
    }

    impl Read for Console {
        /// One `ReadConsoleW`, transcoded to UTF-8 into `buf`.
        ///
        /// At most a third of `buf.len()` units are asked for, because one
        /// UTF-16 unit is at most three UTF-8 bytes and a surrogate pair is
        /// four bytes from two units, so the transcoding always fits and no
        /// typed byte has to be held here between calls. A read that ends on
        /// a high surrogate is completed by one more unit, which the same
        /// bound has room for, so a pair is never split across two reads.
        ///
        /// A read that begins a line with `Ctrl-Z` is end of input, and
        /// `CTRL_Z`'s doc says why it must begin a line and not only a read.
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let want = (buf.len() / 3).min(READ_UNITS);
            if want < 2 {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            let mut units = Zeroizing::new(vec![0u16; want]);
            let mut n = self.read_units(&mut units[..want - 1])?;
            if n > 0 && (0xD800..0xDC00).contains(&units[n - 1]) {
                n += self.read_units(&mut units[n..n + 1])?;
            }
            let begins_a_line = self.at_line_start;
            if let Some(&last) = units[..n].last() {
                self.at_line_start = last == LF;
            }
            if begins_a_line && units[..n].first() == Some(&CTRL_Z) {
                return Ok(0);
            }
            let mut written = 0;
            for c in char::decode_utf16(units[..n].iter().copied()) {
                let c = c.map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
                written += c.encode_utf8(&mut buf[written..]).len();
            }
            Ok(written)
        }
    }

    impl Write for Console {
        /// All of `buf`, as UTF-16, or an error.
        ///
        /// `buf` must be whole UTF-8: every caller writes a `&str`'s bytes in
        /// one call, and a slice that splits a character is refused as
        /// `InvalidData` rather than written as a replacement character. The
        /// wide copy is zeroized, because the phrase passes through here, and
        /// its capacity is reserved before it is filled -- a string never has
        /// more UTF-16 units than UTF-8 bytes -- so it never grows and never
        /// leaves a copy behind, the reason `PHRASE_CAPACITY` exists.
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let text = std::str::from_utf8(buf).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
            let mut units: Zeroizing<Vec<u16>> = Zeroizing::new(Vec::with_capacity(text.len()));
            units.extend(text.encode_utf16());
            let mut done = 0;
            while done < units.len() {
                let rest = &units[done..];
                let len = u32::try_from(rest.len()).unwrap_or(u32::MAX);
                let mut wrote = 0u32;
                // SAFETY: `rest` holds at least `len` readable units, `wrote`
                // is a valid place for the count, and the reserved argument
                // is null as documented. The handle is `CONOUT$`, which
                // `output` owns.
                let ok = unsafe {
                    WriteConsoleW(self.output.as_raw_handle(), rest.as_ptr(), len, &mut wrote, ptr::null())
                };
                if ok == 0 {
                    return Err(io::Error::last_os_error());
                }
                if wrote == 0 {
                    return Err(io::ErrorKind::WriteZero.into());
                }
                done += wrote as usize;
            }
            Ok(buf.len())
        }

        /// `WriteConsoleW` is unbuffered, so there is nothing to flush.
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// The console's echo, off for as long as the guard lives. The Windows
    /// arm of the Unix `EchoGuard`, with the same two directions: turning echo
    /// off is refused on failure, and restoring it is checked by the one
    /// caller whose answer must be visible.
    pub(super) struct EchoGuard {
        input: File,
        mode: u32,
    }

    /// Turn echo off, keeping line input on.
    ///
    /// **Line input is set, not just kept.** The console needs it for echo to
    /// be off at all, and it is what gives the operator backspace while
    /// typing blind -- the Unix terminal's canonical mode. The mode found is
    /// what the guard restores, whatever it was.
    pub(super) fn echo_off(console: &Console) -> Result<EchoGuard, String> {
        let input = console
            .input
            .try_clone()
            .map_err(|e| format!("cannot duplicate the console input handle: {e}"))?;
        let handle = input.as_raw_handle();
        let mut mode = 0u32;
        // SAFETY: `handle` is the `CONIN$` handle `input` owns, and `mode` is
        // a valid place for the mode.
        let found = unsafe { GetConsoleMode(handle, &mut mode) } != 0;
        // SAFETY: the same handle, and a mode derived from the one it reported.
        let set = found && unsafe { SetConsoleMode(handle, (mode | ENABLE_LINE_INPUT) & !ENABLE_ECHO_INPUT) } != 0;
        if !set {
            return Err(
                "refusing to read a secret with terminal echo on: the words would be visible and \
                 may be kept in the terminal's scrollback. Nothing was read."
                    .into(),
            );
        }
        Ok(EchoGuard { input, mode })
    }

    impl EchoGuard {
        /// Put back the mode found **and say whether it worked**; the Unix
        /// arm's note on `restore` is the argument for checking it.
        pub(super) fn restore(&self) -> Result<(), String> {
            // SAFETY: the `CONIN$` handle `input` owns, and the mode the
            // console itself reported for it.
            if unsafe { SetConsoleMode(self.input.as_raw_handle(), self.mode) } == 0 {
                return Err(
                    "cannot turn console echo back on, so the confirmation would be typed blind. \
                     That is how the words get mistyped. Nothing further was read; close this \
                     console window and open another to restore it."
                        .into(),
                );
            }
            Ok(())
        }
    }

    impl Drop for EchoGuard {
        fn drop(&mut self) {
            let _ = self.restore();
        }
    }

    /// The console, with echo already off. The Windows arm of
    /// `open_terminal`, and like it the one place the device is opened.
    ///
    /// Read AND write on both names: `SetConsoleMode` needs the input buffer
    /// opened for both, and `GetConsoleMode` on the screen buffer does too.
    /// `std` passes a name this short to `CreateFileW` unchanged, which is
    /// what makes the two device names reachable through `OpenOptions` --
    /// read in `std`'s Windows path source, not run.
    pub(super) fn open_terminal() -> Result<Tty, String> {
        let open = |name: &str| {
            std::fs::OpenOptions::new().read(true).write(true).open(name).map_err(|e| {
                format!(
                    "cannot open {name}: {e}. This program reads secrets from the console it runs \
                     in and there is none here -- it cannot be driven from a pipe, a scheduled \
                     task or a harness without one."
                )
            })
        };
        let file = Console {
            input: open("CONIN$")?,
            output: open("CONOUT$")?,
            at_line_start: true,
        };
        let _echo = echo_off(&file)?;
        Ok(Tty { file, _echo })
    }

    /// `N` bytes from the system generator: the Windows arm of `os_bytes`.
    ///
    /// Every way it can fail is loud, as on Unix: a draw too wide for one call
    /// is refused before the call, and a non-zero status is an error, so a
    /// weak draw is never returned in place of a strong one.
    pub(super) fn os_bytes<const N: usize>() -> Result<Zeroizing<[u8; N]>, String> {
        let mut buf = Zeroizing::new([0u8; N]);
        let len = u32::try_from(N).map_err(|_| format!("a {N}-byte draw does not fit one BCryptGenRandom call"))?;
        // SAFETY: a null algorithm handle with the system-preferred flag is
        // the documented form of the call, and `buf` is `len` writable bytes.
        let status = unsafe { BCryptGenRandom(ptr::null_mut(), buf.as_mut_ptr(), len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
        if status != 0 {
            return Err(format!("the system random generator failed (BCryptGenRandom, NTSTATUS {status:#010x})"));
        }
        Ok(buf)
    }
}

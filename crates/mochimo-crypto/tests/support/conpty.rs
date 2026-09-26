//! A console the tests can type at on Windows.
//!
//! `tests/cli.rs`'s `pty` module drives the shipped binary under `script(1)`,
//! and Windows has no `script`. What stands in for it is the pseudoconsole:
//! `CreatePseudoConsole` makes a console whose input and output are two pipes
//! this module holds, and a process created with
//! `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` is attached to it as it would be to a
//! console window. The binary opens `CONIN$` and `CONOUT$` by name, so here it
//! makes the calls it makes at any console -- `ReadConsoleW` on a cooked line,
//! the echo bit, `WriteConsoleW` -- and this module sits where the terminal
//! would: what a person types goes into the input pipe, and what the console
//! shows comes out of the output pipe.
//!
//! # What this rests on, from Microsoft's console pages
//!
//! * **The channels are synchronous pipes.** `CreatePseudoConsole` takes an
//!   input and an output handle, each "currently restricted to synchronous
//!   I/O". `std::io::pipe` is, on Windows, `CreatePipe` with no security
//!   attributes -- read in the nightly toolchain's copy of `std`'s source, the
//!   one toolchain with `rust-src` on the macOS host this was written on --
//!   which is the call Microsoft's own session sample makes for these two
//!   channels, and whose handles "cannot be inherited".
//! * **Each channel is serviced apart.** The session page recommends a thread
//!   per channel "to prevent race conditions and deadlocks": a console whose
//!   output pipe is full stops, so a reader thread drains it from the moment
//!   the process exists, and input is written only after the prompt it
//!   answers has been seen.
//! * **The ends given to the console are closed here once the process
//!   exists**, as the session page asks, "to properly detect a broken channel":
//!   when the console closes, its output pipe breaks and the reader thread
//!   ends.
//! * **What comes out is a rendering.** "The input and output streams encoded
//!   as UTF-8 contain plain text interleaved with Virtual Terminal Sequences."
//!   [`visible`] removes the sequences before anything is matched, and a
//!   needle is matched without its trailing blanks, since the rendering may
//!   move the cursor past a trailing blank rather than send one.
//! * **Keys go in as text.** "On the input stream, plain text represents
//!   standard keyboard keys input by a user." Enter is a carriage return, as a
//!   terminal's Enter key sends it, and a cooked read hands it to the program
//!   as CR LF, the line end the binary's reader stops on. `Ctrl` and a letter
//!   go in as the letter's control character, which the page on virtual
//!   terminal sequences describes as "a single character shifted down into
//!   the control character reserved space (0x0-0x1f)". That page is about the
//!   sequences the console itself emits, so for this direction the tests that
//!   type `Ctrl-Z` are the measurement.
//! * **Closing the console ends what is attached to it.** `ClosePseudoConsole`
//!   "will send CTRL_CLOSE_EVENT to each client application that is still
//!   connected". From build 26100 of Windows 11 it returns at once; before
//!   that it waits for the clients to go, which the reader thread lets it do
//!   without a deadlock.
//!
//! # stdout and stderr are files
//!
//! As in the `pty` module, which runs the binary through a two-line shell
//! script that redirects them inside the pty: here `cmd.exe /c` does the
//! redirecting inside the pseudoconsole. So the console's output holds only
//! what the binary writes to `CONOUT$` and what the console echoes, and the
//! two files hold what a redirect would capture. Every test asserts an exit
//! code, so a `cmd.exe` that did not pass its command's code through would
//! fail every one of them.
//!
//! No crate beyond `windows-sys`, which the permission model and the console
//! module already use, and no feature of it beyond the ones they enable. Each
//! call `std` has no wrapper for states its condition at the site.

use std::ffi::{c_void, OsStr};
use std::io::{self, PipeWriter, Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::OnceLock;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::System::Console::{ClosePseudoConsole, CreatePseudoConsole, COORD, HPCON};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess, InitializeProcThreadAttributeList,
    TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject, EXTENDED_STARTUPINFO_PRESENT,
    LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, STARTUPINFOEXW,
};

/// How long one step may take before the session is ended and the test fails
/// with the transcript: the `pty` module's bound, for the same slow step --
/// Argon2id at `Kdf::RECOMMENDED` in the debug profile, paid once per store
/// the binary writes.
pub const STEP: Duration = Duration::from_secs(300);

/// Enter, as a terminal's Enter key sends it.
pub const ENTER: &[u8] = b"\r";

/// `Ctrl-Z`, as its control character.
pub const CTRL_Z: &[u8] = b"\x1a";

/// The console's width, in characters: wide enough that no line the binary
/// writes wraps. The longest is the recovery phrase's, twenty-four words of at
/// most eight letters, indented by two.
const COLUMNS: i16 = 512;

/// The console's height, in lines: tall enough that one run's output never
/// scrolls, so the rendering is the lines as they were written.
const LINES: i16 = 200;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate lives at <repo>/crates/mochimo-crypto")
        .to_path_buf()
}

/// The shipped binary, built once per test process: the `pty` module's own
/// build, repeated here because `tests/cli.rs` is Rep-0's file and changes by
/// one attribute only.
///
/// Everything is a panic rather than a skip, for the reason given there: a
/// harness that cannot build its subject and reports it absent reaches the
/// assertions as a pass over nothing.
pub fn wallet_binary() -> &'static Path {
    static EXE: OnceLock<PathBuf> = OnceLock::new();
    EXE.get_or_init(|| {
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| {
            panic!(
                "CARGO is unset. Cargo sets it for every test process it runs, so this test is \
                 not being run by cargo and cannot build the binary it tests. Run the board with \
                 `cargo test`, not by invoking the test binary."
            )
        });
        // The profile the outer run is using.
        let me = std::env::current_exe().expect("current_exe");
        let release = me.components().any(|c| c.as_os_str() == "release");
        let mut cmd = Command::new(&cargo);
        cmd.current_dir(repo_root()).args([
            "build",
            "-p",
            "mochimo-crypto",
            "--features",
            "mesh-https",
            "--bin",
            "mcm-wallet",
            "--message-format=json",
        ]);
        if release {
            cmd.arg("--release");
        }
        // The variables cargo sets for this test process are removed from the
        // nested build's environment, as the `pty` module removes them:
        // `ring`'s build script declares `rerun-if-env-changed` for
        // `CARGO_MANIFEST_DIR`, so a nested build that inherited them would
        // not share the shell's fingerprint and would recompile `ring` and
        // everything built on it.
        for (k, _) in std::env::vars_os() {
            let k = k.to_string_lossy();
            let injected = matches!(
                k.as_ref(),
                "CARGO_MANIFEST_DIR"
                    | "CARGO_MANIFEST_PATH"
                    | "CARGO_CRATE_NAME"
                    | "CARGO_PRIMARY_PACKAGE"
                    | "CARGO_TARGET_TMPDIR"
                    | "OUT_DIR"
            ) || k.starts_with("CARGO_PKG_")
                || k.starts_with("CARGO_BIN_EXE_");
            if injected {
                cmd.env_remove(k.as_ref());
            }
        }
        let out = cmd
            .output()
            .unwrap_or_else(|e| panic!("could not run `{cargo} build --bin mcm-wallet`: {e}"));
        assert!(
            out.status.success(),
            "`cargo build --features mesh-https --bin mcm-wallet` failed ({}), so the console \
             harness has no subject. This is a build failure of the shipped binary, not a finding \
             about its console handling.\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
        let mut exe: Option<PathBuf> = None;
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            if v["reason"] != "compiler-artifact" || v["target"]["name"] != "mcm-wallet" {
                continue;
            }
            let is_bin = v["target"]["kind"]
                .as_array()
                .is_some_and(|k| k.iter().any(|x| x == "bin"));
            if is_bin {
                if let Some(p) = v["executable"].as_str() {
                    exe = Some(PathBuf::from(p));
                }
            }
        }
        let exe = exe.unwrap_or_else(|| {
            panic!(
                "cargo built without reporting an executable for the `mcm-wallet` bin target. The \
                 path is read from cargo's own JSON rather than guessed, so a renamed target or a \
                 moved target directory fails here rather than running a stale binary."
            )
        });
        assert!(exe.is_file(), "cargo named {} and it is not a file", exe.display());
        // No path in this line: what a test prints can be read by the
        // census, whose floors take the largest integer they find.
        println!(
            "console harness: built the shipped binary in the {} profile",
            if release { "release" } else { "debug" }
        );
        exe
    })
}

/// A pseudoconsole, closed when dropped.
struct Pseudoconsole(HPCON);

impl Drop for Pseudoconsole {
    fn drop(&mut self) {
        // SAFETY: the handle came from a `CreatePseudoConsole` that succeeded,
        // and this is the one place it is closed.
        unsafe { ClosePseudoConsole(self.0) };
    }
}

/// A process-thread attribute list holding one attribute, the pseudoconsole,
/// deleted when dropped. Its storage is `usize`s, so the list the system
/// writes into it is aligned for a pointer.
struct AttributeList {
    storage: Vec<usize>,
}

impl AttributeList {
    fn for_console(console: &Pseudoconsole) -> AttributeList {
        let mut size = 0usize;
        // SAFETY: a null list asks only for the size a list of one attribute
        // needs, written to `size`. The call reports failure by design --
        // it is the first of the two calls the session page makes -- so its
        // result is not the test; the size is.
        unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut size) };
        assert!(
            size > 0,
            "InitializeProcThreadAttributeList reported no size for one attribute: {}",
            io::Error::last_os_error()
        );
        let mut storage = vec![0usize; size.div_ceil(size_of::<usize>())];
        // SAFETY: the list is `storage`: at least `size` bytes, aligned for a
        // pointer, and owned by the value returned below for as long as the
        // list is in use.
        let ok = unsafe { InitializeProcThreadAttributeList(storage.as_mut_ptr().cast(), 1, 0, &mut size) };
        assert!(ok != 0, "InitializeProcThreadAttributeList failed: {}", io::Error::last_os_error());
        let mut list = AttributeList { storage };
        // SAFETY: the list was initialized for one attribute just above. The
        // pseudoconsole attribute's value is the handle itself and not a
        // pointer to it -- the session page passes `hpc` and `sizeof(hpc)` --
        // and the handle stays open for longer than the list lives, in the
        // session that owns both.
        let ok = unsafe {
            UpdateProcThreadAttribute(
                list.as_list(),
                0,
                PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
                console.0 as *const c_void,
                size_of::<HPCON>(),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        };
        assert!(ok != 0, "UpdateProcThreadAttribute with the pseudoconsole failed: {}", io::Error::last_os_error());
        list
    }

    fn as_list(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.storage.as_mut_ptr().cast()
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        // SAFETY: `for_console` initialized the list, and this is the one
        // place it is deleted; its storage is freed after this returns.
        unsafe { DeleteProcThreadAttributeList(self.as_list()) };
    }
}

/// What a finished session left: the exit code, the console's rendering with
/// its sequences removed, the two redirected streams, and the number of
/// prompts answered.
pub struct Outcome {
    pub code: u32,
    pub screen: String,
    pub stdout: String,
    pub stderr: String,
    pub prompts: usize,
}

/// One run of the shipped binary in a pseudoconsole of its own.
pub struct Session {
    process: OwnedHandle,
    console: Option<Pseudoconsole>,
    input: Option<PipeWriter>,
    rx: Receiver<Vec<u8>>,
    reader: Option<JoinHandle<()>>,
    output: Vec<u8>,
    cursor: usize,
    stdout_file: PathBuf,
    stderr_file: PathBuf,
    prompts: usize,
    started: Instant,
}

impl Session {
    /// Start the shipped binary with `args` in a new pseudoconsole, its
    /// stdout and stderr redirected to `io/stdout` and `io/stderr`.
    pub fn spawn(io: &Path, args: &[&str]) -> Session {
        let exe = wallet_binary();
        std::fs::create_dir_all(io).unwrap_or_else(|e| panic!("cannot create {}: {e}", io.display()));
        let stdout_file = io.join("stdout");
        let stderr_file = io.join("stderr");
        let comspec = std::env::var_os("ComSpec")
            .unwrap_or_else(|| panic!("ComSpec is unset, so there is no cmd.exe to redirect the binary's streams"));

        let (console_input, input) =
            std::io::pipe().unwrap_or_else(|e| panic!("cannot create the console's input pipe: {e}"));
        let (output, console_output) =
            std::io::pipe().unwrap_or_else(|e| panic!("cannot create the console's output pipe: {e}"));

        let mut raw: HPCON = 0;
        // SAFETY: both handles are open ends of pipes this function owns, the
        // one the console reads and the one it writes, and `raw` is a valid
        // place for the new handle. The session page has the caller free both
        // after `CreateProcess`, so the console holds references of its own.
        let hr = unsafe {
            CreatePseudoConsole(
                COORD { X: COLUMNS, Y: LINES },
                console_input.as_raw_handle(),
                console_output.as_raw_handle(),
                0,
                &mut raw,
            )
        };
        assert!(hr >= 0, "CreatePseudoConsole failed with HRESULT {hr:#010x}");
        let console = Pseudoconsole(raw);

        let mut list = AttributeList::for_console(&console);
        let mut info = STARTUPINFOEXW::default();
        info.StartupInfo.cb = u32::try_from(size_of::<STARTUPINFOEXW>()).expect("STARTUPINFOEXW's size fits a u32");
        info.lpAttributeList = list.as_list();
        let application = wide(&comspec);
        let mut line = command_line(&comspec, exe, args, &stdout_file, &stderr_file);
        let directory = wide(io.as_os_str());
        let mut started = PROCESS_INFORMATION::default();
        // SAFETY: `application`, `line` and `directory` are NUL-terminated
        // UTF-16 that outlive the call, and `line` is writable, as the command
        // line must be. `info` is a STARTUPINFOEXW whose `cb` says so, and its
        // attribute list lives until after the call. No handle is inherited,
        // and the environment is this process's.
        let ok = unsafe {
            CreateProcessW(
                application.as_ptr(),
                line.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                EXTENDED_STARTUPINFO_PRESENT,
                std::ptr::null(),
                directory.as_ptr(),
                &info.StartupInfo,
                &mut started,
            )
        };
        assert!(ok != 0, "CreateProcessW could not start {}: {}", comspec.to_string_lossy(), io::Error::last_os_error());
        // SAFETY: `CreateProcessW` succeeded, so both handles are open, and
        // each is taken into ownership exactly once.
        let (process, thread) =
            unsafe { (OwnedHandle::from_raw_handle(started.hProcess), OwnedHandle::from_raw_handle(started.hThread)) };
        drop(thread);
        drop(list);
        drop(console_input);
        drop(console_output);

        let (tx, rx) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut output = output;
            let mut chunk = [0u8; 4096];
            loop {
                match output.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if tx.send(chunk[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                }
            }
        });

        Session {
            process,
            console: Some(console),
            input: Some(input),
            rx,
            reader: Some(reader),
            output: Vec::new(),
            cursor: 0,
            stdout_file,
            stderr_file,
            prompts: 0,
            started: Instant::now(),
        }
    }

    /// Wait until the console shows `needle` past what earlier calls
    /// consumed, and return the text before it. The needle's trailing blanks
    /// are not required: the rendering may move the cursor past a trailing
    /// blank rather than send one.
    pub fn expect(&mut self, needle: &str) -> String {
        let needle = needle.trim_end();
        let deadline = Instant::now() + STEP;
        loop {
            let screen = visible(&self.output);
            if let Some(at) = screen[self.cursor..].find(needle) {
                let before = screen[self.cursor..self.cursor + at].to_owned();
                self.cursor += at + needle.len();
                return before;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                let d = self.diagnostics();
                self.end();
                panic!("the console did not show {needle:?} within {STEP:?}, so the session was ended.\n{d}");
            }
            match self.rx.recv_timeout(left) {
                Ok(chunk) => self.output.extend_from_slice(&chunk),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    let d = self.diagnostics();
                    panic!("THE OPERATOR WAS NEVER SHOWN {needle:?}: the console's output closed first.\n{d}");
                }
            }
        }
    }

    /// [`Session::expect`] for a prompt the test then answers, counted: the
    /// count is what a test prints as its evidence.
    pub fn expect_prompt(&mut self, needle: &str) -> String {
        let before = self.expect(needle);
        self.prompts += 1;
        before
    }

    /// Type `keys` at the console, as they are.
    pub fn type_keys(&mut self, keys: &[u8]) {
        let input = self.input.as_mut().expect("the console's input is open until the session finishes");
        input
            .write_all(keys)
            .and_then(|()| input.flush())
            .unwrap_or_else(|e| panic!("cannot type at the console: {e}"));
    }

    /// Type `line` and press Enter.
    pub fn send(&mut self, line: &str) {
        self.type_keys(line.as_bytes());
        self.type_keys(ENTER);
    }

    /// Wait for the program to exit, close the console, and collect what the
    /// run left.
    pub fn finish(mut self) -> Outcome {
        // SAFETY: `process` is an open process handle this session owns.
        let waited = unsafe { WaitForSingleObject(self.process.as_raw_handle(), millis(STEP)) };
        if waited != WAIT_OBJECT_0 {
            let d = self.diagnostics();
            panic!(
                "THE PROGRAM DID NOT EXIT within {STEP:?} of its last step (wait result {waited}), so the \
                 session was ended.\n{d}"
            );
        }
        let mut code = 0u32;
        // SAFETY: as above, and `code` is a valid place for the result.
        let ok = unsafe { GetExitCodeProcess(self.process.as_raw_handle(), &mut code) };
        assert!(ok != 0, "GetExitCodeProcess failed: {}", io::Error::last_os_error());

        // The rest of the output arrives as the console closes: a last
        // rendering, and then its end of the output pipe goes and the reader
        // thread ends.
        self.input = None;
        self.console = None;
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match self.rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok(chunk) => self.output.extend_from_slice(&chunk),
                Err(RecvTimeoutError::Disconnected) => break,
                Err(RecvTimeoutError::Timeout) => {
                    let d = self.diagnostics();
                    panic!("the console's output did not close within 30 s of the program's exit.\n{d}");
                }
            }
        }
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        Outcome {
            code,
            screen: visible(&self.output),
            stdout: read_lossy(&self.stdout_file),
            stderr: read_lossy(&self.stderr_file),
            prompts: self.prompts,
        }
    }

    /// End the run: `cmd.exe` if it is still running, then the console, which
    /// ends the binary if it is still attached. Safe to call twice.
    fn end(&mut self) {
        // SAFETY: `process` is open; a zero wait only asks whether it exited.
        let running = unsafe { WaitForSingleObject(self.process.as_raw_handle(), 0) } == WAIT_TIMEOUT;
        if running {
            // SAFETY: as above. What this leaves attached to the console, the
            // console's closing below ends.
            unsafe { TerminateProcess(self.process.as_raw_handle(), 1) };
        }
        self.input = None;
        self.console = None;
    }

    fn diagnostics(&mut self) -> String {
        while let Ok(chunk) = self.rx.try_recv() {
            self.output.extend_from_slice(&chunk);
        }
        format!(
            "--- after {:?} ---\n--- screen ---\n{}\n--- the console's bytes, escaped ---\n{}\n--- stdout \
             file ---\n{}\n--- stderr file ---\n{}",
            self.started.elapsed(),
            visible(&self.output),
            String::from_utf8_lossy(&self.output).escape_debug(),
            read_lossy(&self.stdout_file),
            read_lossy(&self.stderr_file),
        )
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.end();
    }
}

/// The text a person would read in the console's output: virtual terminal
/// sequences removed, carriage returns dropped, a cursor move to the right
/// kept as that many blanks, and a cursor placement kept as a line break.
///
/// It is a function of the bytes that only ever grows at the end: a sequence
/// or a UTF-8 character still unfinished at the end gives nothing until the
/// rest arrives. So a position in what it returns stays the same position as
/// more output comes, which is what [`Session::expect`]'s cursor relies on.
pub fn visible(bytes: &[u8]) -> String {
    let mut text: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\r' {
            i += 1;
            continue;
        }
        if b != 0x1b {
            text.push(b);
            i += 1;
            continue;
        }
        let Some(&kind) = bytes.get(i + 1) else { break };
        match kind {
            // A control sequence: parameters, then one final byte.
            b'[' => {
                let Some(len) = bytes[i + 2..].iter().position(|c| (0x40..=0x7e).contains(c)) else {
                    break;
                };
                let params = &bytes[i + 2..i + 2 + len];
                match bytes[i + 2 + len] {
                    b'C' => text.extend(std::iter::repeat_n(b' ', count(params))),
                    b'H' | b'f' if text.last().is_some_and(|&c| c != b'\n') => text.push(b'\n'),
                    _ => {}
                }
                i += 3 + len;
            }
            // An operating system command, such as a window title: it ends at
            // BEL or at ESC backslash.
            b']' => {
                let rest = &bytes[i + 2..];
                let end = rest.iter().enumerate().find_map(|(k, &c)| match c {
                    0x07 => Some(k + 1),
                    0x1b if rest.get(k + 1) == Some(&b'\\') => Some(k + 2),
                    _ => None,
                });
                let Some(end) = end else { break };
                i += 2 + end;
            }
            // Intermediate bytes, then one final byte.
            0x20..=0x2f => {
                let Some(len) = bytes[i + 1..].iter().position(|c| (0x30..=0x7e).contains(c)) else {
                    break;
                };
                i += 2 + len;
            }
            _ => i += 2,
        }
    }
    let keep = complete_utf8(&text);
    String::from_utf8_lossy(&text[..keep]).into_owned()
}

/// A sequence's first parameter as a count: 1 when it is absent or zero.
fn count(params: &[u8]) -> usize {
    let digits: String = params.iter().take_while(|c| c.is_ascii_digit()).map(|&c| char::from(c)).collect();
    digits.parse().ok().filter(|&n: &usize| n > 0).unwrap_or(1)
}

/// How much of `text` ends on a complete UTF-8 character: a lead byte whose
/// continuation bytes have not all arrived is held back.
fn complete_utf8(text: &[u8]) -> usize {
    let n = text.len();
    for back in 1..=n.min(3) {
        let b = text[n - back];
        if b & 0xc0 == 0x80 {
            continue;
        }
        let width = match b {
            0xf0..=0xff => 4,
            0xe0..=0xef => 3,
            0xc0..=0xdf => 2,
            _ => 1,
        };
        return if width > back { n - back } else { n };
    }
    n
}

/// `"<cmd.exe>" /d /s /c ""<exe>" "<arg>" … > "<stdout>" 2> "<stderr>""`:
/// no AutoRun commands (`/d`), and the outer quotes stripped and the rest
/// run as written (`/s`).
fn command_line(comspec: &OsStr, exe: &Path, args: &[&str], stdout: &Path, stderr: &Path) -> Vec<u16> {
    let mut inner = quoted(&exe.to_string_lossy());
    for arg in args {
        inner.push(' ');
        inner.push_str(&quoted(arg));
    }
    inner.push_str(&format!(" > {} 2> {}", quoted(&stdout.to_string_lossy()), quoted(&stderr.to_string_lossy())));
    wide(OsStr::new(&format!("{} /d /s /c \"{inner}\"", quoted(&comspec.to_string_lossy()))))
}

/// One word for `cmd.exe`, in double quotes. A quote or a percent sign inside
/// cannot pass through `cmd.exe` intact, and a trailing backslash would
/// escape the closing quote for the program's own parser, so each is refused
/// rather than mangled. No argument a test passes has one.
fn quoted(word: &str) -> String {
    assert!(
        !word.contains(['"', '%']) && !word.ends_with('\\'),
        "{word:?} cannot be passed through cmd.exe intact"
    );
    format!("\"{word}\"")
}

/// NUL-terminated UTF-16, as the wide Win32 calls take it.
fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

fn millis(d: Duration) -> u32 {
    u32::try_from(d.as_millis()).expect("a step fits a u32 of milliseconds")
}

fn read_lossy(path: &Path) -> String {
    match std::fs::read(path) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(e) => format!("({} is not readable: {e})", path.display()),
    }
}

//! Shared instruments for the keystore tests: a scratch directory that
//! cleans up after itself, the seed every crash proof starts from, and the
//! reopen helper that keeps the census's child processes from making a
//! just-released lock look held.
//!
//! Scratch directories live under `CARGO_TARGET_TMPDIR` — cargo creates it
//! for integration-test targets and it sits inside the gitignored `target/`
//! — named by test, pid, a process-wide counter and a nanosecond stamp. The
//! guard removes the directory on `Drop` only when the thread is not
//! panicking, so a failing case leaves its evidence. No `tempfile`: an argued
//! dev-dependency for fifteen lines.

#![allow(dead_code)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use mochimo_crypto::account::Account;
use mochimo_crypto::consts::{PK_LEN, SEED_LEN, WOTS_ADDR_LEN};
use mochimo_crypto::keystore::{Disk, Figures, Keystore, Medium};
use mochimo_crypto::{Error, Result, Secret};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

pub struct ScratchDir {
    path: PathBuf,
}

impl ScratchDir {
    pub fn new(test: &str) -> ScratchDir {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let root = Path::new(env!("CARGO_TARGET_TMPDIR"));
        let path = root.join(format!("{test}-{}-{n}-{nanos}", std::process::id()));
        std::fs::create_dir_all(root).unwrap_or_else(|e| panic!("cannot create {}: {e}", root.display()));
        // The keystore creates the leaf itself, mode 0700; the parent exists.
        ScratchDir { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The names in the directory, sorted — a second observable the byte
    /// comparisons did not choose.
    pub fn listing(&self) -> Vec<String> {
        let mut out: Vec<String> = std::fs::read_dir(&self.path)
            .map(|rd| {
                rd.flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        out.sort();
        out
    }

    #[cfg(unix)]
    pub fn snapshot_bytes(&self) -> Vec<u8> {
        std::fs::read(self.path.join("accounts.mks"))
            .unwrap_or_else(|e| panic!("read snapshot in {}: {e}", self.path.display()))
    }

    /// The image the store would open to: on Windows a store is two slot
    /// files, and what a test compares, parses or damages is the image `open`
    /// takes from them, not either file whole. [`Self::snapshot_bytes_under`]
    /// under [`TEST_PASSWORD`], the password every store this harness makes
    /// is sealed under.
    #[cfg(windows)]
    pub fn snapshot_bytes(&self) -> Vec<u8> {
        self.snapshot_bytes_under(TEST_PASSWORD)
    }

    /// [`Self::snapshot_bytes`] for a store sealed under `password`, which a
    /// Unix snapshot does not need to be read.
    #[cfg(unix)]
    pub fn snapshot_bytes_under(&self, _password: &[u8]) -> Vec<u8> {
        self.snapshot_bytes()
    }

    /// [`Self::snapshot_bytes`] for a store sealed under `password`.
    ///
    /// When only one slot can hold the image -- no slot 1, which is the rename
    /// layout, or one intact frame beside a slot that holds none -- that image
    /// is read here, with no key. A second reader, as a test's should be: it
    /// takes a frame's image by its length alone and leaves the check to the
    /// keystore, whose reading is what the tests are about. Only two images
    /// need the key to be ordered, since the generation is in the ciphertext,
    /// and that is the crate's own `keystore::newest_image`, under
    /// `password`; a store under another one is refused there, loudly.
    #[cfg(windows)]
    pub fn snapshot_bytes_under(&self, password: &[u8]) -> Vec<u8> {
        const MAGIC: &[u8] = b"MCMKSLOT";
        let read = |name: &str| match std::fs::read(self.path.join(name)) {
            Ok(bytes) => Some(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => panic!("read {name} in {}: {e}", self.path.display()),
        };
        let slot0 = read("accounts.mks").unwrap_or_else(|| panic!("no accounts.mks in {}", self.path.display()));
        let Some(slot1) = read("accounts.mks.1") else {
            return slot0;
        };
        let image = |frame: &[u8]| -> Option<Vec<u8>> {
            if frame.get(..MAGIC.len()) != Some(MAGIC) {
                return None;
            }
            let len = usize::try_from(u32::from_le_bytes(frame.get(10..14)?.try_into().ok()?)).ok()?;
            (len > 0 && frame.len() == 46 + len).then(|| frame[14..14 + len].to_vec())
        };
        let plain0 = !slot0.starts_with(MAGIC);
        match (image(&slot0), plain0, image(&slot1)) {
            (Some(only), _, None) | (None, false, Some(only)) => only,
            (None, true, None) => slot0,
            _ => mochimo_crypto::keystore::newest_image(&self.path, password)
                .map(|image| image.to_vec())
                .unwrap_or_else(|e| panic!("order the two slots in {}: {e}", self.path.display())),
        }
    }

    /// Put bytes back, for the arms that damage a file on purpose.
    ///
    /// Writes directly rather than through `Medium`, deliberately: the point
    /// is to produce a file the keystore never would, and routing it through
    /// the writer under test would make that impossible.
    #[cfg(unix)]
    pub fn write_snapshot(&self, bytes: &[u8]) {
        std::fs::write(self.path.join("accounts.mks"), bytes)
            .unwrap_or_else(|e| panic!("write snapshot in {}: {e}", self.path.display()));
    }

    /// Put bytes back, for the arms that damage a file on purpose: on Windows,
    /// a store in the rename layout holding exactly `bytes` as its snapshot,
    /// slot 1 removed -- which a Windows build reads exactly as the Unix one
    /// reads a snapshot, so each damaged image meets the refusal it meets
    /// there.
    #[cfg(windows)]
    pub fn write_snapshot(&self, bytes: &[u8]) {
        match std::fs::remove_file(self.path.join("accounts.mks.1")) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => panic!("remove slot 1 in {}: {e}", self.path.display()),
        }
        std::fs::write(self.path.join("accounts.mks"), bytes)
            .unwrap_or_else(|e| panic!("write snapshot in {}: {e}", self.path.display()));
    }

    /// Every byte of both slot files as they stand, slot 0's and then slot
    /// 1's (empty when absent): the strictest thing a Windows test can compare
    /// a store by, since it notices a write the newest image would not.
    #[cfg(windows)]
    pub fn slot_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for name in ["accounts.mks", "accounts.mks.1"] {
            match std::fs::read(self.path.join(name)) {
                Ok(bytes) => out.extend_from_slice(&bytes),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => panic!("read {name} in {}: {e}", self.path.display()),
            }
        }
        out
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

/// How many times [`reopen_with`] retries `Error::Locked` before returning
/// it, and how long it waits between tries: fifty tries of 100 µs, 5 ms in
/// all — some twenty-five times the window that was measured (never more
/// than two 100 µs retries under ~1,250 spawns per second).
// ---------------------------------------------------------------------------
// The store's encryption, under FIXED entropy
// ---------------------------------------------------------------------------
//
// **This is what kept three proofs alive.** The decision deferring the AEAD predicted that an
// AEAD's per-write nonce would delete the image determinism the format KAT,
// `records_are_addressed_by_tag_not_position` and the I3 crash proof are
// written on. It does not, and the reason is that `mochimo-crypto` has no RNG:
// `cli::create` had already established that the caller supplies entropy, so
// the salt and the nonce seed are PARAMETERS. Fixed parameters give a
// deterministic image, and every byte-level observable survives.
//
// Production supplies `/dev/urandom`. These constants are the test's supply,
// and their only property is that they are constant.
/// The password every harness-built store is created and opened under.
///
/// Long enough to pass `create::MIN_PASSWORD_LEN`, and deliberately not a
/// realistic one -- a test password that looked plausible would eventually be
/// copied into something real.
pub const TEST_PASSWORD_STR: &str = "harness-password-not-for-real-use";
/// The same password as bytes, for `Init`/`Unlock`, whose KDF takes bytes.
/// One literal, two views -- `cli::create::create` takes `&str`
/// because the floor it asks counts characters.
pub const TEST_PASSWORD: &[u8] = TEST_PASSWORD_STR.as_bytes();

/// A second password, for the arm that proves A's file is refused under B.
pub const OTHER_PASSWORD: &[u8] = b"a-different-harness-password";

pub const TEST_SALT: [u8; mochimo_crypto::keystore::SALT_LEN] = [0x5A; mochimo_crypto::keystore::SALT_LEN];
pub const TEST_NONCE_SEED: [u8; mochimo_crypto::keystore::NONCE_SEED_LEN] =
    [0x4E; mochimo_crypto::keystore::NONCE_SEED_LEN];

/// **The harness creates stores with the CHEAP KDF**, and that is a
/// measurement rather than a preference.
///
/// With `Kdf::RECOMMENDED` every `Keystore::create` and every `Keystore::open`
/// cost about seventy milliseconds. One `invariants` test took 39 seconds and
/// the full board deadlocked — the census spawns children that open the same
/// stores, and `reopen` retries a held `flock` fifty times, so a lock window
/// that had been microseconds became long enough for parent and child to wait
/// on each other.
///
/// The parameters live in each file's header, so a cheap store and a shipped
/// store are both valid v3 files and the format code path is identical. What
/// the suite loses is any claim about how expensive a guess is — which no test
/// here was making. `format::tests::the_kdf_is_a_function_of_its_password_salt_
/// and_parameters` is where the parameters themselves are exercised.
pub fn init() -> mochimo_crypto::keystore::Init<'static> {
    mochimo_crypto::keystore::Init {
        password: TEST_PASSWORD,
        salt: TEST_SALT,
        nonce_seed: TEST_NONCE_SEED,
        kdf: mochimo_crypto::keystore::Kdf::CHEAP_FOR_TESTS,
    }
}

pub fn unlock() -> mochimo_crypto::keystore::Unlock<'static> {
    mochimo_crypto::keystore::Unlock {
        password: TEST_PASSWORD,
        nonce_seed: TEST_NONCE_SEED,
    }
}

pub fn unlock_with(password: &[u8]) -> mochimo_crypto::keystore::Unlock<'_> {
    mochimo_crypto::keystore::Unlock {
        password,
        nonce_seed: TEST_NONCE_SEED,
    }
}

/// `Keystore::create` under the harness's fixed entropy.
pub fn create(dir: &Path) -> mochimo_crypto::Result<Keystore<Disk>> {
    Keystore::create(dir, &init())
}

/// `Keystore::open` under the harness's fixed entropy.
pub fn open(dir: &Path) -> mochimo_crypto::Result<Keystore<Disk>> {
    Keystore::open(dir, &unlock())
}

pub const REOPEN_TRIES: usize = 50;
pub const REOPEN_WAIT: Duration = Duration::from_micros(100);

/// What [`reopen_with`] came back with: the open's outcome, and how many
/// `Error::Locked` results it retried through to get there.
pub struct Reopen<M: Medium> {
    pub result: Result<Keystore<M>>,
    pub retries: usize,
}

/// Reopen a keystore a proof has just dropped, retrying **`Error::Locked`
/// alone**, bounded by [`REOPEN_TRIES`].
///
/// # Why this exists
///
/// `flock` lives on the open file description, and a child process holds a
/// copy of the parent's descriptor table between its creation and its
/// `exec`. The census spawns some twenty-five children while the crash
/// proofs run beside it in the same process, so a proof that drops a handle
/// and reopens the same directory within ~200 µs of a spawn takes a fresh
/// description whose `try_lock` conflicts with the old one — for that
/// instant a live holder exists, and the keystore's `Locked` is telling the
/// truth. It was seen once, then reproduced (one solo run in seven) and
/// isolated it with a probe: 788 and 870 transient blocks per 1.3 million
/// lock-close-relock cycles under a spawning thread, none in 1.43 million
/// without one, all cleared within two 100 µs retries.
///
/// # What it must never become
///
/// * **It is test scaffolding, not keystore behaviour.** `Keystore::open`
///   does not retry, by the lock design's decision: a genuine second holder is a
///   real condition, and the message that tells an operator not to delete
///   the lock file depends on `Locked` meaning that. The retry lives here,
///   in the harness the proofs share, and nowhere in `src/`.
/// * **Only `Locked` is retried.** Every other error returns at once with
///   `retries == 0`; `reopen_helper_returns_every_other_error_immediately`
///   in `tests/keystore.rs` holds that.
/// * **The bound is load-bearing.** A genuine second holder — a live handle on
///   the directory — is still refused after [`REOPEN_TRIES`] tries, with the
///   count at the bound and the elapsed time showing the waits happened;
///   `reopen_helper_still_refuses_a_genuine_second_holder_at_the_bound`
///   holds that. Without it this helper is indistinguishable from removing
///   the lock check.
/// * **Retries are visible outside the censused block.** When a call retried
///   at all, one line naming the caller and the count is written **straight
///   to file descriptor 2** (`std::io::stderr().write_all`), which libtest's
///   capture does not intercept: it lands in the process's own stderr, after
///   the `test result:` roll-up, outside every `---- stdout ----` block the
///   census's integer scan reads. A helper that begins retrying
///   constantly therefore shows up in every board log rather than absorbing
///   a future defect silently — and its count can never satisfy a proof's
///   floor, because the scan never sees it.
pub fn reopen_with<M: Medium>(label: &str, dir: &Path, mut medium: impl FnMut() -> M) -> Reopen<M> {
    let mut retries = 0usize;
    loop {
        match Keystore::open_with(dir, medium(), &unlock()) {
            Err(Error::Locked) if retries < REOPEN_TRIES => {
                retries += 1;
                std::thread::sleep(REOPEN_WAIT);
            }
            result => {
                if retries > 0 {
                    let verdict = if result.is_ok() { "opened" } else { "still refused at the bound" };
                    // Leading newline: this write bypasses libtest's capture and
                    // can otherwise land mid-line beside a test's own `ok` line in
                    // a board log written with `2>&1`.
                    let line = format!(
                        "\n  keystore reopen [{label}]: {retries} retry(ies) on Error::Locked, then {verdict} \
                         (written outside the censused block on purpose)\n"
                    );
                    // Deliberately not `eprintln!`: that is captured per test and
                    // printed inside the very block the census scans.
                    let _ = std::io::stderr().write_all(line.as_bytes());
                }
                return Reopen { result, retries };
            }
        }
    }
}

/// [`reopen_with`] over the real filesystem.
pub fn reopen(label: &str, dir: &Path) -> Reopen<Disk> {
    reopen_with(label, dir, || Disk)
}

/// The literals every crash proof is seeded with. **Both accounts are group
/// F's now** (`fixtures/group_f_derivation.json`), and neither tag is read
/// back from our own derivation:
///
/// * the imported account is `F-address-widths` — its `account_seed` as the
///   retained root, its 2208-byte `account_address_file` as the `faddress`
///   an `.mcm` entry carries, and its recorded `account_tag` as the tag
///   `Account::import` must compute. The address is **embedded** rather than
///   transcribed, so no literal here can drift from the fixture;
/// * the derived account is `F-derive-account-1`, whose tag `Account::derive`
///   computes and `DERIVED_TAG` records.
///
/// This changed with format v2. Until then the imported account was
/// `import_with_unverified_tag([0xB7; 32], [0x1A; 20])` — a root chosen for
/// being a pattern nothing in scope derives under a tag that was
/// **arbitrary by construction**, because verifying it needed components the
/// record did not carry. The record carries them now and the unverified
/// constructor is gone, so the tag has to be a real one.
///
/// The two accounts come from **different master seeds** (`000102..1f` and
/// `408b28..cf70`), so they share no key stream and `Keystore::add`'s
/// duplicate-stream refusal is not tripped by the seeding itself. And
/// `IMPORTED_TAG` (`05ff…`) still sorts before `DERIVED_TAG` (`4d9b…`),
/// which the ordering assertions rely on.
pub const ROOT: [u8; SEED_LEN] = [
    0x66, 0x4e, 0xdd, 0x3d, 0x3b, 0xf1, 0xa0, 0xe2, 0x9c, 0x93, 0x98, 0xdd, 0xc1, 0x61, 0x14,
    0xab, 0xc6, 0xd6, 0xb4, 0x32, 0xb1, 0xe5, 0xe4, 0xde, 0x26, 0x7c, 0x7e, 0x2a, 0xe5, 0x3f,
    0x58, 0x0b,
];
pub const IMPORTED_FIRST_ADDRESS: &[u8; WOTS_ADDR_LEN] =
    include_bytes!("../../../../fixtures/F-widths_account_address.bin");
pub const IMPORTED_TAG: [u8; 20] = [
    0x05, 0xff, 0x0f, 0x69, 0xd4, 0xc1, 0xcd, 0x68, 0x2e, 0xd3, 0x34, 0x1c, 0x0b, 0x77, 0x73,
    0x05, 0x4b, 0x58, 0x80, 0x0f,
];
/// The key stream `ROOT` defines: `F-address-widths.wots_address[20..40]`,
/// the rotation-0 address hash the TypeScript emitted at `wots_index: 0`.
pub const IMPORTED_STREAM: [u8; 20] = [
    0x25, 0x87, 0x87, 0x8a, 0xd3, 0x4d, 0x29, 0xcf, 0x2e, 0x4b, 0xe4, 0x83, 0x86, 0xae, 0xc3,
    0xa0, 0xc2, 0xa7, 0xea, 0x8c,
];
/// The master `F-address-widths` derives `ROOT` from, at index 0 — the other
/// side of the same account, for the cross-kind key-stream proofs.
pub const IMPORTED_MASTER: [u8; SEED_LEN] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
    0x1e, 0x1f,
];
pub const DERIVED_MASTER: [u8; SEED_LEN] = [
    0x40, 0x8b, 0x28, 0x5c, 0x12, 0x38, 0x36, 0x00, 0x4f, 0x4b, 0x88, 0x42, 0xc8, 0x93, 0x24,
    0xc1, 0xf0, 0x13, 0x82, 0x45, 0x0c, 0x0d, 0x43, 0x9a, 0xf3, 0x45, 0xba, 0x7f, 0xc4, 0x9a,
    0xcf, 0x70,
];
pub const DERIVED_TAG: [u8; 20] = [
    0x4d, 0x9b, 0x31, 0xe4, 0x78, 0x74, 0x66, 0x8e, 0x45, 0x89, 0x5a, 0x1b, 0x93, 0x38, 0x8e,
    0x5a, 0xa9, 0xb6, 0xfb, 0xe9,
];
pub const DERIVED_POSITION: u32 = 1;
pub const DIGEST: [u8; 32] = [0xD1; 32];
/// The figures every hand-built reservation in the keystore proofs records
///: a balance and a block-to-live no chain in those
/// proofs is asked about. A test that also scripts a chain chooses its own
/// figures to match what the chain holds, so its reservation reads live.
pub const FIGURES: Figures = Figures {
    reserved_balance: 5_000_000,
    blk_to_live: 0,
};

/// Account 0 of `IMPORTED_MASTER` as `Account::derive` builds it -- the
/// same account `imported_account()` holds by its root -- asserted here to
/// sit under `IMPORTED_TAG`, because the captured version-3 reservation
/// (`testdata/keystore_v3_reserved_snapshot.bin`) was written for exactly
/// this account and the tests that read it rest on the identity.
pub fn derived_account_0_of_the_imported_master() -> Account {
    let acct = Account::derive(&Secret::new(IMPORTED_MASTER), 0);
    assert_eq!(
        acct.tag(),
        IMPORTED_TAG,
        "Account::derive(IMPORTED_MASTER, 0) is no longer F-address-widths' tag; the version-3 \
         reservation capture describes an account this harness no longer derives"
    );
    acct
}

pub fn imported_account() -> Account {
    let acct = Account::import(Secret::new(ROOT), IMPORTED_FIRST_ADDRESS)
        .unwrap_or_else(|e| panic!("F-address-widths' root and first address are a pair: {e}"));
    assert_eq!(
        acct.tag(),
        IMPORTED_TAG,
        "Account::import no longer computes F-address-widths' recorded account tag; every \
         keystore proof seeded from this harness would otherwise run on an account the \
         fixture does not describe"
    );
    acct
}

/// A 2208-byte first address for `root` built from **chosen** public
/// components rather than captured from a generator.
///
/// It is a *valid* pair -- `Account::import` verifies exactly that the root
/// reproduces the address's public key, and this computes the public key from
/// the root -- and it names a first key nobody has ever funded. Both facts
/// matter: the first is why tests can build an imported account for any root,
/// the second is why a verifying import does **not** close the key-stream
/// aliasing. Any `(pub_seed, adrs)` gives another valid pair, and
/// therefore another tag, over the same rotation keys.
pub fn synthetic_first_address(root: &Secret<SEED_LEN>, salt: u8) -> Box<[u8; WOTS_ADDR_LEN]> {
    let pub_seed = [salt; SEED_LEN];
    let image = [salt ^ 0xFF; 32];
    let key = mochimo_crypto::derive::first_key_from_components(
        root.duplicate(),
        &pub_seed,
        mochimo_crypto::wots::Adrs::from_le_image(&image),
    );
    let mut out = Box::new([0u8; WOTS_ADDR_LEN]);
    out[..PK_LEN].copy_from_slice(&key.public_key()[..]);
    out[PK_LEN..PK_LEN + SEED_LEN].copy_from_slice(&pub_seed);
    out[PK_LEN + SEED_LEN..].copy_from_slice(&image);
    out
}

/// An imported account over `root`, through [`synthetic_first_address`]. For
/// tests that need *an* imported account rather than a captured one; the
/// captured one is [`imported_account`].
pub fn synthetic_imported_account(root: Secret<SEED_LEN>, salt: u8) -> Account {
    let address = synthetic_first_address(&root, salt);
    Account::import(root, &address).unwrap_or_else(|e| panic!("a computed pair must verify: {e}"))
}

/// An imported account over the **same key stream** as [`imported_account`]
/// under a **different tag**: the key-stream aliasing attack. Any
/// `(pub_seed, adrs)` pair reproduces *some* public key under a given root,
/// so a first address built from junk components verifies, yields another
/// tag, and sits over the same rotation keys. What refuses it is the stream
/// identity, not the tag.
pub fn aliased_imported_account() -> Account {
    let acct = synthetic_imported_account(Secret::new(ROOT), 0x5E);
    assert_ne!(acct.tag(), IMPORTED_TAG, "the alias must carry another tag");
    acct
}

pub fn derived_account() -> Account {
    let acct = Account::derive(&Secret::new(DERIVED_MASTER), DERIVED_POSITION);
    assert_eq!(
        acct.tag(),
        DERIVED_TAG,
        "Account::derive no longer reproduces F-derive-account-1's tag; every \
         keystore proof seeded from this harness would otherwise run on an \
         account the fixture does not describe"
    );
    acct
}

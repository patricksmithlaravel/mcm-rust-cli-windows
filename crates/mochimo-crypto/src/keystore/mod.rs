//! The keystore: durable storage for account records, and the thing that
//! gives [`AdvanceReceipt`] something to witness.
//!
//! # What this is
//!
//! One directory, one snapshot file holding every account, rewritten
//! atomically on every commit through four crate-owned steps — write a temp,
//! fsync it, rename it over the target, fsync the directory — and a receipt
//! minted only after the fourth. On Windows the snapshot is two slot files
//! written in place and the steps are that layout's: `slots` has the frame
//! and the rule by which `open` takes the newer image. The format is
//! `format`; the steps are `medium`; the argument for the whole-snapshot
//! shape is I3's
//! (`docs/specification.md`, *I3*): per-account files cannot put every
//! member in one write once a store-level member exists, and an append-only
//! log moves the same three fsyncs plus a torn-tail parser and a replay path
//! into recovery; what it costs is O(n) bytes per spend, dominated by the
//! fsyncs at wallet scale.
//!
//! # The three obligations the account model carried forward, and what enforces each
//!
//! **Monotonic per tag.** No public API accepts a caller-supplied index except
//! forward: [`Keystore::persist_advance`] computes stored + 1;
//! [`Keystore::persist_advance_to`] refuses any target not strictly ahead
//! (`Error::Range`, with the stored index as `min - 1`). A subtler rollback is
//! closed by the poisoned-handle rule: after any commit error, memory and disk
//! are unknown relative to each other — `rename` may have succeeded and the
//! directory fsync failed — so a handle that saw an error refuses every later
//! call with [`Error::Poisoned`], whose message says drop-and-reopen and never
//! retry. Memory is never mutated before a commit returns `Ok`.
//!
//! **One key stream, one account.** Every record carries the stream's public
//! identity since format v2 — the rotation-0 public key's hash — and
//! [`Keystore::add`] refuses a duplicate across kinds, which is the half a
//! drop-and-reopen would otherwise defeat. The
//! identity of the account being added is recomputed from its key material,
//! never read off a record.
//!
//! **Keyed by tag, never by position.** A `BTreeMap<Tag, _>` in memory,
//! records sorted by tag on disk with a strict order check on load, every API
//! takes `&Tag`, and no positional access exists. A `mem::swap` of two
//! accounts is internally consistent and is laundered into an index rollback
//! only by a store that remembers positions; this one cannot.
//!
//! **Durability is I2's clause.** The four steps hand back typestate tokens so
//! a reorder is a type error, and [`Durable`] — the witness
//! `AdvanceReceipt::attesting` demands — is constructed at exactly one
//! expression in this crate: the `Ok` arm after `fsync_dir` in
//! [`Keystore::commit`]. `tests/invariants.rs::durable_witness_has_one_construction_site`
//! holds that count at one. Error paths cannot mint by construction.
//!
//! # The lock
//!
//! `keystore.lock` is created once, never unlinked, and held with
//! `File::try_lock` (`flock(2)`; `LockFileEx` on Windows) for the handle's
//! life; `Drop` does nothing, because the kernel releases the lock on process
//! death — including `SIGKILL` — so a held lock always means a live holder
//! (on Windows, a live or a just-terminated one; see below). A `create_new`
//! lockfile instead is the stale-lock design that manufactures the
//! delete-the-lock workaround I4's decision warns against, and
//! unlinking on `Drop` is the classic two-holders race. Two opens in one
//! process conflict too (`flock` is per open-file-description); that is
//! asserted by test, not assumed. Residue: local filesystems only — NFS lock
//! emulation can make this silently meaningless and `std` has no `statfs`.
//! Cost: workspace MSRV 1.77 → 1.89.
//!
//! **On Windows the same call is `LockFileEx`**, exclusive and failing
//! immediately, over a range no file reaches, and the property above survives
//! it: the system releases a terminated process's locks, so the lock file is
//! never the remedy there either, and a second open in the same process is
//! refused as it is by `flock`. Microsoft's own note on it adds one residue:
//! the release follows termination after a time that "depends upon available
//! system resources". A lock can therefore outlive its holder briefly, which
//! an operator meets as `Locked` from a process that has already exited -- a
//! refusal, and so the fail-closed direction, gone on a retry. Whether an SMB
//! share honours the lock between machines is not established, which is the
//! NFS residue in its Windows form.
//!
//! **The file's existence means nothing, and nothing reads it as meaning
//! something.** Every refusal `open` makes after the `Missing` check
//! -- a version it does not read, a magic it does not know, a wrong password
//! -- creates `keystore.lock` on its way to the read, because the read has to
//! be under the lock to be authoritative and the lock is taken by creating
//! the file. That side effect is measured
//! (`tests/keystore.rs::a_lock_file_with_no_snapshot_is_inert_and_only_a_live_holder_refuses_create`)
//! and **left**: moving `take_lock` after the read would make the read a
//! guess, and unlinking on failure is the two-inodes race (a second process
//! opens the old inode, this one unlinks and exits, a third creates and locks
//! a new inode, the second locks the old one -- two holders). On the other
//! side, refusing a directory that holds a lock file with no snapshot beside
//! it is the stale-lock semantics `flock` was chosen to avoid, reintroduced
//! through `create`'s pre-check; [`occupied`] reports the snapshot alone --
//! on Windows slot 1 as well, for the reason its doc gives -- and a live
//! holder is refused by `take_lock`'s `Locked`, which is the only
//! thing that can tell a holder from a leftover. Two residues, stated: a
//! `create` killed after `write_temp` and before `rename` leaves a complete
//! image in `accounts.mks.tmp` that the next commit -- `create`'s first, or
//! any other -- unlinks and replaces rather than adopts (one authority, one
//! parse path; and a store nobody was told was created holds nothing to
//! lose); and `create`-versus-`create` exclusivity
//! now rests on the flock alone, which the residue line above already bounds
//! to local filesystems.
//!
//! # What `open` refuses, and why
//!
//! A group- or other-writable directory (a co-user could plant the temp as a
//! symlink; `O_NOFOLLOW` needs libc, so the permission check stands in and
//! says so). A **missing snapshot** — an absent file is not an empty store;
//! treating it as one is I5's index-zero assumption reached through the
//! filesystem, so a genuinely new store goes through [`Keystore::create`]. A
//! stale temp is unlinked after the lock is taken and is never adopted even
//! when it parses: one authority, one parse path. A partial temp under v3 is
//! a plaintext header over a truncated ciphertext, which the tag refuses
//! anyway, so what forbids adopting it is not the leak but that two files
//! must never both be authorities. On Windows `open` does read two files, the
//! slots, and takes one of them by `slots`' rule, which is the one authority
//! there: the older slot is the state before the newer, never a second
//! history, and it is never taken while the newer reads. A stale temp on
//! Windows is one a build of the rename layout left, and it is unlinked the
//! same way.
//!
//! # The signing path
//!
//! [`Keystore::sign_spend`] in `sign` is the public route to a fresh WOTS+
//! signature (`resign_reserved`, beside it, reproduces the one a reservation
//! already released): it consumes the [`AdvanceReceipt`] this store minted, re-checks
//! the store's live state against it, derives the key at the reserved
//! position from the caller's master seed or the stored root, and signs
//! through the native backend. Nothing is persisted by it. Its module doc is
//! the contract and carries the argument.
//!
//! # Encryption at rest: done, and the residue is a different shape
//!
//! The record body, which carries imported roots *and* the
//! master seed, is sealed under an Argon2id key with a ChaCha20-Poly1305 tag.
//! `imported_roots_and_the_master_seed_are_encrypted_at_rest` is green, and a
//! stolen `accounts.mks` alone yields nothing.
//!
//! **The inode residue survives the change but means something else.** Every
//! rewrite still copies the whole store into a new inode, and old inodes,
//! journals and APFS snapshots still keep the superseded ones until
//! overwritten. Those copies are now ciphertext -- but under the *same* key,
//! because the salt lives in the header and does not change across rewrites,
//! and only the nonce moves with the generation. So a recovered old inode is
//! readable by whoever has the password, exactly as the current one is. What
//! the encryption removed is the value of the file to someone who does not.
//!
//! # What the crash tests establish, and cannot see
//!
//! The proofs drive kills at syscall boundaries through
//! [`medium::Instrumented`]; every completed syscall's effect is visible
//! afterwards. They cannot drive power loss, an fsync that lies,
//! or fsyncgate (after `EIO` the dirty pages may be gone — hence `Poisoned`,
//! never retry). Rename atomicity is relied on for ext4/APFS/XFS/btrfs and is
//! not detectable from `std` on FAT/exFAT/FUSE. Said here and at each proof.
//!
//! **On Windows there is no rename, and the power-loss half of I3 rests on
//! the flush.** Win32 documents no call that commits the directory entry a
//! rename writes, so the store is two slot files and a commit writes the one
//! not holding the newest image, in place, and flushes it with
//! `FlushFileBuffers` before [`Durable`] is minted; `open` takes the newer of
//! the two intact images. A power cut can then undo only a write not yet
//! flushed, which no receipt attests, and it cannot bring back an older state
//! than one a receipt did. That the flush, once returned, is on the device is
//! Microsoft's documentation and the device's honesty, as `fsync`'s is on
//! Unix; `medium`'s module doc cites the pages. No rename is relied on, so
//! neither is its atomicity. Kills at a syscall boundary, and writes torn in
//! any mix of sectors, are driven through the same instrument on a Windows
//! runner, by proofs that keep the Unix proofs' names.

// The storage guarantees, per platform, which the module's head states in
// full: the four-step commit and the lock above rest on Unix's rename(2),
// directory fsync and flock(2), and on Windows' two slot files flushed in
// place with FlushFileBuffers, and LockFileEx. A target that is neither has
// had none of that argued.
#[cfg(not(any(unix, windows)))]
compile_error!(
    "the keystore's storage guarantees are stated for Unix (rename atomicity, \
     directory fsync, flock) and for Windows (two slot files flushed in place, \
     LockFileEx); this target is neither"
);

pub(crate) mod crypt;
pub mod format;
pub mod medium;
pub(crate) mod perms;
pub mod sign;
#[cfg(any(windows, test))]
mod slots;
pub mod spend;

use std::collections::BTreeMap;
use std::fs::{self, File, TryLockError};
use std::io::Read;
#[cfg(windows)]
use std::io::{Seek, SeekFrom};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::account::{Account, AccountKind, AccountRecord, AdvanceReceipt, WotsIndex};
use crate::addr::Tag;
use crate::consts::SEED_LEN;
use crate::error::{Error, Result};
use crate::secret::Secret;

pub use crypt::{Kdf, KEY_LEN, NONCE_SEED_LEN, SALT_LEN};
pub use format::{Figures, Pending};
pub use medium::{Call, Disk, Instrumented, Medium};
pub use sign::{KeyAccess, SpendSignature};
pub use spend::SpendAddresses;

use format::{RecordRef, Slot};
#[cfg(windows)]
use medium::SLOT1_NAME;
use medium::{SNAPSHOT_NAME, TEMP_NAME};

pub(crate) const LOCK_NAME: &str = "keystore.lock";

/// Evidence that the commit's durable steps completed: on Unix all four, the
/// directory fsync last; on Windows the slot layout's, the flush of the slot
/// just written last. On both it witnesses a state a power cut cannot take
/// back -- the module's head says what each platform's claim rests on.
///
/// Constructed at exactly one
/// site in this crate (the `Ok` arm of [`Keystore::commit`]); the source scan
/// `durable_witness_has_one_construction_site` holds that. Private field, so
/// nothing outside the crate can forge one — `ui/fail/durable_is_not_constructible.rs`.
#[must_use]
pub struct Durable(());

impl Durable {
    /// Test-only witness for unit tests of the receipt itself. Outside
    /// `cfg(test)` this does not exist, and the one-site scan skips
    /// `cfg(test)` items by design (stated there).
    #[cfg(test)]
    pub(crate) fn for_test() -> Durable {
        Durable(())
    }
}

/// A non-secret view of one account for callers that must not hold the
/// account itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountView {
    pub tag: Tag,
    pub kind: AccountKind,
    pub wots_index: WotsIndex,
    /// The open reservation, if one is open.
    pub pending: Option<Pending>,
    /// The last settled reservation, retained until the index moves:
    /// released by the next `persist_advance`, cleared by
    /// `persist_advance_to`. Never `Some` beside `pending` in any image,
    /// because `format::encode` refuses the pair; the type itself does not
    /// hold it.
    pub settled: Option<Pending>,
}

enum State {
    Live {
        generation: u64,
        slots: BTreeMap<Tag, Slot>,
    },
    Poisoned(Error),
}

/// The keystore handle. Exclusive writer by the lock across processes and by
/// `&mut self` within one. No `Clone` (two handles are two writers — the
/// shipped wallet's race), no `Default`, no `PartialEq`.
#[must_use]
pub struct Keystore<M: Medium = Disk> {
    dir: PathBuf,
    _lock: File,
    medium: M,
    state: State,
    /// The master seed the store holds, when it holds one.
    ///
    /// **In memory for the handle's life, and that is the change the audit
    /// asked for**: before this, every command read twenty-four words from the
    /// terminal to reconstruct it. It is `Secret`, so it zeroizes on drop, and
    /// the handle is dropped at the end of one command -- the mnemonic prompt's "the
    /// crate retains nothing between calls" survives intact. What changed is
    /// where the seed comes from, not how long it lives.
    master: Option<Secret<SEED_LEN>>,
    /// The store key and what it was derived from.
    ///
    /// **Derived once, at open, and held for the handle's life** -- and the
    /// reason is cost:
    /// re-deriving per commit would pay Argon2id's seventy milliseconds on
    /// every write and put pressure on the parameters.
    crypto: StoreCrypto,
    /// The format version the snapshot carried when this handle opened it
    /// (`format::VERSION` for a store this handle created), and the version
    /// on disk now: every commit seals `format::VERSION`, so the two differ
    /// exactly when a version-3 store has crossed to version 4 under this
    /// handle. `open` never commits, so the crossing is
    /// the first write's and never the read's; [`Keystore::upgraded_from`]
    /// is how a page learns it happened.
    opened_version: u16,
    on_disk_version: u16,
    /// On Windows, the two slot files and what this handle knows of them.
    #[cfg(windows)]
    slots: Slots,
}

/// On Windows, the slot files a handle holds, and what it knows of them.
#[cfg(windows)]
struct Slots {
    /// Slot 0 and slot 1, held for the handle's life and shared for reading
    /// alone (`perms::open_slot`); `None` for a slot file not there yet.
    held: [Option<File>; 2],
    /// The slot holding the newest image, which no commit writes. `None` only
    /// inside `create`, before its commit.
    newest: Option<usize>,
    /// Whether the newest slot is known to be on the device -- flushed by
    /// this handle. False after `open`, so a handle's first commit flushes it
    /// before writing the other: after a flush that failed, a later process
    /// can read a newer slot out of the cache although it never reached the
    /// disk, and overwriting the older slot then would leave a power cut
    /// nothing to go back to.
    on_device: bool,
    /// Whether slot 0 has yet to become a frame: it holds a store in the
    /// rename layout, or nothing yet. Until it is one, a build that reads
    /// only that layout would read it as the snapshot.
    vacate: bool,
}

#[cfg(windows)]
impl Slots {
    /// Nothing held and nothing to protect: `create`'s state before its
    /// commit, which creates both files.
    fn fresh() -> Slots {
        Slots {
            held: [None, None],
            newest: None,
            on_device: true,
            vacate: true,
        }
    }
}

/// What a handle needs to read and write its own store.
///
/// No `Debug`, no `Clone`: it holds a key. The Debug-holder scan is what
/// notices if either is ever derived.
struct StoreCrypto {
    key: Zeroizing<[u8; crypt::KEY_LEN]>,
    kdf: crypt::Kdf,
    salt: [u8; crypt::SALT_LEN],
    /// Per-OPEN entropy the per-commit nonce is derived from. See
    /// `crypt::nonce_for` for why this is not a counter and not fresh
    /// randomness per write.
    nonce_seed: [u8; crypt::NONCE_SEED_LEN],
}

/// What a caller supplies to open an existing store.
///
/// `nonce_seed` is entropy, and it is a **parameter** for the reason
/// `cli::create`'s is: there is no RNG in this crate's graph and adding one
/// for this would undo that. The binary reads `/dev/urandom`; a test supplies
/// a constant and gets a deterministic image back, which is what keeps the
/// format KAT, `records_are_addressed_by_tag_not_position` and the I3 crash
/// proof able to compare bytes at all.
pub struct Unlock<'a> {
    pub password: &'a [u8],
    pub nonce_seed: [u8; crypt::NONCE_SEED_LEN],
}

/// What a caller supplies to create one. The salt is entropy too, and it is
/// what makes two stores under one password different files.
pub struct Init<'a> {
    pub password: &'a [u8],
    pub salt: [u8; crypt::SALT_LEN],
    pub nonce_seed: [u8; crypt::NONCE_SEED_LEN],
    /// The KDF cost this store is created with.
    ///
    /// **A parameter, not a constant, and the reason is a measurement.**
    /// `Kdf::RECOMMENDED` is 64 MiB and about seventy milliseconds — right for
    /// a wallet an operator unlocks once per command, and wrong for a test
    /// suite that creates hundreds of stores. When encryption at rest first made every
    /// `Keystore::create` pay it, one `invariants` test took 39 seconds and
    /// the full board deadlocked: the census spawns child processes that open
    /// the same stores, and `keystore_harness::reopen` retries a held `flock`
    /// fifty times, so a lock window that had been microseconds became long
    /// enough for parent and child to wait on each other.
    ///
    /// The parameters live in each file's own header precisely so two stores
    /// can differ, so the fix is not a weaker default — the binary still
    /// passes `Kdf::RECOMMENDED` — but a cheap one in the harness. A test about
    /// the format's layout or the commit state machine is not a test about how
    /// expensive a password guess is.
    pub kdf: crypt::Kdf,
}

fn io(op: &'static str) -> impl Fn(std::io::Error) -> Error {
    move |e| Error::Io { op, kind: e.kind() }
}

fn take_lock(dir: &Path) -> Result<File> {
    let file = perms::open_private_lock(&dir.join(LOCK_NAME)).map_err(io("open lock"))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => Err(Error::Locked),
        Err(TryLockError::Error(e)) => Err(Error::Io {
            op: "flock",
            kind: e.kind(),
        }),
    }
}

/// What [`Keystore::create`] would refuse `dir` for, before it is asked to.
///
/// `Some("snapshot")` -- the one `Exists` refusal `create` makes, from the
/// same name, so there is one definition of "this directory already holds a
/// store" and two callers of it. Added for `cli::create`, whose write
/// moved behind the phrase display and the confirmation: without this, a
/// mistyped `--dir` would have a password chosen and a phrase shown and read
/// back before the keystore said no. The check inside `create` is still the
/// authoritative one; this is the early copy of it, and it deliberately
/// covers only the file-existence refusal -- the permission check needs the
/// directory to exist and the lock needs to be taken, and neither belongs in
/// a probe.
///
/// **`keystore.lock` is not a refusal.** A directory holding the lock and no
/// snapshot is what a `create` killed between `take_lock` and `commit`
/// leaves, and what is left when the snapshot a failed `open` locked beside
/// is removed by hand -- a failed `open` never leaves the lock *alone*, since
/// it got past `Missing` because the snapshot was there and nothing in this
/// crate unlinks one. Reporting that state here would refuse every later
/// `create` with advice every other command contradicts. The file's existence says
/// nothing about a holder; the flock does, `take_lock` asks it, and a live
/// holder is `Locked` there. See the module doc's "The lock".
///
/// **On Windows slot 1 is asked too.** `create` writes it before
/// `accounts.mks`, so a directory holding it without the snapshot is what a
/// `create` cut short leaves -- or the last copy of a store whose snapshot
/// was deleted by hand, which is why it is refused here rather than written
/// over.
pub fn occupied(dir: &Path) -> Option<&'static str> {
    if dir.join(SNAPSHOT_NAME).exists() {
        return Some("snapshot");
    }
    #[cfg(windows)]
    if dir.join(SLOT1_NAME).exists() {
        return Some("snapshot");
    }
    None
}

/// A slot file's bytes, read through the handle held for it: every byte, or
/// -- for a file longer than any frame this build writes, which nothing then
/// allocates for -- the image-length refusal the Unix arm makes of an
/// over-long snapshot, in its words.
#[cfg(windows)]
fn read_slot(file: &mut File) -> Result<Zeroizing<Vec<u8>>> {
    let len = file.metadata().map_err(io("stat slot"))?.len();
    let over = || Error::Range {
        what: "keystore image length",
        min: format::MIN_IMAGE_LEN as u64,
        max: format::MAX_IMAGE_LEN as u64,
        got: len,
    };
    let len = usize::try_from(len)
        .ok()
        .filter(|&len| len <= slots::MAX_FRAME_LEN)
        .ok_or_else(over)?;
    let mut bytes: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; len]);
    file.seek(SeekFrom::Start(0)).map_err(io("read slot"))?;
    file.read_exact(&mut bytes).map_err(io("read slot"))?;
    Ok(bytes)
}

/// The image `open` would take from `dir`, read without the lock and without
/// holding the slots: what a test compares a Windows store by, where a Unix
/// one is compared by its snapshot's bytes, and nothing the wallet calls.
///
/// Windows only, and public only because `tests/` is another crate -- the
/// reason `medium::Instrumented` is public. Ordering two slots needs the key,
/// since the generation is in the ciphertext, so it takes the password.
#[cfg(windows)]
pub fn newest_image(dir: &Path, password: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let read = |name: &str| -> Result<Option<Zeroizing<Vec<u8>>>> {
        match fs::read(dir.join(name)) {
            Ok(bytes) => Ok(Some(Zeroizing::new(bytes))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io("read slot")(e)),
        }
    };
    let slot0 = slots::sort(read(SNAPSHOT_NAME)?)?;
    let slot1 = slots::sort(read(SLOT1_NAME)?)?;
    let newest = if slots::take(&slot0, &slot1, password)?.newest == 0 {
        slot0
    } else {
        slot1
    };
    match newest {
        slots::Content::Image(image) | slots::Content::Other(image) => Ok(image),
        _ => Err(Error::Corrupt {
            what: "neither slot holds an intact image",
            offset: 0,
        }),
    }
}

impl Keystore<Disk> {
    /// Create a new keystore in `dir` (created `0700` if absent). Refuses a
    /// directory that already holds a snapshot, and a live holder of its lock
    /// (`Locked`); a lock file nobody holds is walked through.
    pub fn create(dir: &Path, init: &Init<'_>) -> Result<Self> {
        Self::create_with(dir, Disk, init)
    }

    /// Open an existing keystore. Refuses an unsafe directory, a held lock, and
    /// a missing snapshot.
    pub fn open(dir: &Path, unlock: &Unlock<'_>) -> Result<Self> {
        Self::open_with(dir, Disk, unlock)
    }
}

impl<M: Medium> Keystore<M> {
    /// [`Keystore::create`] over an explicit medium (tests inject
    /// [`Instrumented`]).
    pub fn create_with(dir: &Path, medium: M, init: &Init<'_>) -> Result<Self> {
        if !dir.exists() {
            perms::create_private_dir(dir).map_err(io("create directory"))?;
        }
        perms::refuse_unsafe_dir(dir)?;
        if let Some(what) = occupied(dir) {
            return Err(Error::Exists { what });
        }
        let lock = take_lock(dir)?;
        // **Asked again under the lock**. The check above
        // runs before the lock, so a second `create` can pass it while a
        // first holds the lock with its snapshot not yet renamed in, and then
        // take the lock the moment the first releases it -- and seal an empty
        // store over the first's. Once the lock FILE's existence stood in
        // for this (the first `create` had created it), which is the
        // stale-lock reading the lock design rejected; this is the reading it
        // chose: the decision is taken holding the flock. Not measurable
        // directly -- nothing can be injected between two adjacent
        // statements without a hook -- but a fault-injection row removed the
        // check above and this one still refused an existing store, so it is live.
        if let Some(what) = occupied(dir) {
            return Err(Error::Exists { what });
        }
        // Derived before the first write, so a store that exists is a store
        // whose key was derivable.
        let kdf = init.kdf.checked()?;
        let key = crypt::derive_key(init.password, &init.salt, kdf)?;
        let mut ks = Keystore {
            dir: dir.to_path_buf(),
            _lock: lock,
            medium,
            state: State::Live {
                generation: 0,
                slots: BTreeMap::new(),
            },
            master: None,
            crypto: StoreCrypto {
                key,
                kdf,
                salt: init.salt,
                nonce_seed: init.nonce_seed,
            },
            opened_version: format::VERSION,
            on_disk_version: format::VERSION,
            #[cfg(windows)]
            slots: Slots::fresh(),
        };
        let image = ks.seal(&[], 0)?;
        let _durable: Durable = ks.commit(&image)?;
        Ok(ks)
    }

    /// [`Keystore::open`] over an explicit medium.
    #[cfg(unix)]
    pub fn open_with(dir: &Path, medium: M, unlock: &Unlock<'_>) -> Result<Self> {
        perms::refuse_unsafe_dir(dir)?;
        // The snapshot's existence is checked before the lock file is touched,
        // so an `open` that reports `Missing` leaves no lock behind. **Every
        // refusal below this point does leave one**, because
        // `take_lock` creates the file and the read that follows has to be
        // under the lock to be authoritative; that leftover is inert
        // -- `create` no longer reads the file's existence as a store -- and
        // the module doc's "The lock" says why it is left rather than moved
        // or unlinked. The authoritative read happens after the lock, below.
        let path = dir.join(SNAPSHOT_NAME);
        if !path.exists() {
            return Err(Error::Missing);
        }
        let lock = take_lock(dir)?;
        // A stale temp is a partial or complete image from an interrupted
        // commit. Never adopted; unlinked so it cannot leak or confuse a
        // later listing. Failure to unlink here means rename would fail too.
        let temp = dir.join(TEMP_NAME);
        if temp.exists() {
            fs::remove_file(&temp).map_err(io("remove stale temp"))?;
        }
        let meta = match fs::metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(Error::Missing),
            Err(e) => return Err(io("stat snapshot")(e)),
        };
        // The same range `format::read_header` names for the same
        // refusal: one `what`, one minimum (the empty store's image), one
        // maximum.
        let len = usize::try_from(meta.len()).map_err(|_| Error::Range {
            what: "keystore image length",
            min: format::MIN_IMAGE_LEN as u64,
            max: format::MAX_IMAGE_LEN as u64,
            got: meta.len(),
        })?;
        if len > format::MAX_IMAGE_LEN {
            return Err(Error::Range {
                what: "keystore image length",
                min: format::MIN_IMAGE_LEN as u64,
                max: format::MAX_IMAGE_LEN as u64,
                got: meta.len(),
            });
        }
        let mut file = File::open(&path).map_err(io("open snapshot"))?;
        let mut image: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; len]);
        file.read_exact(&mut image).map_err(io("read snapshot"))?;
        let mut extra = [0u8; 1];
        let n = file.read(&mut extra).map_err(io("read snapshot"))?;
        if n != 0 {
            return Err(Error::Corrupt {
                what: "snapshot grew while being read",
                offset: len,
            });
        }
        // The header is plaintext and is read first: a version this build
        // does not know is `UnsupportedVersion` before a key is derived, so a
        // v2 store does not cost the operator seventy milliseconds of Argon2
        // to be told to migrate. A version-3 store is READ: the same
        // derivation and the same AEAD, a 178-byte record, and
        // nothing is rewritten here -- the first commit re-seals it.
        let framed = format::read_header(&image)?;
        let (salt, kdf, version) = (framed.header.salt, framed.header.kdf, framed.version);
        let key = crypt::derive_key(unlock.password, &salt, kdf)?;
        let parsed = format::parse_with_key(&image, &key)?;
        Ok(Keystore {
            dir: dir.to_path_buf(),
            _lock: lock,
            medium,
            state: State::Live {
                generation: parsed.generation,
                slots: parsed.slots,
            },
            master: parsed.master,
            crypto: StoreCrypto {
                key,
                kdf,
                salt,
                nonce_seed: unlock.nonce_seed,
            },
            opened_version: version,
            on_disk_version: version,
        })
    }

    /// [`Keystore::open`] over an explicit medium, on Windows: the same
    /// refusals in the same order as the Unix arm's, then both slots read
    /// through the handles this one holds for its life, and the newer image
    /// taken by `slots`' rule.
    ///
    /// **Read through the held handles, with nothing re-checked after.** The
    /// Unix arm refuses a snapshot that grows while it is read; here the
    /// handles share read access alone, so nothing else can write a slot
    /// while it is read, or after, while the handle lives.
    #[cfg(windows)]
    pub fn open_with(dir: &Path, medium: M, unlock: &Unlock<'_>) -> Result<Self> {
        perms::refuse_unsafe_dir(dir)?;
        // The snapshot's name before the lock file is touched, the read under
        // the lock, a stale temp unlinked and never adopted: the Unix arm's
        // order, for its reasons, which its comments give.
        let path = dir.join(SNAPSHOT_NAME);
        if !path.exists() {
            return Err(Error::Missing);
        }
        let lock = take_lock(dir)?;
        let temp = dir.join(TEMP_NAME);
        if temp.exists() {
            fs::remove_file(&temp).map_err(io("remove stale temp"))?;
        }
        let mut held0 = perms::open_slot(&path)?.ok_or(Error::Missing)?;
        let mut held1 = perms::open_slot(&dir.join(SLOT1_NAME))?;
        let slot0 = slots::sort(Some(read_slot(&mut held0)?))?;
        // Slot 1 longer than any frame is torn rather than a refusal: it is
        // never read while slot 0 holds the store, and never allocated for.
        let slot1 = match held1.as_mut() {
            None => slots::Content::Absent,
            Some(file) => match read_slot(file) {
                Err(Error::Range { .. }) => slots::Content::Torn,
                read => slots::sort(Some(read?))?,
            },
        };
        let taken = slots::take(&slot0, &slot1, unlock.password)?;
        let vacate = matches!(slot0, slots::Content::Other(_));
        Ok(Keystore {
            dir: dir.to_path_buf(),
            _lock: lock,
            medium,
            state: State::Live {
                generation: taken.parsed.generation,
                slots: taken.parsed.slots,
            },
            master: taken.parsed.master,
            crypto: StoreCrypto {
                key: taken.key,
                kdf: taken.kdf,
                salt: taken.salt,
                nonce_seed: unlock.nonce_seed,
            },
            opened_version: taken.version,
            on_disk_version: taken.version,
            slots: Slots {
                held: [Some(held0), held1],
                newest: Some(taken.newest),
                on_device: false,
                vacate,
            },
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The medium, for instrument inspection in tests.
    pub fn medium(&self) -> &M {
        &self.medium
    }

    pub fn medium_mut(&mut self) -> &mut M {
        &mut self.medium
    }

    /// Encode and seal one image. **The single site that produces a file**,
    /// so the nonce derivation cannot be forgotten at one of four call sites.
    fn seal(&self, records: &[RecordRef<'_>], generation: u64) -> Result<Zeroizing<Vec<u8>>> {
        let nonce = crypt::nonce_for(&self.crypto.nonce_seed, generation);
        format::encode(
            records,
            generation,
            self.master.as_ref(),
            self.crypto.kdf,
            &self.crypto.salt,
            &self.crypto.key,
            &nonce,
        )
    }

    fn live(&self) -> Result<(u64, &BTreeMap<Tag, Slot>)> {
        match &self.state {
            State::Live { generation, slots } => Ok((*generation, slots)),
            State::Poisoned(first) => Err(Error::Poisoned {
                first: Box::new(first.clone()),
            }),
        }
    }

    fn live_mut(&mut self) -> Result<(&mut u64, &mut BTreeMap<Tag, Slot>)> {
        match &mut self.state {
            State::Live { generation, slots } => Ok((generation, slots)),
            State::Poisoned(first) => Err(Error::Poisoned {
                first: Box::new(first.clone()),
            }),
        }
    }

    /// The store-level commit counter, the "keystore metadata" member I3
    /// names alongside the index and the pending record.
    pub fn generation(&self) -> Result<u64> {
        self.live().map(|(g, _)| g)
    }

    pub fn view(&self, tag: &Tag) -> Result<Option<AccountView>> {
        let (_, slots) = self.live()?;
        Ok(slots.get(tag).map(|s| AccountView {
            tag: *tag,
            kind: s.account.kind(),
            wots_index: s.account.wots_index(),
            pending: s.pending,
            settled: s.settled,
        }))
    }

    /// The format version this handle read at `open`, when it differs from
    /// the version on disk now -- that is, once a version-3 store has been
    /// re-sealed as version 4 by a commit under this handle. `None` for a
    /// store created by this build, for a version-4 store,
    /// and for a version-3 store that has not been written yet: `open` does
    /// not rewrite the snapshot. The crossing is one-way, and the page of the
    /// command that made the first write says so through this.
    pub fn upgraded_from(&self) -> Option<u16> {
        (self.opened_version != self.on_disk_version).then_some(self.opened_version)
    }

    /// The public identity of this account's key stream — the rotation-0
    /// public key's hash, carried by every record since format v2.
    ///
    /// Read, not recomputed: `add` recomputes it for the account being added
    /// and `sign_spend` re-derives a derived account's from the master, so
    /// the stored value has been checked everywhere it can be. Its use here
    /// is a **divergence report**, where it lets an operator compare two
    /// stores on one seed without either exposing key material.
    pub fn stream_id(&self, tag: &Tag) -> Result<crate::account::StreamId> {
        let (_, slots) = self.live()?;
        let slot = slots.get(tag).ok_or(Error::NoSuchAccount)?;
        Ok(Self::stored_stream_id(&slot.account))
    }

    /// The master seed this store holds, if it holds one.
    ///
    /// **This is where `Wallet::open` and `sign_spend` get their seed**, and
    /// there is no prompt behind it: the seed is in memory only because the
    /// password decrypted the file that holds it, and it goes when the handle
    /// does.
    pub fn master(&self) -> Result<Option<&Secret<SEED_LEN>>> {
        self.live()?;
        Ok(self.master.as_ref())
    }

    /// Put a master seed into a store that has none, and commit.
    ///
    /// # Why it refuses to replace one
    ///
    /// A store's derived accounts are `derive(master, i)`; replacing the
    /// master would leave every one of them pointing at a key stream the store
    /// can no longer produce, which is I5's loss mode arrived at through a
    /// setter. There is no path that wants it: `create` adopts once into an
    /// empty store, and every later command reads what is there.
    pub fn adopt_master(&mut self, master: &Secret<SEED_LEN>) -> Result<Durable> {
        let (generation, slots) = self.live()?;
        if self.master.is_some() {
            return Err(Error::Exists {
                what: "master seed",
            });
        }
        let next_gen = generation.checked_add(1).ok_or(Error::Range {
            what: "keystore generation",
            min: 0,
            max: u64::MAX,
            got: u64::MAX,
        })?;
        let records = Self::records_with(slots, None, None);
        let nonce = crypt::nonce_for(&self.crypto.nonce_seed, next_gen);
        let image = format::encode(
            &records,
            next_gen,
            Some(master),
            self.crypto.kdf,
            &self.crypto.salt,
            &self.crypto.key,
            &nonce,
        )?;
        let durable = self.commit(&image)?;
        self.master = Some(master.duplicate());
        if let State::Live { generation, .. } = &mut self.state {
            *generation = next_gen;
        }
        Ok(durable)
    }

    /// Every tag, ascending.
    pub fn tags(&self) -> Result<Vec<Tag>> {
        let (_, slots) = self.live()?;
        Ok(slots.keys().copied().collect())
    }

    /// The four steps, in order, and the single site that constructs
    /// [`Durable`]. On any error the handle is poisoned before the error is
    /// returned; no further filesystem operation is performed on the error
    /// path, so what a kill at that boundary would leave is what the
    /// interrupted step left. On Windows the steps are the slot layout's,
    /// in `Keystore::write_slots`, and they return into the same arm.
    fn commit(&mut self, image: &[u8]) -> Result<Durable> {
        let dir = self.dir.clone();
        #[cfg(windows)]
        let outcome = self.write_slots(&dir, image);
        #[cfg(unix)]
        let outcome = (|| -> Result<()> {
            let written = self.medium.write_temp(&dir, image)?;
            let synced = self.medium.fsync_file(written)?;
            let renamed = self.medium.rename(synced, &dir)?;
            self.medium.fsync_dir(renamed, &dir)
        })();
        match outcome {
            Ok(()) => {
                // Every image this handle seals is `format::VERSION`; a
                // version-3 store crossed here, on its first commit.
                self.on_disk_version = format::VERSION;
                Ok(Durable(()))
            }
            Err(e) => {
                self.state = State::Poisoned(e.clone());
                Err(e)
            }
        }
    }

    /// The Windows commit: `image` framed and written into the slot that does
    /// not hold the newest one, and flushed.
    ///
    /// Three rules, each the crash argument's and not a convenience. The
    /// newest slot is on the device before the other is written: a handle's
    /// first commit flushes it as it found it (`Slots::on_device` says why).
    /// The write is flushed before this returns, so before `Durable` exists.
    /// And a plain image in slot 0 is overwritten only once slot 1 holds a
    /// flushed frame, with the vacant frame, which is what makes a build that
    /// reads only the rename layout refuse the store from then on.
    ///
    /// A store with nothing in either slot yet is `create`'s: its image goes
    /// to slot 1 and slot 0 is made vacant after it, so `accounts.mks`
    /// existing means an image is on the device.
    #[cfg(windows)]
    fn write_slots(&mut self, dir: &Path, image: &[u8]) -> Result<()> {
        if let (Some(newest), false) = (self.slots.newest, self.slots.on_device) {
            let standing = self.slots.held[newest].as_ref().ok_or(Error::Io {
                op: "flush_standing",
                kind: std::io::ErrorKind::NotFound,
            })?;
            self.medium.flush_standing(dir, newest, standing)?;
            self.slots.on_device = true;
        }
        let target = if self.slots.newest == Some(1) { 0 } else { 1 };
        let framed = slots::frame(image)?;
        let written = self.medium.write_slot(dir, target, &mut self.slots.held[target], &framed)?;
        let _flushed = self.medium.flush_slot(written)?;
        if target == 1 && self.slots.vacate {
            let vacant = slots::frame(&[])?;
            let written = self.medium.write_slot(dir, 0, &mut self.slots.held[0], &vacant)?;
            let _flushed = self.medium.flush_slot(written)?;
        }
        self.slots.vacate = false;
        self.slots.newest = Some(target);
        Ok(())
    }

    /// Build the record list for an image: the current slots, optionally with
    /// one record's index and its two blocks overridden and optionally with
    /// one extra account appended, sorted by tag. Every slot the override
    /// does not name carries its own `pending` AND its own `settled` -- a
    /// retained block survives every write that is about some other account
    /// (`a_retained_block_survives_a_write_that_does_not_override_its_account`).
    fn records_with<'a>(
        slots: &'a BTreeMap<Tag, Slot>,
        over: Option<(&Tag, WotsIndex, Option<Pending>, Option<Pending>)>,
        extra: Option<(&'a Account, Tag)>,
    ) -> Vec<RecordRef<'a>> {
        let mut out: Vec<RecordRef<'a>> = slots
            .iter()
            .map(|(tag, slot)| {
                let (wots_index, pending, settled) = match over {
                    Some((t, i, p, s)) if t == tag => (i, p, s),
                    _ => (slot.account.wots_index(), slot.pending, slot.settled),
                };
                RecordRef {
                    tag: *tag,
                    account: &slot.account,
                    wots_index,
                    pending,
                    settled,
                }
            })
            .collect();
        if let Some((account, tag)) = extra {
            out.push(RecordRef {
                tag,
                account,
                wots_index: account.wots_index(),
                pending: None,
                settled: None,
            });
            out.sort_by_key(|r| r.tag);
        }
        out
    }

    /// Add an account and make it durable. Insert-only, and it refuses three
    /// collisions rather than one:
    ///
    /// * **the tag** -- one slot per account;
    /// * **the imported root itself**, constant-time and checked first, so
    ///   one root under two tags reports the key material rather than the
    ///   value derived from it. The crate's one comparison of secret bytes
    ///   (`Secret::ct_eq`), and it holds even where a stored
    ///   identity has been tampered with;
    /// * **the key stream**, across kinds, by the identity every record has
    ///   carried since format v2: a rotation key is a function of the 32-byte
    ///   seed alone, so a derived account's seed re-imported under another tag
    ///   -- or the *same* root imported under a first address built from junk
    ///   components, which verifies and yields another tag -- is two indices
    ///   over one stream, and one key signs twice. This is the half a
    ///   drop-and-reopen defeated before v2: the identity has to be in the
    ///   record (filed, then landed with format v2). The incoming account's
    ///   identity is **recomputed** here from its own key material rather
    ///   than read off it -- from the root for an imported account, and for
    ///   a derived one from the master seed the store has held since format
    ///   v3 -- so a forged record cannot walk past this; a derived record
    ///   whose stored tag or identity is not what its seed produces is
    ///   refused at the door, by the names `sign_spend` uses. Only a store
    ///   holding no master takes a derived account's identity as carried,
    ///   because there nothing can recompute it and nothing can sign for it
    ///   either; `sign_spend` re-derives it the day a master is in hand.
    ///
    /// No receipt: receipts attest advances.
    pub fn add(&mut self, account: Account) -> Result<()> {
        let tag = account.tag();
        let (generation, slots) = self.live()?;
        if slots.contains_key(&tag) {
            return Err(Error::Exists { what: "account tag" });
        }
        // The root check first, so the same root under two tags reports the
        // specific thing it is rather than the general one. Equal roots imply
        // equal stream identities, so the order decides which message a
        // caller sees -- and this one names the key material.
        if let crate::account::KeyMaterial::Imported { root, .. } = account.key_material() {
            if self.imported_roots(slots).any(|stored| stored.ct_eq(root.secret())) {
                return Err(Error::Exists { what: "imported root" });
            }
        }
        let incoming = self.recomputed_stream_id(&account)?;
        if slots
            .values()
            .any(|s| Self::stored_stream_id(&s.account) == incoming)
        {
            return Err(Error::Exists { what: "key stream" });
        }
        let next_gen = generation.checked_add(1).ok_or(Error::Range {
            what: "keystore generation",
            min: 0,
            max: u64::MAX - 1,
            got: generation,
        })?;
        let image = self.seal(&Self::records_with(slots, None, Some((&account, tag))), next_gen)?;
        let _durable: Durable = self.commit(&image)?;
        let (g, slots) = self.live_mut()?;
        *g = next_gen;
        slots.insert(
            tag,
            Slot {
                account,
                pending: None,
                settled: None,
            },
        );
        Ok(())
    }

    /// The stream identity an account's **key material** produces, for the
    /// account being added: recomputed from the imported root, or from the
    /// master seed this store holds for a derived account -- the same two
    /// comparisons `key_at` makes at signing time, refused by the same
    /// names, so a forged derived record is refused at `add` rather than
    /// at `sign_spend`. A store holding no master cannot recompute it and
    /// takes the stored value: that store cannot sign for the account
    /// either, and `sign_spend` re-derives the identity once a master is
    /// in hand. `Account::restore_from_record` carries the same asymmetry
    /// for a record read off disk, where no master is in hand at all.
    fn recomputed_stream_id(&self, account: &Account) -> Result<crate::account::StreamId> {
        match account.key_material() {
            crate::account::KeyMaterial::Imported { root, .. } => {
                Ok(crate::derive::stream_id(root.secret()))
            }
            crate::account::KeyMaterial::Derived {
                account_index,
                stream,
            } => match &self.master {
                Some(master) => {
                    let derived = crate::derive::derive_account(master, *account_index);
                    if derived.tag() != account.tag() {
                        return Err(Error::DerivedTagNotReproduced {
                            account_index: *account_index,
                        });
                    }
                    let recomputed = crate::derive::stream_id(derived.seed());
                    if recomputed != *stream {
                        return Err(Error::StreamIdNotReproduced);
                    }
                    Ok(recomputed)
                }
                None => Ok(*stream),
            },
        }
    }

    /// The stream identity a stored slot carries.
    fn stored_stream_id(account: &Account) -> crate::account::StreamId {
        match account.key_material() {
            crate::account::KeyMaterial::Imported { stream, .. }
            | crate::account::KeyMaterial::Derived { stream, .. } => *stream,
        }
    }

    /// Reserve the account's current key for `digest` and advance the index
    /// by one, durably, in one write. The receipt attests the new index.
    ///
    /// `figures` are the reserved spend's two figures:
    /// the ledger balance the plan was built against and its block-to-live,
    /// recorded beside the digest so that a later reader can tell a dead
    /// reservation from a live one and recover the block-to-live
    /// without the page that printed it. Always recorded for a
    /// new reservation; the one producer of an absent pair is the version-3
    /// read arm. A retained settled block does not refuse this -- it is
    /// overwritten, which is what releases it; only an OPEN
    /// reservation does.
    pub fn persist_advance(&mut self, tag: &Tag, digest: &[u8; 32], figures: Figures) -> Result<AdvanceReceipt> {
        let (generation, slots) = self.live()?;
        let slot = slots.get(tag).ok_or(Error::NoSuchAccount)?;
        if let Some(p) = slot.pending {
            return Err(Error::PendingUnresolved {
                spent_index: p.spent_index.get(),
            });
        }
        let current = slot.account.wots_index();
        let next = current.advanced()?;
        let pending = Some(Pending {
            spent_index: current,
            digest: *digest,
            figures: Some(figures),
        });
        self.advance_committed(tag, generation, next, pending, None)
    }

    /// Move the index forward to `target` without reserving a key — the
    /// reconciliation path. Refuses anything not strictly ahead, and refuses
    /// while a spend is pending. A retained settled block is CLEARED by this
    /// write: an acknowledged advance moves the index,
    /// so the relation `spent_index + 1 == wots_index` would no longer hold,
    /// and the encoder refuses rather than seals a block it was left in.
    pub fn persist_advance_to(&mut self, tag: &Tag, target: WotsIndex) -> Result<AdvanceReceipt> {
        let (generation, slots) = self.live()?;
        let slot = slots.get(tag).ok_or(Error::NoSuchAccount)?;
        if let Some(p) = slot.pending {
            return Err(Error::PendingUnresolved {
                spent_index: p.spent_index.get(),
            });
        }
        let stored = slot.account.wots_index();
        if target.get() <= stored.get() {
            return Err(Error::Range {
                what: "wots index for tag",
                min: u64::from(stored.get()) + 1,
                max: u64::from(u32::MAX),
                got: u64::from(target.get()),
            });
        }
        self.advance_committed(tag, generation, target, None, None)
    }

    /// One commit that moves the index and sets both blocks to exactly what
    /// the caller passes -- and, durable in hand, applies the same pair in
    /// memory, so the live handle never disagrees with the image about
    /// `settled` any more than about `pending`.
    fn advance_committed(
        &mut self,
        tag: &Tag,
        generation: u64,
        next: WotsIndex,
        pending: Option<Pending>,
        settled: Option<Pending>,
    ) -> Result<AdvanceReceipt> {
        let next_gen = generation.checked_add(1).ok_or(Error::Range {
            what: "keystore generation",
            min: 0,
            max: u64::MAX - 1,
            got: generation,
        })?;
        let image = {
            let (_, slots) = self.live()?;
            self.seal(&Self::records_with(slots, Some((tag, next, pending, settled)), None), next_gen)?
        };
        let durable = self.commit(&image)?;
        // Durable in hand: apply in memory exactly what disk now holds. An
        // error past this point would leave disk ahead of memory with the
        // handle live -- the one gap in the commit sequence -- so it
        // poisons the handle before it returns, the
        // way `commit` poisons on its own errors. Unreachable from today's
        // callers, every argument having been checked before the seal; the
        // module's unit test drives it directly.
        let applied = (|| -> Result<AdvanceReceipt> {
            let (g, slots) = self.live_mut()?;
            *g = next_gen;
            let slot = slots.get_mut(tag).ok_or(Error::NoSuchAccount)?;
            slot.account.advance_to(next)?;
            slot.pending = pending;
            slot.settled = settled;
            Ok(AdvanceReceipt::attesting(*tag, next, durable))
        })();
        self.poison_on(applied)
    }

    /// The application half of a commit, held to the commit's own rule: an
    /// error after the image is durable poisons the handle, since memory no
    /// longer says what disk says and a later call would act on the stale
    /// half.
    fn poison_on<T>(&mut self, applied: Result<T>) -> Result<T> {
        match applied {
            Ok(v) => Ok(v),
            Err(e) => {
                self.state = State::Poisoned(e.clone());
                Err(e)
            }
        }
    }

    /// Move the open reservation to the retained settled block, durably.
    /// The block -- index, digest and figures -- is
    /// kept under the record's third state until the next `persist_advance`
    /// overwrites it or `persist_advance_to` clears it, because a settle
    /// taken on one observation (the settle rule) can be reverted by
    /// the chain, and the store that discarded the block would then hold no
    /// record of the only signature that key may ever give. It costs no byte:
    /// the fields exist. `slot.pending` becomes `None`, which is what lets
    /// the account spend again; nothing reads the retained block as an open
    /// reservation.
    pub fn persist_settled(&mut self, tag: &Tag) -> Result<()> {
        let (generation, slots) = self.live()?;
        let slot = slots.get(tag).ok_or(Error::NoSuchAccount)?;
        let block = slot.pending.ok_or(Error::NothingPending)?;
        let index = slot.account.wots_index();
        let next_gen = generation.checked_add(1).ok_or(Error::Range {
            what: "keystore generation",
            min: 0,
            max: u64::MAX - 1,
            got: generation,
        })?;
        let image = self.seal(&Self::records_with(slots, Some((tag, index, None, Some(block))), None), next_gen)?;
        let _durable: Durable = self.commit(&image)?;
        // Durable in hand: apply in memory exactly what disk now holds; an
        // error here poisons, as in `advance_committed`. The slot was read
        // above, so its absence now is a state the handle cannot explain.
        let applied = (|| -> Result<()> {
            let (g, slots) = self.live_mut()?;
            *g = next_gen;
            let slot = slots.get_mut(tag).ok_or(Error::NoSuchAccount)?;
            slot.pending = None;
            slot.settled = Some(block);
            Ok(())
        })();
        self.poison_on(applied)
    }

    /// Consume the handle into its records — the one door key material leaves
    /// through, the same conspicuous-and-consuming convention as
    /// `Account::to_record`. The lock is released when the handle drops.
    pub fn into_records(self) -> Result<Vec<AccountRecord>> {
        match self.state {
            State::Live { slots, .. } => Ok(slots.into_values().map(|s| s.account.to_record()).collect()),
            State::Poisoned(first) => Err(Error::Poisoned {
                first: Box::new(first),
            }),
        }
    }
}

impl<M: Medium> core::fmt::Debug for Keystore<M> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut d = f.debug_struct("Keystore");
        d.field("dir", &self.dir);
        match &self.state {
            State::Live { generation, slots } => {
                d.field("generation", generation).field("accounts", &slots.len())
            }
            State::Poisoned(e) => d.field("poisoned", e),
        };
        d.finish()
    }
}

#[cfg(test)]
mod tests {
    //! What only this module can drive: `advance_committed` is private, and
    //! every public caller checks its arguments before the seal, so the
    //! application half's failure has no public route.
    // Not under Miri: this module is one gated test and the three helpers
    // it alone uses, so under that cfg the glob brings in nothing.
    #[cfg(not(miri))]
    use super::*;

    // Not under Miri: its one caller is the gated test, and the wall
    // clock it reads is what Miri's isolation refuses first.
    #[cfg(not(miri))]
    fn scratch(name: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("mcm-keystore-unit-{name}-{}-{nanos}", std::process::id()))
    }

    // Not under Miri: read only by the gated poisoning test.
    #[cfg(not(miri))]
    const PASSWORD: &[u8] = b"unit-test-password-not-for-use";
    // Not under Miri: read only by the gated poisoning test.
    #[cfg(not(miri))]
    const NONCE_SEED: [u8; NONCE_SEED_LEN] = [4u8; NONCE_SEED_LEN];

    /// Disk ahead of memory poisons the handle.
    ///
    /// `advance_committed` with a `next` equal to the current position and
    /// no blocks: the encoder accepts that image (position 0, nothing
    /// pending), `commit` writes it under the next generation, and
    /// `advance_to` then refuses a target that is not strictly ahead. Disk
    /// holds generation 2; memory would have held generation 1's slot. The
    /// handle must answer its next call as poisoned, and a fresh open must
    /// read the generation the commit wrote.
    ///
    /// Not under Miri: this test reads the wall clock for its scratch
    /// directory and then writes a real store, and Miri's isolation refuses
    /// the first of those (`clock_gettime` with a realtime clock) before
    /// the first `mkdir`; the poisoning path it drives is safe
    /// Rust over syscalls, with nothing for an interpreter to check.
    #[cfg(not(miri))]
    #[test]
    fn a_failed_application_after_a_durable_commit_poisons_the_handle() {
        let dir = scratch("item14");
        let init = Init {
            password: PASSWORD,
            salt: [3u8; SALT_LEN],
            nonce_seed: NONCE_SEED,
            kdf: Kdf::CHEAP_FOR_TESTS,
        };
        let mut ks = Keystore::create(&dir, &init).unwrap_or_else(|e| panic!("{e}"));
        let master = Secret::new([7u8; SEED_LEN]);
        let account = Account::derive(&master, 0);
        let tag = account.tag();
        ks.add(account).unwrap_or_else(|e| panic!("{e}"));
        let generation = ks.generation().unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(generation, 1, "premise: create then add is generation 1");

        let err = ks.advance_committed(&tag, generation, WotsIndex::ZERO, None, None).err();
        assert!(
            matches!(err, Some(Error::Range { .. })),
            "premise: advance_to must refuse a target equal to the current position, after the \
             commit: {err:?}"
        );
        let next_call = ks.generation().err();
        assert!(
            matches!(next_call, Some(Error::Poisoned { .. })),
            "THE HANDLE ANSWERED AS IF NOTHING HAPPENED after a durable commit whose application \
             failed: {next_call:?}. Disk is ahead of memory and the handle is live."
        );
        drop(ks);
        let reopened = Keystore::open(
            &dir,
            &Unlock {
                password: PASSWORD,
                nonce_seed: NONCE_SEED,
            },
        )
        .unwrap_or_else(|e| panic!("reopen: {e}"));
        assert_eq!(
            reopened.generation().unwrap_or_else(|e| panic!("{e}")),
            2,
            "the image on disk does not carry the generation the commit wrote"
        );
        let view = reopened
            .view(&tag)
            .unwrap_or_else(|e| panic!("{e}"))
            .unwrap_or_else(|| panic!("the account is gone from disk"));
        assert_eq!(view.wots_index, WotsIndex::ZERO, "the image on disk moved the position");
        drop(reopened);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

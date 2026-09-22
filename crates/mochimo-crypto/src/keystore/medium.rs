//! The four durable steps as primitives, and the typestate that fixes their
//! order.
//!
//! # Why a trait, and why it is sealed
//!
//! The keystore's commit is four syscall-level steps: write the temp, fsync
//! it, rename it over the target, fsync the directory. The steps are
//! primitives supplied by a [`Medium`]; the **order** is crate-owned code in
//! `Keystore::commit` and is not something an implementor can change. The
//! trait is `pub` only so that `tests/` — an external crate — can drive the
//! instrumented medium; it is sealed so nothing outside this crate can
//! implement it, which is what makes "the durability contract is I2's clause"
//! a property rather than a promise.
//!
//! # The typestate
//!
//! Each step returns a token the next step consumes: `write_temp -> Written`,
//! `fsync_file(Written) -> Synced`, `rename(Synced) -> Renamed`,
//! `fsync_dir(Renamed)`. A reorder is a type error (E0308), not a review
//! finding — `ui/fail/medium_steps_are_not_reorderable.rs` pins it. The
//! tokens have private fields, so they cannot be forged outside the crate.
//!
//! # What the instrumented medium models, and what it cannot
//!
//! [`Instrumented`] records every call **with its arguments** and can be told
//! to stop after call `k`: it performs the primitive and then returns an
//! error, modelling a process that died after the syscall completed and
//! before it consumed the return. Everything a completed syscall left behind
//! is visible afterwards; that is a kill at a syscall boundary. It is **not**
//! power loss: it cannot drop the page cache or truncate a journal, and it
//! cannot make `fsync` lie. Those residues are stated at the proof tests.
//! Recording arguments is what makes the recorder non-decorative: an fsync on
//! the wrong path keeps every count and every byte assertion green and is
//! visible only here (the proof test's sequence assertion, and the paired
//! injection that shows it).

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use super::perms;
use crate::error::{Error, Result};

pub(crate) const SNAPSHOT_NAME: &str = "accounts.mks";
pub(crate) const TEMP_NAME: &str = "accounts.mks.tmp";

mod sealed {
    pub trait Sealed {}
}

/// The temp file has been written in full (not yet flushed).
pub struct Written {
    file: File,
    path: PathBuf,
}

/// The temp file's bytes and metadata have reached the device (`sync_all`,
/// not `sync_data`: a new inode's size and block map are metadata, which
/// `fdatasync` may omit).
pub struct Synced {
    path: PathBuf,
}

/// The temp has been renamed over the target; the directory entry may still
/// be in an uncommitted journal transaction until `fsync_dir`.
pub struct Renamed {
    _private: (),
}

/// The primitives. See the module doc for why the order is not here.
pub trait Medium: sealed::Sealed {
    fn write_temp(&mut self, dir: &Path, image: &[u8]) -> Result<Written>;
    fn fsync_file(&mut self, written: Written) -> Result<Synced>;
    fn rename(&mut self, synced: Synced, dir: &Path) -> Result<Renamed>;
    fn fsync_dir(&mut self, renamed: Renamed, dir: &Path) -> Result<()>;
}

fn io(op: &'static str) -> impl Fn(std::io::Error) -> Error {
    move |e| Error::Io { op, kind: e.kind() }
}

/// The real filesystem.
pub struct Disk;

impl sealed::Sealed for Disk {}

impl Medium for Disk {
    fn write_temp(&mut self, dir: &Path, image: &[u8]) -> Result<Written> {
        let path = dir.join(TEMP_NAME);
        // A leftover temp is UNLINKED first, then the temp is created new.
        // The unlink is what keeps a temp left by an earlier crash from
        // blocking every future commit; creating new rather than truncating
        // is what keeps that leftover's mode out of the snapshot, since a
        // mode passed to `open` applies only when the file is created and a
        // truncated leftover carries its own permissions through the rename.
        // `open` already unlinks a stale temp after taking the lock; doing it
        // here too is what keeps `create`'s first commit, and every other,
        // from depending on the caller remembering. The mode the temp is
        // created with is `perms::FILE_MODE`, and the reason it is the same
        // `0600` the lock file gets is argued there: since format v3 the temp
        // is a 51-byte plaintext header over a sealed body, so a partial one
        // leaks the KDF parameters, the salt and the nonce rather than a root
        // -- metadata, not key material, and still nobody else's.
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(io("write_temp unlink stale temp")(e)),
        }
        let mut file = perms::create_private_file(&path).map_err(io("write_temp open"))?;
        file.write_all(image).map_err(io("write_temp write"))?;
        Ok(Written { file, path })
    }

    fn fsync_file(&mut self, written: Written) -> Result<Synced> {
        written.file.sync_all().map_err(io("fsync_file"))?;
        Ok(Synced { path: written.path })
    }

    fn rename(&mut self, synced: Synced, dir: &Path) -> Result<Renamed> {
        fs::rename(&synced.path, dir.join(SNAPSHOT_NAME)).map_err(rename_refusal)?;
        Ok(Renamed { _private: () })
    }

    #[cfg(unix)]
    fn fsync_dir(&mut self, _renamed: Renamed, dir: &Path) -> Result<()> {
        // On Apple targets std's sync_all is fcntl(F_FULLFSYNC) with no
        // fallback; it was measured succeeding on a directory fd on APFS.
        File::open(dir)
            .map_err(io("fsync_dir open"))?
            .sync_all()
            .map_err(io("fsync_dir"))
    }

    /// **The fourth step performs no I/O on Windows, and I3's power-loss
    /// clause is not claimed there.**
    ///
    /// The Unix step cannot simply be compiled here. `File::open` on a
    /// directory is `CreateFileW` without `FILE_FLAG_BACKUP_SEMANTICS`, which
    /// Windows refuses, so that body fails every commit at its last step --
    /// after the rename, on a handle that is then poisoned for a commit that
    /// landed. Read in `std`'s Windows `fs` source, not run.
    ///
    /// Nor is there a substitute to put in its place. What the Unix step buys
    /// is that the directory entry the rename wrote reaches the device before
    /// [`crate::keystore::Durable`] is minted, so a power cut after the
    /// receipt cannot bring back the previous snapshot. Win32 documents no
    /// call that establishes that for a same-volume rename on NTFS:
    /// `MOVEFILE_WRITE_THROUGH` is documented for a move performed as a copy
    /// and a delete, and a directory handle opened for backup semantics and
    /// flushed is behaviour no document states. Two candidates were weighed
    /// and refused:
    ///
    /// * **Flush a directory handle opened with backup semantics.** It may
    ///   commit the entry and may be refused; neither is documented, and a
    ///   refusal here fails a commit whose rename already landed.
    /// * **Reopen the snapshot under its new name and flush it.** That
    ///   flushes the file, which the second step already did under the old
    ///   name. Whether flushing a file also commits the journal record of the
    ///   rename that named it is an NTFS implementation property this tree
    ///   has not measured, and the reopen is a fresh chance for the sharing
    ///   refusal `ReplaceRefused` names -- again after the rename.
    ///
    /// Either would make the claim sound stronger than anything measured,
    /// which is the one thing this step must not do.
    ///
    /// # What that leaves, stated as a hazard and not as a footnote
    ///
    /// Every kill at a syscall boundary is still covered: the rename is
    /// visible to every other process when it returns, and the proofs driven
    /// through [`Instrumented`] are about exactly that. That rests on the
    /// replacing move being atomic, which NTFS provides and Win32 does not
    /// document -- the same reliance the keystore states for ext4 and APFS,
    /// on one more filesystem. What is not covered is
    /// **power loss or an operating-system crash between a commit and the
    /// filesystem's own flush of its log**. After one, the previous snapshot
    /// can come back. If that commit reserved a key and the spend it signed
    /// has not yet settled, the store no longer records the reservation, and
    /// the next spend can reserve and sign the same position again -- the
    /// key reuse this wallet exists to refuse. Reconciliation catches it only
    /// once the first spend has reached the chain.
    ///
    /// What would change this answer is a measurement, not an argument: a
    /// power-cut test on NTFS under each candidate above.
    #[cfg(windows)]
    fn fsync_dir(&mut self, _renamed: Renamed, _dir: &Path) -> Result<()> {
        Ok(())
    }
}

/// The rename's failure, named when Windows reports a held file.
///
/// On Unix every failure is the anonymous `Io` it always was: `rename(2)`
/// is not refused because another process has either file open.
#[cfg(unix)]
fn rename_refusal(e: std::io::Error) -> Error {
    io("rename")(e)
}

/// The rename's failure, named when Windows reports a held file.
///
/// `std`'s Windows `rename` is `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING`,
/// retried once through `FileRenameInfoEx` with POSIX semantics when the first
/// attempt is `ERROR_ACCESS_DENIED`; if the retry also fails, the FIRST error
/// is what comes back. So the codes arriving here are `MoveFileExW`'s, and
/// the two a held source or target produces are the two matched below.
/// `ERROR_SHARING_VIOLATION` has no `ErrorKind` in `std` and would reach the
/// operator as `Uncategorized`, which is the other reason it needs a name.
#[cfg(windows)]
fn rename_refusal(e: std::io::Error) -> Error {
    use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION};
    match e.raw_os_error() {
        Some(code) if code == ERROR_ACCESS_DENIED as i32 || code == ERROR_SHARING_VIOLATION as i32 => {
            Error::ReplaceRefused { code }
        }
        _ => io("rename")(e),
    }
}

/// One recorded primitive call, with the arguments that matter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Call {
    WriteTemp { path: PathBuf, len: usize },
    FsyncFile { path: PathBuf },
    Rename { from: PathBuf, to: PathBuf },
    FsyncDir { dir: PathBuf },
}

/// A recording, optionally interrupting decorator over any medium.
pub struct Instrumented<M: Medium> {
    inner: M,
    calls: Vec<Call>,
    /// `(k, calls.len() when armed)`: the interruption fires on the k-th call
    /// **after arming**, so seeding calls recorded earlier do not shift it.
    stop_after: Option<(usize, usize)>,
}

impl<M: Medium> Instrumented<M> {
    pub fn new(inner: M) -> Self {
        Instrumented {
            inner,
            calls: Vec::new(),
            stop_after: None,
        }
    }

    /// After the `k`-th call (1-based, counted from this arming) performs its
    /// primitive, return an error instead of its result. `None` disarms.
    pub fn stop_after(&mut self, k: Option<usize>) {
        self.stop_after = k.map(|k| (k, self.calls.len()));
    }

    pub fn calls(&self) -> &[Call] {
        &self.calls
    }

    pub fn reset_calls(&mut self) {
        self.calls.clear();
    }

    fn interrupt_here(&self, op: &'static str) -> Result<()> {
        match self.stop_after {
            Some((k, armed_at)) if self.calls.len() == armed_at + k => Err(Error::Io {
                op,
                kind: std::io::ErrorKind::Interrupted,
            }),
            _ => Ok(()),
        }
    }
}

impl<M: Medium> sealed::Sealed for Instrumented<M> {}

impl<M: Medium> Medium for Instrumented<M> {
    fn write_temp(&mut self, dir: &Path, image: &[u8]) -> Result<Written> {
        self.calls.push(Call::WriteTemp {
            path: dir.join(TEMP_NAME),
            len: image.len(),
        });
        let out = self.inner.write_temp(dir, image)?;
        self.interrupt_here("write_temp")?;
        Ok(out)
    }

    fn fsync_file(&mut self, written: Written) -> Result<Synced> {
        self.calls.push(Call::FsyncFile {
            path: written.path.clone(),
        });
        let out = self.inner.fsync_file(written)?;
        self.interrupt_here("fsync_file")?;
        Ok(out)
    }

    fn rename(&mut self, synced: Synced, dir: &Path) -> Result<Renamed> {
        self.calls.push(Call::Rename {
            from: synced.path.clone(),
            to: dir.join(SNAPSHOT_NAME),
        });
        let out = self.inner.rename(synced, dir)?;
        self.interrupt_here("rename")?;
        Ok(out)
    }

    fn fsync_dir(&mut self, renamed: Renamed, dir: &Path) -> Result<()> {
        self.calls.push(Call::FsyncDir {
            dir: dir.to_path_buf(),
        });
        self.inner.fsync_dir(renamed, dir)?;
        self.interrupt_here("fsync_dir")
    }
}

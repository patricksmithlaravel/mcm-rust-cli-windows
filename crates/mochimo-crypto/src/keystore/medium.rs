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
//! # One primitive outside the commit
//!
//! [`Medium::fsync_parent`] flushes the directory that holds the store
//! directory -- where the store directory's own entry lives, which none of
//! the four steps reaches. `Keystore::create` calls it once, before its first
//! commit, and no commit calls it; it takes and returns no token, because it
//! has no place in the commit's order to hold. [`Instrumented`] records it
//! with the parent's path, so a flush aimed at the store directory instead --
//! a wrong path that would leave every count green -- shows in the recorded
//! sequence. The keystore's module doc says what the flush does and does not
//! reach.
//!
//! **On Windows the call is made and flushes nothing**, because there is
//! nothing documented to call. `FlushFileBuffers`' page names a file, whose
//! data and metadata it writes, and a volume, whose handle needs
//! administrative privileges; `CreateFile` opens a directory only as an
//! existing one, under `FILE_FLAG_BACKUP_SEMANTICS`; and the File Caching
//! page's "the file must either be flushed or be opened with
//! `FILE_FLAG_WRITE_THROUGH`" speaks of files. No page says that flushing
//! anything an unprivileged process can open commits a directory's entry in
//! its parent. So the Windows `fsync_parent` returns having done nothing,
//! `Instrumented` still records it with the parent's path -- the sequence
//! keeps Unix's shape, and the call has a place to become real in -- and the
//! gap the Unix flush closes stays open on Windows, stated where the
//! keystore's module doc and the specification state the flush.
//!
//! # The typestate
//!
//! Each step returns a token the next step consumes: `write_temp -> Written`,
//! `fsync_file(Written) -> Synced`, `rename(Synced) -> Renamed`,
//! `fsync_dir(Renamed)`. A reorder is a type error (E0308), not a review
//! finding — `ui/fail/medium_steps_are_not_reorderable.rs` pins it. The
//! tokens have private fields, so they cannot be forged outside the crate.
//!
//! # On Windows the steps are the slot layout's
//!
//! A Windows store is two slot files rewritten in place -- `super::slots` has
//! the frame and the rule by which `open` takes the newer -- because Win32
//! documents no way to commit the directory entry a rename writes. So the
//! trait is a second one, under the same seal, whose steps are the layout's:
//! `write_slot -> SlotWritten`, `flush_slot(SlotWritten) -> Flushed`, and
//! `flush_standing`, which flushes a slot as it stands. The order is again
//! crate-owned, in `Keystore::commit`: the slot holding the newest image is
//! known to be on the device before the other is written, a write is flushed
//! before `Durable` is minted, and a plain image in slot 0 is overwritten only
//! once slot 1 holds a flushed frame.
//! `ui/fail/medium_slot_steps_are_not_reorderable.rs` pins that a flush takes
//! a write's token and nothing else.
//!
//! No step renames or deletes, and the one directory entry a step creates is
//! a slot file's, when a store's first commit, or a migrating store's, writes
//! a slot that is not there yet. The flush after it stores that entry: the
//! `CreateFile` page's section on caching gives a file just created as its
//! example of metadata that may still be cached and `FlushFileBuffers` as how
//! to make sure it reaches the disk, and the File Caching page says the same
//! of all a file's metadata. `sync_all` is that call, read in `std`'s Windows
//! `fs` source. A flush that returned surviving a power cut rests on those
//! pages and on the device honouring the flush it is sent, as an `fsync` on
//! Unix rests on its own; nothing here can measure it.
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
//!
//! On Windows it can also tear a write: after the `k`-th call, a `write_slot`,
//! it leaves the slot holding whatever bytes a `Tear` makes of the slot as
//! it stood and the frame the write was asked for -- or no file, when the
//! write was creating it -- and returns its error. That is what a power cut
//! before the flush can leave of an unflushed write, in any mix of sectors
//! and at either length, and it is how the layout's crash proofs reach it.
//! What a tear cannot model is a flushed write lost, which is the premise the
//! layout rests on and not a case it handles.

use std::fs::{self, File};
use std::io::Write;
#[cfg(windows)]
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use super::perms;
use crate::error::{Error, Result};

pub(crate) const SNAPSHOT_NAME: &str = "accounts.mks";
pub(crate) const TEMP_NAME: &str = "accounts.mks.tmp";
/// Slot 1's file name on Windows; slot 0's is [`SNAPSHOT_NAME`].
#[cfg(windows)]
pub(crate) const SLOT1_NAME: &str = "accounts.mks.1";

mod sealed {
    pub trait Sealed {}
}

/// The temp file has been written in full (not yet flushed).
#[cfg(unix)]
pub struct Written {
    file: File,
    path: PathBuf,
}

/// The temp file's bytes and metadata have reached the device (`sync_all`,
/// not `sync_data`: a new inode's size and block map are metadata, which
/// `fdatasync` may omit).
#[cfg(unix)]
pub struct Synced {
    path: PathBuf,
}

/// The temp has been renamed over the target; the directory entry may still
/// be in an uncommitted journal transaction until `fsync_dir`.
#[cfg(unix)]
pub struct Renamed {
    _private: (),
}

/// The primitives. See the module doc for why the order is not here.
#[cfg(unix)]
pub trait Medium: sealed::Sealed {
    fn write_temp(&mut self, dir: &Path, image: &[u8]) -> Result<Written>;
    fn fsync_file(&mut self, written: Written) -> Result<Synced>;
    fn rename(&mut self, synced: Synced, dir: &Path) -> Result<Renamed>;
    fn fsync_dir(&mut self, renamed: Renamed, dir: &Path) -> Result<()>;
    /// Flush the directory holding `dir`, which is where `dir`'s own entry
    /// lives. Not a commit step; see the module doc.
    fn fsync_parent(&mut self, dir: &Path) -> Result<()>;
}

/// A slot has been written in full at its new length (not yet flushed).
#[cfg(windows)]
pub struct SlotWritten {
    file: File,
    path: PathBuf,
}

/// The slot just written is on the device, its data and its metadata:
/// `FlushFileBuffers`, which writes both and then has the storage flush its
/// own cache.
#[cfg(windows)]
pub struct Flushed {
    _private: (),
}

/// The primitives, on Windows. See the module doc for why the order is not
/// here.
///
/// A slot is named by its number, 0 or 1, and handed over as the handle the
/// keystore holds for it: `None` when no file exists yet, which `write_slot`
/// then creates and leaves in its place.
#[cfg(windows)]
pub trait Medium: sealed::Sealed {
    fn flush_standing(&mut self, dir: &Path, slot: usize, held: &File) -> Result<()>;
    fn write_slot(&mut self, dir: &Path, slot: usize, held: &mut Option<File>, frame: &[u8]) -> Result<SlotWritten>;
    fn flush_slot(&mut self, written: SlotWritten) -> Result<Flushed>;
    /// The Unix `fsync_parent`'s place in `create`, where Windows has nothing
    /// documented to call. Not a commit step; see the module doc.
    fn fsync_parent(&mut self, dir: &Path) -> Result<()>;
}

fn io(op: &'static str) -> impl Fn(std::io::Error) -> Error {
    move |e| Error::Io { op, kind: e.kind() }
}

/// The directory holding `dir`: its parent, `.` for a bare relative name, and
/// `dir` itself for a root, which has no parent to hold its entry.
///
/// `Path::parent` answers `Some("")` for `wallet` and for `wallet/` -- the
/// second is what shell completion types -- and opening the empty path
/// fails, so that answer is read as the working directory it means. Without
/// the mapping, `create --dir wallet` would be refused at its flush.
fn parent_of(dir: &Path) -> &Path {
    match dir.parent() {
        Some(p) if p.as_os_str().is_empty() => Path::new("."),
        Some(p) => p,
        None => dir,
    }
}

/// The real filesystem.
pub struct Disk;

impl sealed::Sealed for Disk {}

#[cfg(unix)]
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
        fs::rename(&synced.path, dir.join(SNAPSHOT_NAME)).map_err(io("rename"))?;
        Ok(Renamed { _private: () })
    }

    fn fsync_dir(&mut self, _renamed: Renamed, dir: &Path) -> Result<()> {
        // On Apple targets std's sync_all is fcntl(F_FULLFSYNC) with no
        // fallback; it was measured succeeding on a directory fd on APFS.
        File::open(dir)
            .map_err(io("fsync_dir open"))?
            .sync_all()
            .map_err(io("fsync_dir"))
    }

    fn fsync_parent(&mut self, dir: &Path) -> Result<()> {
        // The same call as `fsync_dir`, one directory up: `sync_all` on a
        // directory descriptor, `F_FULLFSYNC` on Apple targets.
        File::open(parent_of(dir))
            .map_err(io("fsync_parent open"))?
            .sync_all()
            .map_err(io("fsync_parent"))
    }
}

/// The slot layout's steps, over the files themselves.
///
/// `write_slot` writes the frame from offset 0 and then sets the file's
/// length to the frame's, so a slot is intact only when both the bytes and the
/// length are the new ones; `super::slots` reads a slot of any other length as
/// torn. A slot that does not exist yet is created under the protected list
/// `perms` gives every store file, sharing read access only, like the handles
/// `open` holds.
#[cfg(windows)]
impl Medium for Disk {
    fn flush_standing(&mut self, _dir: &Path, _slot: usize, held: &File) -> Result<()> {
        held.sync_all().map_err(io("flush_standing"))
    }

    fn write_slot(&mut self, dir: &Path, slot: usize, held: &mut Option<File>, frame: &[u8]) -> Result<SlotWritten> {
        let path = slot_path(dir, slot);
        let file = match held {
            Some(file) => file,
            None => held.insert(perms::create_slot(&path).map_err(io("write_slot create"))?),
        };
        overwrite(file, frame).map_err(io("write_slot"))?;
        let file = file.try_clone().map_err(io("write_slot"))?;
        Ok(SlotWritten { file, path })
    }

    fn flush_slot(&mut self, written: SlotWritten) -> Result<Flushed> {
        written.file.sync_all().map_err(io("flush_slot"))?;
        Ok(Flushed { _private: () })
    }

    fn fsync_parent(&mut self, _dir: &Path) -> Result<()> {
        // Nothing to call: no Win32 page documents a flush an unprivileged
        // process can make that commits a directory's entry in its parent.
        // The module doc names the pages read.
        Ok(())
    }
}

/// Slot `slot`'s file in `dir`: 0 is the snapshot's own name.
#[cfg(windows)]
fn slot_path(dir: &Path, slot: usize) -> PathBuf {
    dir.join(if slot == 0 { SNAPSHOT_NAME } else { SLOT1_NAME })
}

/// `bytes` from offset 0, and then the length set to theirs.
#[cfg(windows)]
fn overwrite(file: &mut File, bytes: &[u8]) -> std::io::Result<()> {
    file.seek(SeekFrom::Start(0))?;
    file.write_all(bytes)?;
    file.set_len(bytes.len() as u64)
}

/// One recorded primitive call, with the arguments that matter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Call {
    #[cfg(unix)]
    WriteTemp { path: PathBuf, len: usize },
    #[cfg(unix)]
    FsyncFile { path: PathBuf },
    #[cfg(unix)]
    Rename { from: PathBuf, to: PathBuf },
    #[cfg(unix)]
    FsyncDir { dir: PathBuf },
    #[cfg(windows)]
    FlushStanding { path: PathBuf },
    #[cfg(windows)]
    WriteSlot { path: PathBuf, len: usize },
    #[cfg(windows)]
    FlushSlot { path: PathBuf },
    /// The store directory's parent, as `create` names it to `fsync_parent`:
    /// flushed on Unix, and on Windows recorded with nothing flushed, there
    /// being no documented call to make.
    FsyncParent { dir: PathBuf },
}

/// What a torn `write_slot` leaves: given the slot as it stood (`None` when
/// the write was creating it) and the frame the write was asked for, the
/// bytes the slot holds afterwards, or `None` for no file at all.
#[cfg(windows)]
pub type Tear = Box<dyn FnMut(Option<&[u8]>, &[u8]) -> Option<Vec<u8>>>;

/// A recording, optionally interrupting decorator over any medium.
pub struct Instrumented<M: Medium> {
    inner: M,
    calls: Vec<Call>,
    /// `(k, calls.len() when armed)`: the interruption fires on the k-th call
    /// **after arming**, so seeding calls recorded earlier do not shift it.
    stop_after: Option<(usize, usize)>,
    /// `(k, calls.len() when armed, what the slot is left holding)`, counted
    /// as `stop_after` counts.
    #[cfg(windows)]
    tear: Option<(usize, usize, Tear)>,
}

impl<M: Medium> Instrumented<M> {
    pub fn new(inner: M) -> Self {
        Instrumented {
            inner,
            calls: Vec::new(),
            stop_after: None,
            #[cfg(windows)]
            tear: None,
        }
    }

    /// After the `k`-th call (1-based, counted from this arming) performs its
    /// primitive, return an error instead of its result. `None` disarms.
    pub fn stop_after(&mut self, k: Option<usize>) {
        self.stop_after = k.map(|k| (k, self.calls.len()));
    }

    /// Tear the `k`-th call (1-based, counted from this arming), which must
    /// be a `write_slot`: once it has written, leave the slot holding what
    /// `tear` makes of it, and return an error instead of its result. `None`
    /// disarms.
    #[cfg(windows)]
    pub fn tear_after(&mut self, k: Option<usize>, tear: Tear) {
        self.tear = k.map(|k| (k, self.calls.len(), tear));
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

#[cfg(unix)]
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

    fn fsync_parent(&mut self, dir: &Path) -> Result<()> {
        self.calls.push(Call::FsyncParent {
            dir: parent_of(dir).to_path_buf(),
        });
        self.inner.fsync_parent(dir)?;
        self.interrupt_here("fsync_parent")
    }
}

#[cfg(windows)]
impl<M: Medium> Medium for Instrumented<M> {
    fn flush_standing(&mut self, dir: &Path, slot: usize, held: &File) -> Result<()> {
        self.calls.push(Call::FlushStanding {
            path: slot_path(dir, slot),
        });
        self.inner.flush_standing(dir, slot, held)?;
        self.interrupt_here("flush_standing")
    }

    fn write_slot(&mut self, dir: &Path, slot: usize, held: &mut Option<File>, frame: &[u8]) -> Result<SlotWritten> {
        let path = slot_path(dir, slot);
        self.calls.push(Call::WriteSlot {
            path: path.clone(),
            len: frame.len(),
        });
        let calls = self.calls.len();
        let tear = match &mut self.tear {
            Some((k, armed_at, tear)) if calls == *armed_at + *k => Some(tear),
            _ => None,
        };
        let Some(tear) = tear else {
            let out = self.inner.write_slot(dir, slot, held, frame)?;
            self.interrupt_here("write_slot")?;
            return Ok(out);
        };
        let stood = match held.as_mut() {
            Some(file) => Some(read_all(file).map_err(io("write_slot tear"))?),
            None => None,
        };
        drop(self.inner.write_slot(dir, slot, held, frame)?);
        match tear(stood.as_deref(), frame) {
            Some(bytes) => {
                if let Some(file) = held.as_mut() {
                    overwrite(file, &bytes).map_err(io("write_slot tear"))?;
                }
            }
            None => {
                *held = None;
                fs::remove_file(&path).map_err(io("write_slot tear"))?;
            }
        }
        Err(Error::Io {
            op: "write_slot",
            kind: std::io::ErrorKind::Interrupted,
        })
    }

    fn flush_slot(&mut self, written: SlotWritten) -> Result<Flushed> {
        self.calls.push(Call::FlushSlot {
            path: written.path.clone(),
        });
        let out = self.inner.flush_slot(written)?;
        self.interrupt_here("flush_slot")?;
        Ok(out)
    }

    fn fsync_parent(&mut self, dir: &Path) -> Result<()> {
        self.calls.push(Call::FsyncParent {
            dir: parent_of(dir).to_path_buf(),
        });
        self.inner.fsync_parent(dir)?;
        self.interrupt_here("fsync_parent")
    }
}

/// Every byte of a slot file, from offset 0.
#[cfg(windows)]
fn read_all(file: &mut File) -> std::io::Result<Vec<u8>> {
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::parent_of;
    use std::path::Path;

    /// The directory `create` flushes, for every shape `--dir` arrives in.
    /// The bare name, with or without the slash shell completion adds, is the
    /// case that matters: without its mapping to `.`, `create --dir wallet`
    /// would be refused at the flush.
    #[test]
    fn parent_of_names_the_directory_holding_the_store_in_every_shape() {
        assert_eq!(parent_of(Path::new("wallet")), Path::new("."));
        assert_eq!(parent_of(Path::new("wallet/")), Path::new("."));
        assert_eq!(parent_of(Path::new("./wallet")), Path::new("."));
        assert_eq!(parent_of(Path::new("stores/wallet")), Path::new("stores"));
        assert_eq!(parent_of(Path::new("/home/op/wallet")), Path::new("/home/op"));
        assert_eq!(parent_of(Path::new("/")), Path::new("/"));
    }
}

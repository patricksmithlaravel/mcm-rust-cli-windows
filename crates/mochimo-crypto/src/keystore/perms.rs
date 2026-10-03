//! The Unix permission model, in one module.
//!
//! Every mode bit this crate sets or reads is here: the `0600` the lock file
//! and the temp snapshot are created with, the `0700` the store directory is
//! created with when this crate creates it, the group- and other-writable
//! bits whose presence on that directory is a refusal rather than a warning,
//! and the owner that directory must have.
//!
//! # Why they are in one place
//!
//! `lib.rs`'s platform statement names three interfaces this crate cannot do
//! without, and the first of them is this one: the store is created `0600` and
//! its directory `0700`, and a store whose directory is group- or
//! world-writable, or owned by another user, is refused, which is a check
//! against another local user rather than a convenience.
//!
//! That sentence is a claim about the whole crate. While the sites it
//! describes were spread across `keystore/mod.rs` and `keystore/medium.rs` --
//! six of them, behind three separate `std::os::unix::fs` imports -- it was
//! prose checked against nothing: a mode loosened at one of the six, or a
//! seventh site added beside them, and the statement went on reading exactly
//! the same. Concentrated, the claim has one module to be read against and one
//! module to be wrong in. [`super::Directory`] opens every file and directory
//! the store uses on Unix, and every mode it passes is a constant from here.
//!
//! This is [`crate::cli::destination`]'s argument about a tag aimed at a
//! permission instead of a string: four separate call sites of the formatter
//! would be four chances to print a form no other wallet takes, and six
//! separate call sites of a mode are six chances to create a file this
//! crate's own platform statement does not describe.
//!
//! # Two arms, one standard
//!
//! The items below are the Unix arm: the two modes `super::Directory` creates
//! with, the bits it refuses, and `refuse_unsafe_dir`, which it asks of the
//! directory it has opened. The Windows arm is [`windows`], a file of its own.
//! It shares one name with this arm, `refuse_unsafe_dir`, and not its
//! signature: here the check is asked of an opened directory, there of a
//! path, because a Windows store is still opened by path. That arm also
//! creates the directory and opens the lock itself -- `create_private_dir`
//! and `open_private_lock` -- where on Unix `super::Directory` does both
//! relative to the handle it holds; and it has `create_slot` and `open_slot`,
//! the slot layout's two files, and `refuse_unsafe_file`, which reads a store
//! file's own list. So `keystore` chooses between the arms at its call sites,
//! under `cfg`, and only Windows code calls those five. **There is no
//! trait**, because nothing ever chooses between the arms at run time -- a
//! build has exactly one, and a trait would be an interface with one
//! implementation per binary.
//!
//! The Windows arm is a separate file rather than a second block in this one
//! so that this file stays the Unix arm and nothing else. The Unix arm is
//! what the command-line wallet upstream of this tree ships, and a change
//! there merges into this file without meeting the Windows code.
//!
//! What the arms share is the standard, not the mechanism: each makes a
//! directory and files only its owner can reach, and each refuses a
//! directory another local user owns or can write to. The Windows arm also
//! refuses a store file another local user can read or write, because there
//! a file's own list, and not its directory's, decides who reaches it; on
//! Unix a `0700` directory keeps other users from every file inside it. How
//! far the second arm is established is stated at its head: its tests pass
//! on a Windows runner, and what that runner is not -- an unelevated desktop
//! with a scanner running -- it does not establish.
//!
//! # The shape of the public error, stated because it is not obvious
//!
//! [`Error::UnsafePermissions`] carries `mode: u32` -- a Unix mode, in this
//! crate's public error type, rendered as octal by its `Display`. The
//! refusal is therefore not merely *implemented* in terms of mode bits; it
//! *reports* in them, and a caller that matches on the variant reads an octal
//! number out of it.
//!
//! That is the right shape for a crate whose platform statement is the one
//! above, and it is written down here rather than left in `error.rs` to be
//! inferred, because it is the part of the permission model that is visible
//! from outside the crate and the only part a dependent can come to depend on.

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub(crate) use windows::{
    create_private_dir, create_slot, open_private_lock, open_slot, refuse_unsafe_dir, refuse_unsafe_file,
};

#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

#[cfg(unix)]
use crate::error::{Error, Result};

/// The mode every file this crate creates is created with: owner read and
/// write, nothing for anyone else.
///
/// Both files it names are covered. The snapshot's temp holds a plaintext
/// header over a sealed body, so a partial one leaks KDF parameters rather
/// than a root; the lock file holds no bytes at all. Neither is key material
/// and both are still nobody else's, which is the same standard the directory
/// check below applies and the reason one constant serves both.
#[cfg(unix)]
pub(crate) const FILE_MODE: rustix::fs::Mode = rustix::fs::Mode::from_bits_retain(0o600);

/// The mode the store directory is created with **when this crate creates
/// it**: owner only, no group and no other.
///
/// A directory this crate did not create keeps whatever mode it has, and is
/// then held to [`refuse_unsafe_dir`] instead. The two are not the same
/// standard and deliberately so: this is what we make, that is what we accept.
#[cfg(unix)]
pub(crate) const DIR_MODE: rustix::fs::Mode = rustix::fs::Mode::from_bits_retain(0o700);

/// The bits whose presence on the store directory is a refusal: group-write
/// (`0o020`) and other-write (`0o002`).
///
/// **Write, and not read.** A group- or world-*readable* directory discloses
/// that a store exists and what its files are called, which is metadata; a
/// group- or world-*writable* one lets another local user rename the snapshot
/// out from under a live handle, which defeats the commit's atomicity
/// directly. The check is aimed at the second and says nothing about the
/// first, and widening it to `0o077` would refuse the mode a great many
/// home directories already carry for a property this crate does not rest on.
#[cfg(unix)]
const REFUSED_WRITE_BITS: u32 = 0o022;

/// Refuse a store directory another local user could write to.
///
/// Asked by both [`crate::keystore::Keystore::create_with`] and
/// [`crate::keystore::Keystore::open_with`], through [`super::Directory`],
/// before either takes the lock. It is asked of the opened directory and
/// never of a path, so the directory checked is the directory every later
/// operation uses.
///
/// A path that is not a directory is refused as `NotADirectory` under the
/// same `op` as the stat that found it, rather than as a permission problem:
/// the caller named something that cannot hold a store, which is a different
/// mistake from naming a directory that should not.
///
/// **The owner is checked before the mode**, because the mode of a directory
/// someone else owns is theirs to change at any moment: on such a directory
/// the mode check describes the present and promises nothing about the next
/// commit.
#[cfg(unix)]
pub(crate) fn refuse_unsafe_dir(dir: &File) -> Result<()> {
    let meta = dir.metadata().map_err(|e| Error::Io { op: "stat directory", kind: e.kind() })?;
    if !meta.is_dir() {
        return Err(Error::Io { op: "stat directory", kind: std::io::ErrorKind::NotADirectory });
    }
    if meta.uid() != rustix::process::geteuid().as_raw() {
        return Err(Error::Io { op: "directory owner", kind: std::io::ErrorKind::PermissionDenied });
    }
    let mode = meta.mode() & 0o777;
    if mode & REFUSED_WRITE_BITS != 0 {
        return Err(Error::UnsafePermissions { mode });
    }
    Ok(())
}

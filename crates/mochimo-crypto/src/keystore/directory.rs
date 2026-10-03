//! A verified Unix store directory held open for every store operation.
//!
//! Paths are retained for diagnostics only. Locking, snapshot reads, temp
//! writes, replacement and flushes all use the same directory handle, even
//! if an ancestor is renamed while a store is open.
//!
//! # Why the store directory may not be a symbolic link
//!
//! The owner and mode checks are asked of the directory the path reaches,
//! and a link there would pass them whenever it points at any directory the
//! operator owns. With a link refused as the path's last component, whoever
//! can write the directory the store is named in can make that name only a
//! directory of their own, which the owner check refuses, or one already
//! beside it -- never a pointer to another of the operator's directories,
//! such as an older copy of the store. Components above the last one keep
//! their filesystem meaning: they are the operator's layout, and what this
//! module guards is the store's own name. The refusal is
//! [`Error::StoreDirectoryIsLink`], so the operator reads that the path was a
//! link and passes the directory it points to.

use std::ffi::OsStr;
use std::fs::File;
use std::path::{Component, Path, PathBuf};

use rustix::fs::{self, AtFlags, Mode, OFlags};

use super::perms;
use crate::error::{Error, Result};

/// The directory identity used by the Unix storage primitives.
///
/// Only the keystore can construct one. A path is never a substitute for
/// this handle after the store's permissions have been checked.
pub struct Directory {
    file: File,
    parent: Option<File>,
    path: PathBuf,
    parent_path: PathBuf,
}

fn io(op: &'static str) -> impl Fn(std::io::Error) -> Error {
    move |e| Error::Io { op, kind: e.kind() }
}

/// What a failed no-follow open of the store directory reports.
///
/// A link there fails as `ELOOP` on one platform and `ENOTDIR` on another,
/// and neither names the cause, so the entry itself is looked at once more.
/// The look only chooses the error: the open has already refused, and a link
/// that appears or vanishes between the two calls changes the wording of a
/// refusal and never what is opened.
fn refused_open(e: rustix::io::Errno, entry: &Path) -> Error {
    match std::fs::symlink_metadata(entry) {
        Ok(meta) if meta.file_type().is_symlink() => Error::StoreDirectoryIsLink,
        _ => io("stat directory")(e.into()),
    }
}

impl Directory {
    pub(crate) fn open(path: &Path, create: bool) -> Result<Self> {
        if path.as_os_str().is_empty() {
            return Err(Error::Io { op: "stat directory", kind: std::io::ErrorKind::NotFound });
        }
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
        if !create {
            // Normalize trailing separators and dots so NOFOLLOW checks the
            // store itself. Parent components keep their filesystem meaning.
            let normalized: PathBuf = path.components().collect();
            let file = File::from(fs::open(&normalized, flags | OFlags::NOFOLLOW, Mode::empty())
                .map_err(|e| refused_open(e, &normalized))?);
            perms::refuse_unsafe_dir(&file)?;
            return Ok(Self {
                file,
                parent: None,
                path: path.to_path_buf(),
                parent_path: super::medium::parent_of(path).to_path_buf(),
            });
        }
        let mut parent_path = super::medium::parent_of(path).to_path_buf();
        let leaf = match path.components().next_back() {
            Some(Component::Normal(name)) => name,
            Some(Component::ParentDir) => OsStr::new(".."),
            _ => OsStr::new("."),
        };
        let parent = File::from(fs::open(&parent_path, flags, Mode::empty())
            .map_err(std::io::Error::from).map_err(io("open parent directory"))?);
        match fs::mkdirat(&parent, leaf, perms::DIR_MODE) {
            Ok(()) | Err(rustix::io::Errno::EXIST) => {}
            Err(e) => return Err(io("create directory")(e.into())),
        }
        let file = File::from(fs::openat(&parent, leaf, flags | OFlags::NOFOLLOW, Mode::empty())
            .map_err(|e| refused_open(e, &parent_path.join(leaf)))?);
        perms::refuse_unsafe_dir(&file)?;
        // For `.` and `..`, the lexical parent opened above was only a
        // lookup anchor. Flush the actual parent of the verified directory.
        let parent = if matches!(path.components().next_back(), Some(Component::Normal(_))) {
            parent
        } else {
            parent_path = path.join("..");
            File::from(fs::openat(&file, "..", flags, Mode::empty())
                .map_err(std::io::Error::from).map_err(io("open parent directory"))?)
        };
        Ok(Self { file, parent: Some(parent), path: path.to_path_buf(), parent_path })
    }

    pub(crate) fn path(&self) -> &Path { &self.path }

    pub(crate) fn parent_path(&self) -> &Path { &self.parent_path }

    pub(crate) fn exists(&self, name: &str) -> std::io::Result<bool> {
        match fs::statat(&self.file, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => Ok(true),
            Err(rustix::io::Errno::NOENT) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// Open an entry of the store without following a link, and refuse
    /// anything that is not a regular file. `NONBLOCK` is what makes that
    /// refusal reachable for a FIFO planted under a store name: without it
    /// the open waits for a writer and the check after it never runs.
    fn open_file(&self, name: &str, flags: OFlags) -> std::io::Result<File> {
        let file = File::from(fs::openat(
            &self.file, name,
            flags | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            perms::FILE_MODE,
        )?);
        if !file.metadata()?.is_file() {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "store entry is not a regular file"));
        }
        Ok(file)
    }

    /// Open the lock file at [`perms::FILE_MODE`], creating it if absent and
    /// **never** truncating it.
    ///
    /// Read and write are both asked for because the caller locks the
    /// descriptor afterwards; truncation is refused because the file is a
    /// lock and not a store, and truncating here would rewrite a file another
    /// process may hold at exactly the moment this one is finding out whether
    /// it does.
    pub(crate) fn open_lock(&self, name: &str) -> std::io::Result<File> {
        self.open_file(name, OFlags::RDWR | OFlags::CREATE)
    }

    pub(crate) fn open_snapshot(&self, name: &str) -> std::io::Result<File> {
        self.open_file(name, OFlags::RDONLY)
    }

    /// Create a file at [`perms::FILE_MODE`], failing if it already exists.
    ///
    /// Exclusive, so a leftover cannot be opened in place: a mode passed to
    /// `open` applies only when the file is created, and a truncated leftover
    /// carries its own permissions through to whatever is written into it.
    /// The caller that needs the leftover gone unlinks it first.
    pub(crate) fn create_temp(&self, name: &str) -> std::io::Result<File> {
        self.open_file(name, OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL)
    }

    pub(crate) fn remove_temp(&self, name: &str) -> std::io::Result<()> {
        match fs::unlinkat(&self.file, name, AtFlags::empty()) {
            Ok(()) | Err(rustix::io::Errno::NOENT) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    pub(crate) fn replace(&self, from: &str, to: &str) -> std::io::Result<()> {
        fs::renameat(&self.file, from, &self.file, to).map_err(Into::into)
    }

    pub(crate) fn sync_all(&self) -> std::io::Result<()> { self.file.sync_all() }

    pub(crate) fn sync_parent(&self) -> std::io::Result<()> {
        match self.parent.as_ref() {
            Some(parent) => parent.sync_all(),
            None => Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "parent flush requires a creation handle")),
        }
    }
}

#[cfg(all(test, not(miri)))]
mod tests {
    use super::*;

    #[test]
    fn dot_components_hold_the_actual_parent_for_durability() {
        let root = std::env::temp_dir().join(format!("store-parent-{}", std::process::id()));
        let store = root.join("store");
        std::fs::create_dir_all(store.join("child")).unwrap();
        let expected = File::open(&root).unwrap();
        let expected = fs::fstat(&expected).unwrap();
        for path in [store.clone(), store.join("."), store.join("child/..")] {
            let dir = Directory::open(&path, true).unwrap();
            let actual = fs::fstat(dir.parent.as_ref().unwrap()).unwrap();
            assert_eq!((actual.st_dev, actual.st_ino), (expected.st_dev, expected.st_ino));
            dir.sync_parent().unwrap();
            let opened = Directory::open(&path, false).unwrap();
            assert!(opened.parent.is_none());
            assert_eq!(opened.sync_parent().err().map(|e| e.kind()), Some(std::io::ErrorKind::InvalidInput));
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}

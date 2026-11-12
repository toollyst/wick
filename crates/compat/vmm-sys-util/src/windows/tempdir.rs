// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: BSD-3-Clause

//! `tempdir` for Windows: same API as the Unix module; the directory is
//! created with a random suffix, which `create_dir` makes atomic, like
//! `mkdtemp`.

use std::env::temp_dir;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::errno::{Error, Result};

/// The random suffix [`TempDir::new_with_prefix`] appends.
const SUFFIX: usize = 6;

/// The longest directory path CreateDirectoryW takes without the `\\?\`
/// prefix: MAX_PATH less 12, room for an 8.3 name (CreateDirectoryW's
/// documentation).
const PLAIN_DIR_MAX: usize = 260 - 12;

/// `path`, as `canonicalize` gives it (the verbatim form, `\\?\C:\...`),
/// as the plain `C:\...` where that names the same directory: Linux's
/// canonical path is a plain one, which a name joined with '/' extends.
/// In a `\\?\` path the Win32 file functions leave '/' as it is ("Naming
/// Files, Paths, and Namespaces"), so "dir/name" there is one name with a
/// '/' in it: an AF_UNIX bind of it fails with ERROR_INVALID_PARAMETER and
/// the plain form's binds (libc's test_unix_bind_of_each_path_form_on_record,
/// CI run 43298293407), which is how vmm's create_tmp_socket failed.
///
/// The verbatim form is kept where the plain one would be parsed into
/// another path (same page): a name ending in '.' or ' ' (Win32 strips
/// them), a DOS device name with or without an extension (CON, NUL, COM1,
/// ...: the device), a UNC or device path, a name that is not Unicode, or
/// a directory too long without the prefix ([`PLAIN_DIR_MAX`]).
fn plain(path: PathBuf) -> PathBuf {
    use std::os::windows::ffi::OsStrExt;
    use std::path::{Component, Prefix};

    let mut components = path.components();
    let Some(Component::Prefix(prefix)) = components.next() else {
        return path;
    };
    let Prefix::VerbatimDisk(drive) = prefix.kind() else {
        return path;
    };
    let mut out = std::ffi::OsString::from(format!("{}:\\", char::from(drive)));
    let mut first = true;
    for c in components {
        match c {
            Component::RootDir => {}
            Component::Normal(name) => {
                match name.to_str() {
                    Some(s) if win32_keeps(s) => {}
                    _ => return path,
                }
                if !first {
                    out.push("\\");
                }
                out.push(name);
                first = false;
            }
            _ => return path,
        }
    }
    // The directory made in it: this, a separator and the suffix.
    if out.encode_wide().count() + 1 + SUFFIX >= PLAIN_DIR_MAX {
        return path;
    }
    PathBuf::from(out)
}

/// Whether Win32 takes `name`, in a plain path, as the same name.
fn win32_keeps(name: &str) -> bool {
    if name.is_empty() || name.ends_with('.') || name.ends_with(' ') || name.contains('/') {
        return false;
    }
    let stem = name.split('.').next().unwrap_or(name).trim_end_matches(' ').to_ascii_uppercase();
    let numbered = (stem.starts_with("COM") || stem.starts_with("LPT"))
        && stem.chars().count() == 4
        && matches!(stem.chars().nth(3), Some('0'..='9' | '\u{b9}' | '\u{b2}' | '\u{b3}'));
    let device = numbered || matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$");
    !device
}

/// Wrapper over a temporary directory, removed with its contents on drop.
#[derive(Debug)]
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Creates a new directory whose path starts with `prefix`.
    pub fn new_with_prefix<P: AsRef<OsStr>>(prefix: P) -> Result<TempDir> {
        for _ in 0..64 {
            let mut name = prefix.as_ref().to_os_string();
            name.push(crate::rand::rand_alphanumerics(6));
            let path = PathBuf::from(name);
            match fs::create_dir(&path) {
                Ok(()) => return Ok(TempDir { path }),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(Error::from(e)),
            }
        }
        Err(Error::from(io::Error::from(io::ErrorKind::AlreadyExists)))
    }

    /// Creates a new directory in `path`, canonicalized as upstream does,
    /// in its plain form where it has one ([`plain`]).
    pub fn new_in(path: &Path) -> Result<TempDir> {
        let mut path_buf = plain(path.canonicalize().map_err(Error::from)?);
        path_buf.push("");
        TempDir::new_with_prefix(path_buf)
    }

    /// Creates a new directory in the system's temporary directory.
    pub fn new() -> Result<TempDir> {
        TempDir::new_in(&temp_dir())
    }

    /// Removes the directory and its contents.
    pub fn remove(&self) -> Result<()> {
        fs::remove_dir_all(&self.path).map_err(Error::from)
    }

    /// The path of the directory.
    pub fn as_path(&self) -> &Path {
        self.path.as_ref()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = self.remove();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_remove() {
        let t = TempDir::new().unwrap();
        let path = t.as_path().to_owned();
        assert!(path.is_dir());
        fs::write(path.join("f"), b"x").unwrap();
        let inner = TempDir::new_in(&path).unwrap();
        assert!(inner.as_path().starts_with(plain(path.canonicalize().unwrap())));
        drop(inner);
        drop(t);
        assert!(!path.exists());
    }

    // vmm's create_tmp_socket: the directory's path as a string, "/" and a
    // name. As on Linux, that names a file in the directory.
    #[test]
    fn test_a_name_joined_with_a_slash_is_in_the_directory() {
        let t = TempDir::new().unwrap();
        let s = t.as_path().to_str().unwrap().to_owned();
        assert!(!s.starts_with(r"\\?\"), "{s}");
        fs::write(format!("{s}/tmp_socket"), b"x").unwrap();
        assert_eq!(fs::read(t.as_path().join("tmp_socket")).unwrap(), b"x");
    }

    #[test]
    fn test_plain_only_where_it_names_the_same_path() {
        let p = |s: &str| plain(PathBuf::from(s));
        assert_eq!(p(r"\\?\C:\Users\a\Temp"), PathBuf::from(r"C:\Users\a\Temp"));
        assert_eq!(p(r"\\?\D:\"), PathBuf::from(r"D:\"));
        // Win32 would parse the plain form into another path.
        for kept in [
            r"\\?\C:\a\b.",
            r"\\?\C:\a\b ",
            r"\\?\C:\a\CON",
            r"\\?\C:\a\nul.txt",
            r"\\?\C:\a\Com1",
            "\\\\?\\C:\\a\\LPT\u{b9}.log",
            r"\\?\C:\a\..",
            r"\\?\UNC\server\share\a",
            r"\\.\C:\a",
            r"C:\a",
        ] {
            assert_eq!(p(kept), PathBuf::from(kept), "{kept}");
        }
        // Names that only look like devices are names.
        assert_eq!(p(r"\\?\C:\a\console"), PathBuf::from(r"C:\a\console"));
        assert_eq!(p(r"\\?\C:\a\COM10"), PathBuf::from(r"C:\a\COM10"));
        // Too long for a directory without the prefix.
        let long = format!(r"\\?\C:\{}", "a".repeat(PLAIN_DIR_MAX));
        assert_eq!(p(&long), PathBuf::from(&long));
        // The longest that fits: "C:\", the name, a separator and the
        // suffix, shorter than PLAIN_DIR_MAX.
        let n = PLAIN_DIR_MAX - 1 - r"C:\".len() - 1 - SUFFIX;
        let fits = format!(r"\\?\C:\{}", "a".repeat(n));
        assert_eq!(p(&fits), PathBuf::from(&fits[4..]));
    }
}

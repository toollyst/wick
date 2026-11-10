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

    /// Creates a new directory in `path`.
    pub fn new_in(path: &Path) -> Result<TempDir> {
        let mut path_buf = path.canonicalize().map_err(Error::from)?;
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
        assert!(inner.as_path().starts_with(path.canonicalize().unwrap()));
        drop(inner);
        drop(t);
        assert!(!path.exists());
    }
}

// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! Stage 0's checks of a share (docs/design-fs.md §4.2, §6.1, §6.2), made
//! with the operator's rights before any guest byte is read. Each failure is
//! a [`Refusal`] that names what is wrong; there is no switch that skips a
//! check.
//!
//! In order:
//! 1. the directory's canonical path (macOS: EPERM there is TCC, and the
//!    message says so);
//! 2. not a refused root ([`refused_root`]);
//! 3. opened as a directory, the same object the path named;
//! 4. not a volume's root (a mount point), and on a local file system;
//! 5. read-write: the file system stores extended attributes itself (the
//!    metadata record lives in one); a read-only share is served without;
//! 6. `RLIMIT_NOFILE` raised to the most descriptors the limits let the
//!    server hold ([`descriptors`]), read back, or refused if the hard limit
//!    is below it (macOS: or `kern.maxfilesperproc`, which xnu enforces when
//!    it is lower);
//! 7. [`HostDir::new`]: beneath-resolution present, and names not folded by
//!    case unless the operator allowed it.

use std::os::fd::AsFd;
use std::path::{Component, Path, PathBuf};

use wick_fs_sys as sys;

use crate::host::unix::{HostDir, Options, RECORD_XATTR, Refusal};
use crate::limits::{Limits, SPARE_FDS, descriptors};

/// What bounds the server's descriptors, as a refusal names it.
#[cfg(target_os = "linux")]
const LIMIT: &str = "hard RLIMIT_NOFILE";
#[cfg(target_os = "macos")]
const LIMIT: &str = "descriptor limit (the lower of the hard RLIMIT_NOFILE and kern.maxfilesperproc)";

/// One share as the operator gives it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Share {
    /// The host directory.
    pub dir: PathBuf,
    /// Every change refused (EROFS).
    pub read_only: bool,
    /// Serve a volume that folds case (docs/design-fs.md §7).
    pub case_insensitive_ok: bool,
    /// The share's limits.
    pub limits: Limits,
}

/// Directories a share may never be, nor be beneath: the system's own and
/// where credentials and start-up files live. Host tools read what a guest
/// writes there (design-fs decision 8).
#[cfg(target_os = "linux")]
const SYSTEM_TREES: &[&str] = &[
    "/bin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64", "/libx32", "/proc", "/root", "/run", "/sbin",
    "/sys", "/usr", "/var/lib", "/var/log", "/var/run",
];
/// Directories a share may never be, nor be beneath: the system's own and
/// where credentials and start-up files live. Host tools read what a guest
/// writes there (design-fs decision 8).
#[cfg(target_os = "macos")]
const SYSTEM_TREES: &[&str] = &[
    "/Applications",
    "/Library",
    "/System",
    "/bin",
    "/cores",
    "/dev",
    "/etc",
    "/private/etc",
    "/private/var/db",
    "/private/var/root",
    "/sbin",
    "/usr/bin",
    "/usr/lib",
    "/usr/libexec",
    "/usr/sbin",
    "/usr/share",
];

/// Directories a share may not be, though a directory beneath one may.
#[cfg(target_os = "linux")]
const HOLDERS: &[&str] = &["/", "/home", "/var", "/tmp", "/mnt", "/media", "/srv", "/opt"];
/// Directories a share may not be, though a directory beneath one may.
#[cfg(target_os = "macos")]
const HOLDERS: &[&str] = &[
    "/",
    "/Users",
    "/Volumes",
    "/private",
    "/private/tmp",
    "/private/var",
    "/private/var/folders",
    "/usr",
    "/usr/local",
    "/opt",
];

/// Why `path` (canonical) may not be a share, if it may not: one of the
/// system trees or holders above, the home directory `home` itself, a
/// directory beneath it whose first component starts with `.` (`~/.ssh`,
/// `~/.config`, ...), or (macOS) beneath `~/Library`.
pub fn refused_root(path: &Path, home: Option<&Path>) -> Option<String> {
    if SYSTEM_TREES.iter().any(|t| path.starts_with(t)) {
        return Some(format!("{} is a system location", path.display()));
    }
    if HOLDERS.iter().any(|h| path == Path::new(h)) {
        return Some(format!("{} holds other users' or the system's files; share a directory beneath it", path.display()));
    }
    if let Some(home) = home {
        if path == home {
            return Some(format!("{} is the home directory; share a directory beneath it", path.display()));
        }
        if let Ok(rest) = path.strip_prefix(home) {
            let first = rest.components().next();
            if let Some(Component::Normal(c)) = first {
                let c = c.to_string_lossy();
                if c.starts_with('.') || (cfg!(target_os = "macos") && c == "Library") {
                    return Some(format!(
                        "{} is where the home directory's settings and credentials live",
                        path.display()
                    ));
                }
            }
        }
    }
    None
}

/// File systems that are not served: their identities and attributes are
/// another machine's. Linux `statfs` magics, macOS type names.
#[cfg(target_os = "linux")]
const REMOTE: &[(&str, &str)] = &[
    ("0x6969", "NFS"),
    ("0xff534d42", "CIFS"),
    ("0xfe534d42", "SMB2"),
    ("0x517b", "SMB"),
    ("0x65735546", "FUSE"),
    ("0x564c", "NCP"),
    ("0x7461636f", "OCFS2"),
    ("0x47504653", "GPFS"),
];
/// File systems that are not served: their identities and attributes are
/// another machine's. Linux `statfs` magics, macOS type names.
#[cfg(target_os = "macos")]
const REMOTE: &[(&str, &str)] = &[
    ("nfs", "NFS"),
    ("smbfs", "SMB"),
    ("afpfs", "AFP"),
    ("webdav", "WebDAV"),
    ("macfuse", "macFUSE"),
    ("osxfuse", "macFUSE"),
    ("fskit", "FSKit"),
];

/// Runs the checks and opens the share.
pub fn open(share: &Share, home: Option<&Path>) -> Result<HostDir, Refusal> {
    let shown = share.dir.display();
    let canonical = std::fs::canonicalize(&share.dir).map_err(|e| {
        if cfg!(target_os = "macos") && e.kind() == std::io::ErrorKind::PermissionDenied {
            Refusal(format!(
                "{shown}: permission denied. On macOS this is TCC (Privacy & Security): a share under Documents, \
                 Desktop, Downloads, iCloud or a removable volume needs the permission of the app that starts \
                 wick-fsd"
            ))
        } else {
            Refusal(format!("{shown}: {e}"))
        }
    })?;
    if let Some(why) = refused_root(&canonical, home) {
        return Err(Refusal(format!("refused share root: {why}")));
    }
    let root = sys::open_root(&canonical).map_err(|e| Refusal(format!("{}: {e:?}", canonical.display())))?;
    let st = sys::fstat(root.as_fd()).map_err(|e| Refusal(format!("{}: {e:?}", canonical.display())))?;
    let named = std::fs::symlink_metadata(&canonical).map_err(|e| Refusal(format!("{}: {e}", canonical.display())))?;
    {
        use std::os::unix::fs::MetadataExt;
        if (named.dev(), named.ino()) != (st.dev, st.ino) {
            return Err(Refusal(format!("{} changed while it was opened", canonical.display())));
        }
    }
    if let Some(parent) = canonical.parent() {
        use std::os::unix::fs::MetadataExt;
        let p = std::fs::metadata(parent).map_err(|e| Refusal(format!("{}: {e}", parent.display())))?;
        if p.dev() != st.dev {
            return Err(Refusal(format!(
                "{} is the root of a volume (a mount point); share a directory on it",
                canonical.display()
            )));
        }
    }
    let ty = sys::fs_type(root.as_fd()).map_err(|e| Refusal(format!("{}: {e:?}", canonical.display())))?;
    if let Some((_, name)) = REMOTE.iter().find(|(t, _)| *t == ty) {
        return Err(Refusal(format!("{} is on {name}, not a local file system", canonical.display())));
    }
    if !share.read_only {
        let native = sys::xattr_native(root.as_fd(), RECORD_XATTR)
            .map_err(|e| Refusal(format!("{}: {e:?}", canonical.display())))?;
        if !native {
            return Err(Refusal(format!(
                "{} is on a file system without extended attributes ({ty}), where the metadata record \
                 (docs/design-fs.md §4.5) cannot be kept; serve it read-only",
                canonical.display()
            )));
        }
    }
    let need = descriptors(&share.limits);
    let (soft, hard) = sys::nofile().map_err(|e| Refusal(format!("RLIMIT_NOFILE: {e:?}")))?;
    if soft < need {
        if hard < need {
            return Err(Refusal(format!(
                "the {LIMIT} ({hard}) is below the {need} descriptors this share's limits may hold open \
                 (nodes + handles + {SPARE_FDS}); raise it, or lower the limits"
            )));
        }
        sys::set_nofile(need).map_err(|e| Refusal(format!("RLIMIT_NOFILE to {need}: {e:?}")))?;
        // What the kernel enforces now, read back, never assumed.
        let (now, _) = sys::nofile().map_err(|e| Refusal(format!("RLIMIT_NOFILE: {e:?}")))?;
        if now < need {
            return Err(Refusal(format!(
                "the {LIMIT} is {now} after raising it to {need}, below what this share's limits may hold open"
            )));
        }
    }
    HostDir::new(
        root,
        Options {
            case_insensitive_ok: share.case_insensitive_ok,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_refused_share_roots() {
        let home = Path::new(if cfg!(target_os = "macos") { "/Users/u" } else { "/home/u" });
        let refused: &[&str] = if cfg!(target_os = "macos") {
            &[
                "/",
                "/Users",
                "/Users/u",
                "/Users/u/.ssh",
                "/Users/u/.config/x",
                "/Users/u/Library",
                "/Users/u/Library/Keychains",
                "/System",
                "/System/Library",
                "/private/etc",
                "/private/var",
                "/Library/Preferences",
                "/usr/bin",
                "/Applications/Safari.app",
                "/Volumes",
                "/private/tmp",
            ]
        } else {
            &[
                "/",
                "/home",
                "/home/u",
                "/home/u/.ssh",
                "/home/u/.config/x",
                "/etc",
                "/etc/ssh",
                "/usr",
                "/usr/lib/x",
                "/var",
                "/var/lib/docker",
                "/proc/1",
                "/sys/fs",
                "/dev/shm",
                "/boot",
                "/root/x",
                "/tmp",
            ]
        };
        for r in refused {
            assert!(refused_root(Path::new(r), Some(home)).is_some(), "{r} should be refused");
        }
        let served: &[&str] = if cfg!(target_os = "macos") {
            &["/Users/u/src", "/Users/u/src/.git", "/private/tmp/x", "/Volumes/Data/x", "/opt/x", "/usr/local/x"]
        } else {
            &["/home/u/src", "/home/u/src/.git", "/tmp/x", "/srv/data", "/mnt/disk/x", "/var/tmp/x", "/opt/x"]
        };
        for s in served {
            assert_eq!(refused_root(Path::new(s), Some(home)), None, "{s}");
        }
    }
}

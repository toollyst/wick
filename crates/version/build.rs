// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! Reads the release version from the wick repository: the upstream release in
//! `patches/base` (`v1.18.0`) and wick's number in `patches/version` (`1`)
//! make `1.18.0-wick.1`. Writes it to `$OUT_DIR/version.rs` for `src/lib.rs`.
//! A missing or malformed file fails the build; there is no fallback.

use std::path::{Path, PathBuf};

fn read(path: &Path) -> String {
    println!("cargo:rerun-if-changed={}", path.display());
    match std::fs::read_to_string(path) {
        Ok(s) => s.trim().to_string(),
        Err(err) => panic!("wick-version: cannot read {}: {err}", path.display()),
    }
}

/// A semver numeric identifier: digits, no leading zero.
fn is_numeric(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && (s == "0" || !s.starts_with('0'))
}

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let patches = manifest_dir.join("../../patches");
    let base_file = patches.join("base");
    let number_file = patches.join("version");

    let base = read(&base_file);
    let upstream = base
        .strip_prefix('v')
        .filter(|v| v.split('.').count() == 3 && v.split('.').all(is_numeric))
        .unwrap_or_else(|| {
            panic!(
                "wick-version: {} must name an upstream release tag like v1.18.0, not '{base}'",
                base_file.display()
            )
        });

    let number = read(&number_file);
    assert!(
        is_numeric(&number) && number != "0",
        "wick-version: {} must hold wick's release number (1, 2, ...), not '{number}'",
        number_file.display()
    );

    let version = format!("{upstream}-wick.{number}");
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("version.rs");
    let code = format!(
        "/// The full version, `<upstream>-wick.<N>`, as a string literal.\n\
         #[macro_export]\n\
         macro_rules! version {{\n    () => {{\n        {version:?}\n    }};\n}}\n\
         /// The upstream Firecracker release wick is built on.\n\
         pub const UPSTREAM: &str = {upstream:?};\n\
         /// wick's release number on top of [`UPSTREAM`].\n\
         pub const NUMBER: u32 = {number};\n"
    );
    std::fs::write(&out, code)
        .unwrap_or_else(|err| panic!("wick-version: cannot write {}: {err}", out.display()));
}

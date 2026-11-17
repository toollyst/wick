// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! Stage 1's confinement, per host (docs/design-fs.md §6). Linux's is here;
//! macOS's comes with its own commit, and until then wick-fsd refuses to
//! serve there (it has no unconfined mode).

#[cfg(target_os = "linux")]
pub mod linux;

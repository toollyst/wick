// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! Features of wick.
//!
//! Upstream Firecracker calls these through the hooks in `vmm::ext`. Each feature
//! (desktop network, host folder sharing, ...) is added here as a named extension,
//! reachable through `PUT /extensions/{name}` or the `extensions` section of the
//! config file. See `docs/ARCHITECTURE.md`.

use vmm::ext::{BootContext, ExtError, ExtRequest, Extension};

/// Wick's extension. It has no features yet, so every request is rejected
/// and nothing is attached at boot.
#[derive(Debug, Default)]
pub struct WickExtension;

impl Extension for WickExtension {
    fn configure(&self, request: ExtRequest) -> Result<(), ExtError> {
        Err(unknown(&request.name))
    }

    fn update(&self, request: ExtRequest) -> Result<(), ExtError> {
        Err(unknown(&request.name))
    }

    fn attach_boot_devices(&self, _ctx: &mut BootContext<'_>) -> Result<(), ExtError> {
        Ok(())
    }
}

fn unknown(name: &str) -> ExtError {
    ExtError(format!("unknown extension `{name}`"))
}

/// Registers [`WickExtension`] with the VMM. Call once at process start; later calls
/// are ignored.
pub fn register() {
    // Only the first registration takes effect, which is what we want.
    let _ = vmm::ext::register(Box::new(WickExtension));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unknown_extension_is_rejected() {
        let request = ExtRequest {
            name: "fs".to_string(),
            body: Default::default(),
        };
        let err = WickExtension.configure(request.clone()).unwrap_err();
        assert_eq!(err.to_string(), "unknown extension `fs`");
        WickExtension.update(request).unwrap_err();
    }
}

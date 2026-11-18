// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! Features of wick.
//!
//! Upstream Firecracker calls these through the hooks in `vmm::ext`. Each feature
//! (desktop network, host folder sharing, ...) is added here as a named extension,
//! reachable through `PUT /extensions/{name}` or the `extensions` section of the
//! config file. See `docs/ARCHITECTURE.md`.

// A broken documentation link fails `cargo doc` (CI's rustdoc steps).
#![deny(rustdoc::broken_intra_doc_links)]

#[cfg(all(feature = "fs", unix))]
pub mod fs;

use vmm::ext::{BootContext, ExtError, ExtRequest, Extension};

/// Wick's extension: host folder sharing (`fs`) with the `fs` feature, on
/// Linux and macOS. Any other request is rejected, and without a feature
/// nothing is attached at boot.
#[derive(Debug, Default)]
pub struct WickExtension {
    #[cfg(all(feature = "fs", unix))]
    fs: fs::Fs,
}

impl Extension for WickExtension {
    fn configure(&self, request: ExtRequest) -> Result<(), ExtError> {
        match request.name.as_str() {
            #[cfg(all(feature = "fs", unix))]
            "fs" => self.fs.configure(request.body),
            // Built with the feature where the device is not written yet:
            // said, rather than taken for an unknown name.
            #[cfg(all(feature = "fs", not(unix)))]
            "fs" => Err(ExtError("extension `fs`: virtio-fs is not built for this host yet".to_string())),
            name => Err(unknown(name)),
        }
    }

    fn update(&self, request: ExtRequest) -> Result<(), ExtError> {
        match request.name.as_str() {
            #[cfg(feature = "fs")]
            "fs" => Err(ExtError("extension `fs` cannot be changed after boot".to_string())),
            name => Err(unknown(name)),
        }
    }

    fn attach_boot_devices(&self, _ctx: &mut BootContext<'_>) -> Result<(), ExtError> {
        #[cfg(all(feature = "fs", unix))]
        self.fs.attach(_ctx)?;
        Ok(())
    }

    fn snapshot_blocker(&self) -> Option<String> {
        #[cfg(all(feature = "fs", unix))]
        if let Some(why) = self.fs.snapshot_blocker() {
            return Some(why);
        }
        None
    }

    fn write_metrics(&self, _out: &mut serde_json::Map<String, serde_json::Value>) {
        #[cfg(all(feature = "fs", unix))]
        fs::Fs::write_metrics(_out);
    }
}

fn unknown(name: &str) -> ExtError {
    ExtError(format!("unknown extension `{name}`"))
}

/// Registers [`WickExtension`] with the VMM. Call once at process start; later calls
/// are ignored.
pub fn register() {
    // Only the first registration takes effect, which is what we want.
    let _ = vmm::ext::register(Box::new(WickExtension::default()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unknown_extension_is_rejected() {
        let ext = WickExtension::default();
        for name in ["net", "fs"] {
            if cfg!(feature = "fs") && name == "fs" {
                continue;
            }
            let request = ExtRequest {
                name: name.to_string(),
                body: Default::default(),
            };
            let err = ext.configure(request.clone()).unwrap_err();
            assert_eq!(err.to_string(), format!("unknown extension `{name}`"));
            ext.update(request).unwrap_err();
        }
        assert!(ext.snapshot_blocker().is_none());
    }
}

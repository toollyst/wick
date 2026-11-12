// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! Extension point of wick. Not part of upstream Firecracker.
//!
//! Upstream code calls into this module from a few fixed points, each marked with
//! an `wick:` comment. Wick's features live in the `wick-ext` crate, which
//! registers itself here with [`register`]. Without a registered extension every
//! hook is a no-op, so upstream behaviour is unchanged.
//!
//! A Firecracker process runs one microVM, so the extension keeps its own
//! configuration state; no upstream resource struct needs a new field.
//!
//! See `docs/ARCHITECTURE.md`.

pub mod api_process;
pub mod fifo;
pub mod jail;
pub mod sandbox;
pub mod vcpu_thread;
#[cfg(all(test, target_os = "macos"))]
mod snapshot_vcpu_tests;
#[cfg(all(test, unix))]
mod nonblocking_pipe_tests;
#[cfg(all(test, unix))]
mod sigpipe_tests;
#[cfg(all(test, unix))]
mod unix_stream_tests;

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::sync::{Arc, Mutex, OnceLock};

use event_manager::MutEventSubscriber;
use linux_loader::cmdline::Cmdline;
use serde::Deserialize;
use serde_json::Value;

use crate::EventManager;
use crate::device_manager::DeviceManager;
use crate::devices::virtio::device::VirtioDevice;
use crate::rpc_interface::{VmmAction, VmmActionError, VmmData};
use crate::vstate::vm::Vm;

/// API path prefix of extension requests: `PUT /extensions/{name}`.
pub const API_PATH: &str = "extensions";

/// Key of the extension section in the `--config-file` JSON.
pub const CONFIG_KEY: &str = "extensions";

/// Error reported by an extension.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ExtError(pub String);

/// A request for one extension: `PUT /extensions/{name}` with a JSON body, or the
/// `extensions.{name}` entry of the config file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtRequest {
    /// Extension name, the last path segment.
    pub name: String,
    /// Request body.
    pub body: Value,
}

/// Features added by wick.
pub trait Extension: Send + Sync + Debug {
    /// Applies a request before the microVM boots.
    fn configure(&self, request: ExtRequest) -> Result<(), ExtError>;

    /// Applies a request after the microVM has booted.
    fn update(&self, request: ExtRequest) -> Result<(), ExtError> {
        Err(ExtError(format!(
            "extension `{}` cannot be changed after boot",
            request.name
        )))
    }

    /// Attaches the configured devices while the microVM is built.
    fn attach_boot_devices(&self, ctx: &mut BootContext<'_>) -> Result<(), ExtError>;

    /// Returns why a snapshot cannot be taken, or `None` if it can.
    fn snapshot_blocker(&self) -> Option<String> {
        None
    }
}

/// What an extension may use while the microVM is built.
pub struct BootContext<'a> {
    device_manager: &'a mut DeviceManager,
    vm: &'a Vm,
    cmdline: &'a mut Cmdline,
    event_manager: &'a mut EventManager,
}

impl Debug for BootContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootContext").finish_non_exhaustive()
    }
}

impl BootContext<'_> {
    /// The microVM being built.
    pub fn vm(&self) -> &Vm {
        self.vm
    }

    /// Attaches a virtio device the same way upstream attaches its boot devices.
    pub fn attach_virtio_device<T: 'static + VirtioDevice + MutEventSubscriber + Debug>(
        &mut self,
        id: String,
        device: Arc<Mutex<T>>,
        is_vhost_user: bool,
    ) -> Result<(), ExtError> {
        self.device_manager
            .attach_boot_virtio_device(
                self.vm,
                id,
                device,
                self.cmdline,
                self.event_manager,
                is_vhost_user,
            )
            .map_err(|err| ExtError(err.to_string()))
    }
}

static EXTENSION: OnceLock<Box<dyn Extension>> = OnceLock::new();

/// Registers the process-wide extension. Only the first call takes effect.
pub fn register(extension: Box<dyn Extension>) -> Result<(), ExtError> {
    EXTENSION
        .set(extension)
        .map_err(|_| ExtError("an extension is already registered".to_string()))
}

fn registered() -> Option<&'static dyn Extension> {
    EXTENSION.get().map(Box::as_ref)
}

fn require<'a>(
    extension: Option<&'a dyn Extension>,
    name: &str,
) -> Result<&'a dyn Extension, ExtError> {
    extension.ok_or_else(|| ExtError(format!("unknown extension `{name}`")))
}

/// Parses `PUT /extensions/{name}`. Called by the API server.
pub fn parse_put(name: Option<&str>, body: &[u8]) -> Result<VmmAction, ExtError> {
    let name = match name {
        Some(name) if !name.is_empty() => name.to_string(),
        _ => return Err(ExtError("missing extension name in the path".to_string())),
    };
    let body = serde_json::from_slice(body)
        .map_err(|err| ExtError(format!("invalid body for extension `{name}`: {err}")))?;
    Ok(VmmAction::Extension(ExtRequest { name, body }))
}

/// Handles an extension request before boot. Called by the preboot API controller.
pub(crate) fn configure(request: ExtRequest) -> Result<VmmData, VmmActionError> {
    configure_with(registered(), request)
}

fn configure_with(
    extension: Option<&dyn Extension>,
    request: ExtRequest,
) -> Result<VmmData, VmmActionError> {
    require(extension, &request.name)?.configure(request)?;
    Ok(VmmData::Empty)
}

/// Handles an extension request after boot. Called by the runtime API controller.
pub(crate) fn update(request: ExtRequest) -> Result<VmmData, VmmActionError> {
    update_with(registered(), request)
}

fn update_with(
    extension: Option<&dyn Extension>,
    request: ExtRequest,
) -> Result<VmmData, VmmActionError> {
    require(extension, &request.name)?.update(request)?;
    Ok(VmmData::Empty)
}

#[derive(Deserialize)]
struct ConfigSection {
    #[serde(default)]
    extensions: BTreeMap<String, Value>,
}

/// Applies the `extensions` section of the config file. Called by `VmResources::from_json`.
pub(crate) fn configure_from_json(config_json: &str) -> Result<(), ExtError> {
    configure_from_json_with(registered(), config_json)
}

fn configure_from_json_with(
    extension: Option<&dyn Extension>,
    config_json: &str,
) -> Result<(), ExtError> {
    let section: ConfigSection = serde_json::from_str(config_json)
        .map_err(|err| ExtError(format!("invalid `{CONFIG_KEY}` section: {err}")))?;
    for (name, body) in section.extensions {
        require(extension, &name)?.configure(ExtRequest { name, body })?;
    }
    Ok(())
}

/// Attaches extension devices. Called by the builder after the upstream boot devices.
pub(crate) fn attach_boot_devices(
    device_manager: &mut DeviceManager,
    vm: &Vm,
    cmdline: &mut Cmdline,
    event_manager: &mut EventManager,
) -> Result<(), ExtError> {
    let Some(extension) = registered() else {
        return Ok(());
    };
    extension.attach_boot_devices(&mut BootContext {
        device_manager,
        vm,
        cmdline,
        event_manager,
    })
}

/// Fails if an extension cannot be snapshotted. Called before a snapshot is created.
pub(crate) fn check_snapshot() -> Result<(), ExtError> {
    check_snapshot_with(registered())
}

fn check_snapshot_with(extension: Option<&dyn Extension>) -> Result<(), ExtError> {
    match extension.and_then(Extension::snapshot_blocker) {
        Some(reason) => Err(ExtError(format!("snapshot not supported: {reason}"))),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Default)]
    struct Recorder {
        configured: Mutex<Vec<ExtRequest>>,
        blocker: Option<String>,
    }

    impl Extension for Recorder {
        fn configure(&self, request: ExtRequest) -> Result<(), ExtError> {
            if request.name == "bad" {
                return Err(ExtError("rejected".to_string()));
            }
            self.configured.lock().unwrap().push(request);
            Ok(())
        }

        fn attach_boot_devices(&self, _ctx: &mut BootContext<'_>) -> Result<(), ExtError> {
            Ok(())
        }

        fn snapshot_blocker(&self) -> Option<String> {
            self.blocker.clone()
        }
    }

    fn request(name: &str) -> ExtRequest {
        ExtRequest {
            name: name.to_string(),
            body: serde_json::json!({"k": 1}),
        }
    }

    #[test]
    fn test_parse_put() {
        assert_eq!(
            parse_put(Some("fs"), br#"{"k": 1}"#).unwrap(),
            VmmAction::Extension(request("fs"))
        );
        parse_put(None, b"{}").unwrap_err();
        parse_put(Some(""), b"{}").unwrap_err();
        parse_put(Some("fs"), b"not json").unwrap_err();
    }

    #[test]
    fn test_requests_without_extension() {
        configure_with(None, request("fs")).unwrap_err();
        update_with(None, request("fs")).unwrap_err();
        check_snapshot_with(None).unwrap();
        // A config file without the section is accepted, as upstream does.
        configure_from_json_with(None, r#"{"boot-source": {}}"#).unwrap();
        configure_from_json_with(None, r#"{"extensions": {"fs": {}}}"#).unwrap_err();
    }

    #[test]
    fn test_requests_with_extension() {
        let ext = Recorder::default();
        assert_eq!(
            configure_with(Some(&ext), request("fs")).unwrap(),
            VmmData::Empty
        );
        configure_with(Some(&ext), request("bad")).unwrap_err();
        // The default `update` refuses changes after boot.
        update_with(Some(&ext), request("fs")).unwrap_err();

        configure_from_json_with(Some(&ext), r#"{"extensions": {"net": {"k": 1}}}"#).unwrap();
        configure_from_json_with(Some(&ext), r#"{"extensions": {"bad": {}}}"#).unwrap_err();
        configure_from_json_with(Some(&ext), r#"{"extensions": []}"#).unwrap_err();
        assert_eq!(
            *ext.configured.lock().unwrap(),
            vec![request("fs"), request("net")]
        );
    }

    #[test]
    fn test_snapshot_blocker() {
        let ext = Recorder {
            blocker: Some("virtio-fs".to_string()),
            ..Default::default()
        };
        check_snapshot_with(Some(&ext)).unwrap_err();
        check_snapshot_with(Some(&Recorder::default())).unwrap();
    }
}

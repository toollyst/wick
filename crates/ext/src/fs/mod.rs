// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! Host folder sharing (docs/design-fs.md): one virtio-fs device per share,
//! each a copier between its queues and wick-fsd, the share's file server,
//! over a Unix socket. The VMM never opens a host file of the share: the
//! server does, in its own confinement.
//!
//! `PUT /extensions/fs` (or the config file's `extensions.fs`) names the
//! shares ([`config`]); while the microVM is built each device connects to
//! its server and checks the hello, and a share whose server is absent or
//! not the share's stops the build. A snapshot is refused while a share is
//! attached, and nothing of it changes after boot.

pub mod config;
pub mod copy;
pub mod device;
pub mod metrics;

use std::sync::{Arc, Mutex};

use serde_json::{Map, Value};
use vmm::ext::{BootContext, ExtError};

use self::config::FsConfig;
use self::device::FsDevice;

/// The shares configured before boot.
#[derive(Debug, Default)]
pub struct Fs {
    config: Mutex<Option<FsConfig>>,
}

impl Fs {
    /// Takes `PUT /extensions/fs`'s body; a later request before boot
    /// replaces it.
    pub fn configure(&self, body: Value) -> Result<(), ExtError> {
        let config = FsConfig::parse(body).map_err(ExtError)?;
        *self.lock() = Some(config);
        Ok(())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<FsConfig>> {
        self.config.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Connects each share's device to its server and attaches it.
    pub fn attach(&self, ctx: &mut BootContext<'_>) -> Result<(), ExtError> {
        let Some(config) = self.lock().clone() else {
            return Ok(());
        };
        let mut shares = Vec::with_capacity(config.shares.len());
        for share in &config.shares {
            let conn = device::connect(share).map_err(ExtError)?;
            let device = FsDevice::new(share, conn).map_err(ExtError)?;
            shares.push((share.id.clone(), device.metrics()));
            ctx.attach_virtio_device(share.id.clone(), Arc::new(Mutex::new(device)), false)?;
        }
        metrics::register(shares);
        Ok(())
    }

    /// Why a snapshot cannot be taken: the shares' state is the servers',
    /// outside the VMM (design-fs row 17).
    pub fn snapshot_blocker(&self) -> Option<String> {
        let config = self.lock();
        let ids: Vec<&str> = config.as_ref()?.shares.iter().map(|s| s.id.as_str()).collect();
        Some(format!("virtio-fs (shares {})", ids.join(", ")))
    }

    /// Adds each share's counters, read without a lock.
    pub fn write_metrics(out: &mut Map<String, Value>) {
        metrics::write(out);
    }
}

// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! Each share's counters, `fs_<id>` in the metrics line's `wick` object.
//!
//! Counters only, each an atomic: the line is written wherever upstream
//! writes it, a fatal signal's handler included (`Extension::write_metrics`),
//! so reading them takes no lock a device could hold.

use std::sync::{Arc, OnceLock};

use serde::Serialize;
use serde_json::{Map, Value};
use vmm::logger::{IncMetric, SharedIncMetric, SharedStoreMetric, StoreMetric};

/// One share's counters, as upstream's device metrics: each a count since
/// the last line, but the three stores (`server_lost`, `stalled`,
/// `waiting`), which are the state.
#[derive(Debug, Default, Serialize)]
pub struct FsMetrics {
    /// Request frames sent to the server.
    pub requests: SharedIncMetric,
    /// Their bytes, headers included.
    pub request_bytes: SharedIncMetric,
    /// Reply frames taken from the server.
    pub replies: SharedIncMetric,
    /// Their payload bytes written into the guest's chains.
    pub reply_bytes: SharedIncMetric,
    /// Chains the device answered itself: too long, too little writable
    /// space, or after the server was lost.
    pub refused_chains: SharedIncMetric,
    /// Chains answered with `-EIO` because the server was lost.
    pub eio_answers: SharedIncMetric,
    /// Times a queue was left untaken at the in-flight limit.
    pub inflight_full: SharedIncMetric,
    /// Times a queue was left untaken by the rate limiter.
    pub rate_limited: SharedIncMetric,
    /// Failures writing a reply into guest memory or signalling the guest.
    pub event_fails: SharedIncMetric,
    /// 1 once the server is lost (the connection ended or broke a rule).
    pub server_lost: SharedStoreMetric,
    /// 1 while the server has sent nothing and taken nothing for the
    /// stall time with requests outstanding.
    pub stalled: SharedStoreMetric,
    /// Requests waiting for a reply, at the device's last event.
    pub waiting: SharedStoreMetric,
}

impl FsMetrics {
    /// Counts a lost server.
    pub fn lose(&self) {
        self.server_lost.store(1);
    }

    /// Counts `n` more.
    pub fn add(metric: &SharedIncMetric, n: usize) {
        metric.add(u64::try_from(n).unwrap_or(u64::MAX));
    }
}

/// The shares' counters, set once when their devices are attached: read
/// without a lock.
static SHARES: OnceLock<Vec<(String, Arc<FsMetrics>)>> = OnceLock::new();

/// Records the attached shares' counters. Once per process (one microVM).
pub fn register(shares: Vec<(String, Arc<FsMetrics>)>) {
    let _ = SHARES.set(shares);
}

/// Adds each share's counters to `out` as `fs_<id>`.
pub fn write(out: &mut Map<String, Value>) {
    write_from(SHARES.get().map(Vec::as_slice).unwrap_or_default(), out);
}

pub(crate) fn write_from(shares: &[(String, Arc<FsMetrics>)], out: &mut Map<String, Value>) {
    for (id, metrics) in shares {
        if let Ok(value) = serde_json::to_value(metrics.as_ref()) {
            out.insert(format!("fs_{id}"), value);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[test]
    fn test_counters_are_written_as_fs_id() {
        let m = Arc::new(FsMetrics::default());
        m.requests.inc();
        m.lose();
        let mut out = Map::new();
        write_from(&[("docs".to_string(), m)], &mut out);
        let v = &out["fs_docs"];
        assert_eq!(v["requests"], 1);
        assert_eq!(v["server_lost"], 1);
        assert_eq!(v["replies"], 0);
    }

    /// The hook takes no lock a device holds: written while a device's lock
    /// is held (as a fatal signal could interrupt the device's thread), it
    /// returns.
    #[test]
    fn test_write_takes_no_lock_a_device_holds() {
        let m = Arc::new(FsMetrics::default());
        let device = Mutex::new(m.clone());
        let held = device.lock().unwrap();
        held.replies.inc();
        let mut out = Map::new();
        write_from(&[("a".to_string(), m.clone())], &mut out);
        write(&mut Map::new());
        assert_eq!(out["fs_a"]["replies"], 1);
        drop(held);
    }
}

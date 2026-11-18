// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! `PUT /extensions/fs` and the config file's `extensions.fs`
//! (docs/design-fs.md §4.1): the guest's side of each share only. The host
//! directory is wick-fsd's configuration, never the VMM's.
//!
//! ```json
//! {"shares": [{"id": "docs", "tag": "docs", "socket": "/run/wick/fs-docs.sock",
//!              "queue_size": 256, "rate_limiter": {"ops": {...}}}]}
//! ```

use std::path::PathBuf;

use serde::Deserialize;
use vmm::vmm_config::RateLimiterConfig;
use wick_fs_frame::check_id;

/// The longest tag: `virtio_fs_config.tag` is 36 bytes.
pub const MAX_TAG_LEN: usize = 36;

/// The largest queue, as upstream's devices have (`FIRECRACKER_MAX_QUEUE_SIZE`,
/// private to vmm's queue module).
pub const MAX_QUEUE_SIZE: u16 = 256;

/// The most shares a microVM takes.
pub const MAX_SHARES: usize = 8;

/// The shares of a microVM.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FsConfig {
    /// One device each.
    pub shares: Vec<ShareConfig>,
}

/// One share, as the guest sees it.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ShareConfig {
    /// The share's id, which wick-fsd's hello must name: `[a-z0-9_-]`, 1 to
    /// 64 characters.
    pub id: String,
    /// The tag the guest mounts (`mount -t virtiofs <tag>`): UTF-8, 1 to 36
    /// bytes.
    pub tag: String,
    /// wick-fsd's socket. When not given, `/fs-<id>.sock`
    /// ([`default_socket`]): where the jailer's `--fs-share` puts it, in the
    /// jail's root (overlay/jailer/fs_share.rs). Without the jailer it is
    /// required: the default is then a name at the host's root, which the
    /// connect refuses naming it and saying so.
    #[serde(default)]
    pub socket: Option<PathBuf>,
    /// Each queue's size: a power of two, at most 256.
    #[serde(default)]
    pub queue_size: Option<u16>,
    /// Upstream's block-device rate limiter: one op per chain, and its
    /// readable and writable bytes.
    #[serde(default)]
    pub rate_limiter: Option<RateLimiterConfig>,
}

/// The socket of share `id` when its `socket` is not given: the jailer's
/// name for it, in the jail's root.
pub fn default_socket(id: &str) -> PathBuf {
    PathBuf::from(format!("/fs-{id}.sock"))
}

impl ShareConfig {
    /// The socket the device connects to: `socket`, or [`default_socket`].
    pub fn socket(&self) -> PathBuf {
        self.socket.clone().unwrap_or_else(|| default_socket(&self.id))
    }

    /// The queues' size.
    pub fn queue_size(&self) -> u16 {
        self.queue_size.unwrap_or(MAX_QUEUE_SIZE)
    }
}

impl FsConfig {
    /// The configuration in `body`, checked.
    pub fn parse(body: serde_json::Value) -> Result<FsConfig, String> {
        let config: FsConfig = serde_json::from_value(body).map_err(|e| format!("invalid `fs`: {e}"))?;
        config.check()?;
        Ok(config)
    }

    fn check(&self) -> Result<(), String> {
        if self.shares.is_empty() || self.shares.len() > MAX_SHARES {
            return Err(format!("`fs` takes 1 to {MAX_SHARES} shares, not {}", self.shares.len()));
        }
        for (i, share) in self.shares.iter().enumerate() {
            check_id(&share.id).map_err(|_| {
                format!("share id {:?}: 1 to 64 characters of a-z, 0-9, `_` and `-`", share.id)
            })?;
            if share.tag.is_empty() || share.tag.len() > MAX_TAG_LEN || share.tag.contains('\0') {
                return Err(format!(
                    "share {}: the tag is 1 to {MAX_TAG_LEN} bytes of UTF-8 without NUL",
                    share.id
                ));
            }
            let size = share.queue_size();
            if !size.is_power_of_two() || !(2..=MAX_QUEUE_SIZE).contains(&size) {
                return Err(format!(
                    "share {}: queue_size is a power of two from 2 to {MAX_QUEUE_SIZE}",
                    share.id
                ));
            }
            if share.socket.as_ref().is_some_and(|s| s.as_os_str().is_empty()) {
                return Err(format!("share {}: an empty socket path", share.id));
            }
            for other in &self.shares[..i] {
                if other.id == share.id {
                    return Err(format!("share id {} given twice", share.id));
                }
                if other.tag == share.tag {
                    return Err(format!("tag {} given twice", share.tag));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    /// A share with `id`, `tag` and a socket, and `extra` fields.
    fn share(id: &str, tag: &str, extra: Value) -> Value {
        let mut v = json!({"id": id, "tag": tag, "socket": format!("/run/fs-{id}.sock")});
        if let (Some(v), Some(extra)) = (v.as_object_mut(), extra.as_object()) {
            v.extend(extra.clone());
        }
        v
    }

    #[test]
    fn test_a_share_with_defaults() {
        let c = FsConfig::parse(json!({"shares": [share("docs", "Docs ü", json!({}))]})).unwrap();
        assert_eq!(c.shares[0].socket(), PathBuf::from("/run/fs-docs.sock"));
        assert_eq!(c.shares[0].queue_size(), 256);
        assert!(c.shares[0].rate_limiter.is_none());
    }

    #[test]
    fn test_bad_configs_are_refused() {
        let long_tag = "t".repeat(37);
        let bad = [
            json!({"shares": []}),
            json!({"shares": [share("Docs", "t", json!({}))]}),
            json!({"shares": [share("d", "", json!({}))]}),
            json!({"shares": [share("d", &long_tag, json!({}))]}),
            json!({"shares": [share("d", "a\u{0}", json!({}))]}),
            json!({"shares": [share("d", "t", json!({"queue_size": 100}))]}),
            json!({"shares": [share("d", "t", json!({"queue_size": 512}))]}),
            json!({"shares": [share("d", "t", json!({"queue_size": 1}))]}),
            json!({"shares": [share("d", "t", json!({"socket": ""}))]}),
            json!({"shares": [share("d", "t", json!({})), share("d", "u", json!({}))]}),
            json!({"shares": [share("d", "t", json!({})), share("e", "t", json!({}))]}),
            // The host directory and read_only are the server's, never the VMM's.
            json!({"shares": [share("d", "t", json!({"shared_dir": "/"}))]}),
            json!({"shares": [share("d", "t", json!({"read_only": true}))]}),
            json!({"shares": [share("d", "t", json!({}))], "other": 1}),
        ];
        for body in bad {
            FsConfig::parse(body.clone()).expect_err(&body.to_string());
        }
        let nine: Vec<_> = (0..9).map(|i| share(&format!("s{i}"), &format!("t{i}"), json!({}))).collect();
        FsConfig::parse(json!({ "shares": nine })).unwrap_err();
        // 36 bytes of UTF-8 is the longest tag.
        let tag = "ü".repeat(18);
        FsConfig::parse(json!({"shares": [share("d", &tag, json!({}))]})).unwrap();
    }

    /// No `socket`: the jailer's name for the share's socket, in the jail's
    /// root (device::tests::test_the_default_socket_s_refusal_says_it_is_required
    /// has the connect's refusal without the jailer).
    #[test]
    fn test_the_default_socket_is_the_jailer_s() {
        let c = FsConfig::parse(json!({"shares": [{"id": "docs", "tag": "t"}]})).unwrap();
        assert_eq!(c.shares[0].socket, None);
        assert_eq!(c.shares[0].socket(), PathBuf::from("/fs-docs.sock"));
    }
}

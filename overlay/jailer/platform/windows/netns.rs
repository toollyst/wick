// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! `--netns` on Windows: the jail's network, and no other.
//!
//! On Linux the jailer joins the network namespace the operator names, and
//! Firecracker then has that namespace's interfaces and no other: the guest
//! reaches only the network given there. Windows has no network namespaces.
//! What a jail gets instead is the same reach:
//!
//! - **Its network is a directory of endpoints.** `--netns <dir>` names a
//!   directory the operator made; every network endpoint Firecracker opens
//!   (`platform::net`, a Unix stream socket a host-side switch connects to)
//!   is made there, and the jail's SID is granted on it, as a TAP device in
//!   the namespace is reachable from inside it. Two jails given the same
//!   directory share a network, as two Firecrackers in one namespace do; a
//!   jail given its own reaches no other jail's (`jailer-test.ps1 netns`).
//! - **No IP networking at all**, through the Windows Filtering Platform
//!   ([`NetFilter`]): every IPv4 and IPv6 connect, bind, listen and accept of
//!   the processes running the jail's copy of Firecracker is blocked, in a
//!   session that ends with the jailer, so a jailer that dies leaves no
//!   filter behind. Inside a namespace of its own, Firecracker has no route
//!   to the host's networks either. The filter is by the image file
//!   (`FWPM_CONDITION_ALE_APP_ID`): the jail's copy of the binary, which only
//!   that jail runs, and which a process cannot change about itself. Unix
//!   sockets (the API socket, vsock, the network endpoints, userfaultfd and
//!   vhost-user) are not IP and pass.
//!
//! Adding a filter takes the filter engine's `FWPM_ACTRL_ADD` right, which
//! Windows grants to administrators: `--netns` needs an elevated jailer, as
//! `setns` needs root on Linux, and is refused loudly without one, when the
//! flag is applied ([`NetFilter::open`], before anything else of the jail is
//! made), as `setns` fails there.

use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE, FWP_CONDITION_VALUE0,
    FWP_CONDITION_VALUE0_0, FWP_MATCH_EQUAL, FWP_UINT8, FWP_VALUE0, FWP_VALUE0_0,
    FWPM_CONDITION_ALE_APP_ID, FWPM_FILTER0, FWPM_FILTER_CONDITION0,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_AUTH_LISTEN_V4, FWPM_LAYER_ALE_AUTH_LISTEN_V6,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4, FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6,
    FWPM_SESSION0, FWPM_SESSION_FLAG_DYNAMIC, FWPM_SUBLAYER0, FwpmEngineClose0,
    FwpmEngineOpen0, FwpmFilterAdd0, FwpmFreeMemory0, FwpmGetAppIdFromFileName0,
    FwpmSubLayerAdd0,
};
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
use windows_sys::core::GUID;

/// `ERROR_ACCESS_DENIED`.
const ACCESS_DENIED: u32 = 5;

/// The layers at which a process's IP networking is decided: outbound
/// connections (TCP `connect`, the first UDP `send`), local addresses and
/// ports (`bind`, explicit or implicit), `listen`, and inbound connections
/// and datagrams; IPv4 and IPv6.
const LAYERS: [(&str, GUID); 8] = [
    ("connect v4", FWPM_LAYER_ALE_AUTH_CONNECT_V4),
    ("connect v6", FWPM_LAYER_ALE_AUTH_CONNECT_V6),
    ("bind v4", FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4),
    ("bind v6", FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6),
    ("listen v4", FWPM_LAYER_ALE_AUTH_LISTEN_V4),
    ("listen v6", FWPM_LAYER_ALE_AUTH_LISTEN_V6),
    ("accept v4", FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4),
    ("accept v6", FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6),
];

/// What failed, and the filter engine's error.
#[derive(Debug)]
pub struct NetFilterError {
    pub what: &'static str,
    pub code: u32,
}

impl std::fmt::Display for NetFilterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let code = self.code;
        if code == ACCESS_DENIED {
            write!(
                f,
                "{}: access denied; --netns needs an elevated jailer (adding a Windows Filtering \
                 Platform filter is an administrator's right)",
                self.what
            )
        } else if code & 0xFFFF_0000 == 0x8032_0000 {
            write!(f, "{}: the filter engine answered {code:#010x}", self.what)
        } else {
            write!(f, "{}: {}", self.what, io::Error::from_raw_os_error(code.cast_signed()))
        }
    }
}

impl std::error::Error for NetFilterError {}

fn check(what: &'static str, code: u32) -> Result<(), NetFilterError> {
    if code == 0 { Ok(()) } else { Err(NetFilterError { what, code }) }
}

fn wide(s: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(std::iter::once(0)).collect()
}

/// A random GUID, for this session's sublayer.
fn guid() -> GUID {
    use std::hash::{BuildHasher, Hasher};
    let word = |n: u64| {
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_u64(n);
        h.finish()
    };
    GUID::from_u128(u128::from(word(1)) << 64 | u128::from(word(2)))
}

/// The application id of `image` (its NT path), freed on drop.
struct AppId(*mut FWP_BYTE_BLOB);

impl Drop for AppId {
    fn drop(&mut self) {
        // SAFETY: allocated by FwpmGetAppIdFromFileName0.
        unsafe { FwpmFreeMemory0((&raw mut self.0).cast()) };
    }
}

/// The IP block of one jail: a session on the filter engine, dynamic, so
/// its sublayer and filters go when the session ends (this object dropped,
/// or the jailer gone).
pub struct NetFilter {
    engine: HANDLE,
    /// This session's sublayer.
    sublayer: GUID,
    /// Whether [`NetFilter::block`] was done.
    blocking: bool,
}

impl std::fmt::Debug for NetFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetFilter").field("engine", &self.engine).field("blocking", &self.blocking).finish()
    }
}

// SAFETY: an engine handle may be used and closed from any thread.
unsafe impl Send for NetFilter {}

impl NetFilter {
    /// Opens a session on the filter engine with a sublayer of its own:
    /// where an unelevated jailer is refused.
    pub fn open() -> Result<NetFilter, NetFilterError> {
        // SAFETY: an all-zero session is valid; the flags are set below.
        let mut session: FWPM_SESSION0 = unsafe { std::mem::zeroed() };
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;
        let mut engine: HANDLE = std::ptr::null_mut();
        // SAFETY: the local engine, with the session above; an out-pointer.
        let rc = unsafe {
            FwpmEngineOpen0(std::ptr::null(), RPC_C_AUTHN_WINNT, std::ptr::null(), &session, &mut engine)
        };
        check("opening the filter engine", rc)?;
        let key = guid();
        let filter = NetFilter { engine, sublayer: key, blocking: false };

        // A sublayer of this session, weighted above every other, so that a
        // permit filter elsewhere cannot override the block.
        let mut name = wide("wick jailer --netns");
        // SAFETY: an all-zero sublayer is valid; the fields are set below.
        let mut sublayer: FWPM_SUBLAYER0 = unsafe { std::mem::zeroed() };
        sublayer.subLayerKey = key;
        sublayer.displayData.name = name.as_mut_ptr();
        sublayer.weight = u16::MAX;
        // SAFETY: a valid sublayer; no security descriptor.
        check("adding the sublayer", unsafe { FwpmSubLayerAdd0(engine, &sublayer, std::ptr::null_mut()) })?;
        Ok(filter)
    }

    /// Blocks every IPv4 and IPv6 connect, bind, listen and accept of the
    /// processes running `image`, from now until the filter is dropped.
    pub fn block(&mut self, image: &Path) -> Result<(), NetFilterError> {
        let (engine, key) = (self.engine, self.sublayer);
        let mut name = wide("wick jailer --netns");
        let mut app_id: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
        // SAFETY: a NUL-terminated path and an out-pointer.
        let rc = unsafe { FwpmGetAppIdFromFileName0(wide(image).as_ptr(), &mut app_id) };
        check("the application id of the jail's binary", rc)?;
        let app_id = AppId(app_id);

        for (what, layer) in LAYERS {
            let condition = FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_ALE_APP_ID,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_BYTE_BLOB_TYPE,
                    Anonymous: FWP_CONDITION_VALUE0_0 { byteBlob: app_id.0 },
                },
            };
            // SAFETY: an all-zero filter is valid; the fields are set below.
            let mut f: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
            f.displayData.name = name.as_mut_ptr();
            f.layerKey = layer;
            f.subLayerKey = key;
            f.weight = FWP_VALUE0 { r#type: FWP_UINT8, Anonymous: FWP_VALUE0_0 { uint8: 15 } };
            f.numFilterConditions = 1;
            f.filterCondition = (&raw const condition).cast_mut();
            f.action.r#type = FWP_ACTION_BLOCK;
            let mut id = 0u64;
            // SAFETY: a valid filter whose condition and name outlive the call.
            let rc = unsafe { FwpmFilterAdd0(engine, &f, std::ptr::null_mut(), &mut id) };
            check(what, rc)?;
        }
        self.blocking = true;
        Ok(())
    }

    /// Whether [`NetFilter::block`] was done.
    pub fn is_blocking(&self) -> bool {
        self.blocking
    }
}

impl Drop for NetFilter {
    fn drop(&mut self) {
        // SAFETY: closes the session this object opened; its filters go with it.
        unsafe { FwpmEngineClose0(self.engine) };
    }
}

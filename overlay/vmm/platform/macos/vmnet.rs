// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! vmnet.framework interfaces: the macOS way to put a VM's frames on a host
//! network.
//!
//! - Shared mode (NAT to the host's networks, with DHCP and DNS) and host mode
//!   (the host and the other VMs only) use the network API of macOS 26
//!   (`vmnet_network_create` + `vmnet_interface_start_with_network`), which
//!   works for an unprivileged process signed with the
//!   `com.apple.security.virtualization` entitlement. Every interface of one
//!   mode in a process joins the same network.
//! - Bridged mode, and the other modes before macOS 26, use
//!   `vmnet_start_interface`, which needs root (or the
//!   `com.apple.vm.networking` entitlement).
//!
//! Frames are plain Ethernet frames. vmnet reports arriving packets through a
//! callback on a dispatch queue; the callback writes to a pipe whose read end
//! is the interface's pollable descriptor.

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::fs::File;
use std::io::{self, Read};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::ptr::{self, null, null_mut};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::Duration;

type InterfaceRef = *mut c_void;
type XpcObject = *mut c_void;
type DispatchQueue = *mut c_void;
type NetworkRef = *mut c_void;

const VMNET_HOST_MODE: u32 = 1000;
const VMNET_SHARED_MODE: u32 = 1001;
const VMNET_BRIDGED_MODE: u32 = 1002;
const VMNET_SUCCESS: u32 = 1000;
const VMNET_INTERFACE_PACKETS_AVAILABLE: u32 = 1;

/// How long to wait for vmnet to start or stop an interface.
const TIMEOUT: Duration = Duration::from_secs(30);

#[repr(C)]
struct VmPktDesc {
    vm_pkt_size: usize,
    vm_pkt_iov: *mut libc::iovec,
    vm_pkt_iovcnt: u32,
    vm_flags: u32,
}

#[link(name = "vmnet", kind = "framework")]
unsafe extern "C" {
    static vmnet_operation_mode_key: *const c_char;
    static vmnet_shared_interface_name_key: *const c_char;
    static vmnet_mac_address_key: *const c_char;
    static vmnet_mtu_key: *const c_char;
    static vmnet_max_packet_size_key: *const c_char;

    fn vmnet_start_interface(
        desc: XpcObject,
        queue: DispatchQueue,
        handler: *mut c_void,
    ) -> InterfaceRef;
    fn vmnet_stop_interface(iface: InterfaceRef, queue: DispatchQueue, handler: *mut c_void)
    -> u32;
    fn vmnet_interface_set_event_callback(
        iface: InterfaceRef,
        mask: u32,
        queue: DispatchQueue,
        callback: *mut c_void,
    ) -> u32;
    fn vmnet_read(iface: InterfaceRef, packets: *mut VmPktDesc, count: *mut c_int) -> u32;
    fn vmnet_write(iface: InterfaceRef, packets: *mut VmPktDesc, count: *mut c_int) -> u32;
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRelease(cf: *const c_void);
}

unsafe extern "C" {
    static _NSConcreteGlobalBlock: u8;
    fn dispatch_queue_create(label: *const c_char, attr: *const c_void) -> DispatchQueue;
    fn dispatch_release(object: *mut c_void);
    fn xpc_dictionary_create(
        keys: *const *const c_char,
        values: *const XpcObject,
        count: usize,
    ) -> XpcObject;
    fn xpc_dictionary_set_uint64(dict: XpcObject, key: *const c_char, value: u64);
    fn xpc_dictionary_set_string(dict: XpcObject, key: *const c_char, value: *const c_char);
    fn xpc_dictionary_get_uint64(dict: XpcObject, key: *const c_char) -> u64;
    fn xpc_dictionary_get_string(dict: XpcObject, key: *const c_char) -> *const c_char;
    fn xpc_release(object: XpcObject);
}

type ConfigurationCreate = unsafe extern "C" fn(u32, *mut u32) -> *mut c_void;
type NetworkCreate = unsafe extern "C" fn(*mut c_void, *mut u32) -> NetworkRef;
type StartWithNetwork =
    unsafe extern "C" fn(NetworkRef, XpcObject, DispatchQueue, *mut c_void) -> InterfaceRef;
type GetIpv4Subnet = unsafe extern "C" fn(NetworkRef, *mut libc::in_addr, *mut libc::in_addr);

/// The network API of macOS 26, looked up at run time so the binary still
/// loads on older systems.
struct NetworkApi {
    configuration_create: ConfigurationCreate,
    network_create: NetworkCreate,
    start_with_network: StartWithNetwork,
    get_ipv4_subnet: GetIpv4Subnet,
}

fn network_api() -> Option<&'static NetworkApi> {
    static API: OnceLock<Option<NetworkApi>> = OnceLock::new();
    API.get_or_init(|| {
        let sym = |name: &CStr| {
            // SAFETY: dlsym with a NUL-terminated name.
            let p = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) };
            (!p.is_null()).then_some(p)
        };
        let (a, b, c, d) = (
            sym(c"vmnet_network_configuration_create")?,
            sym(c"vmnet_network_create")?,
            sym(c"vmnet_interface_start_with_network")?,
            sym(c"vmnet_network_get_ipv4_subnet")?,
        );
        // SAFETY: the symbols have these signatures (vmnet.h, macOS 26).
        unsafe {
            Some(NetworkApi {
                configuration_create: std::mem::transmute::<*mut c_void, ConfigurationCreate>(a),
                network_create: std::mem::transmute::<*mut c_void, NetworkCreate>(b),
                start_with_network: std::mem::transmute::<*mut c_void, StartWithNetwork>(c),
                get_ipv4_subnet: std::mem::transmute::<*mut c_void, GetIpv4Subnet>(d),
            })
        }
    })
    .as_ref()
}

/// The network of a mode, shared by every interface of the process.
fn network(api: &NetworkApi, mode: u32) -> io::Result<NetworkRef> {
    // The networks live as long as the process; stored as addresses.
    static NETWORKS: Mutex<Vec<(u32, usize)>> = Mutex::new(Vec::new());
    let mut nets = NETWORKS.lock().unwrap();
    if let Some((_, net)) = nets.iter().find(|(m, _)| *m == mode) {
        return Ok(*net as NetworkRef);
    }
    let mut status = 0;
    // SAFETY: plain calls; the configuration is released once used.
    let net = unsafe {
        let config = (api.configuration_create)(mode, &mut status);
        if config.is_null() {
            return Err(vmnet_error("vmnet_network_configuration_create", status));
        }
        let net = (api.network_create)(config, &mut status);
        CFRelease(config);
        net
    };
    if net.is_null() {
        return Err(vmnet_error("vmnet_network_create", status));
    }
    let mut subnet = libc::in_addr { s_addr: 0 };
    let mut mask = libc::in_addr { s_addr: 0 };
    // SAFETY: a valid network and two output addresses.
    unsafe { (api.get_ipv4_subnet)(net, &mut subnet, &mut mask) };
    let subnet = std::net::Ipv4Addr::from(u32::from_be(subnet.s_addr));
    let prefix = u32::from_be(mask.s_addr).count_ones();
    crate::logger::info!("vmnet: network {subnet}/{prefix} (mode {mode})");
    nets.push((mode, net as usize));
    Ok(net)
}

/// errno for a `vmnet_return_t`.
fn status_errno(status: u32) -> i32 {
    match status {
        1002 => libc::ENOMEM,
        1003 => libc::EINVAL,
        1004 => libc::EAGAIN,
        1005 => libc::EACCES,
        1006 => libc::EMSGSIZE,
        1007 => libc::ENOBUFS,
        1008 => libc::E2BIG,
        1009 => libc::EBUSY,
        1010 => libc::EPERM,
        _ => libc::EIO,
    }
}

fn status_name(status: u32) -> &'static str {
    match status {
        1001 => "VMNET_FAILURE",
        1002 => "VMNET_MEM_FAILURE",
        1003 => "VMNET_INVALID_ARGUMENT",
        1004 => "VMNET_SETUP_INCOMPLETE",
        1005 => "VMNET_INVALID_ACCESS",
        1006 => "VMNET_PACKET_TOO_BIG",
        1007 => "VMNET_BUFFER_EXHAUSTED",
        1008 => "VMNET_TOO_MANY_PACKETS",
        1009 => "VMNET_SHARING_SERVICE_BUSY",
        1010 => "VMNET_NOT_AUTHORIZED",
        _ => "unknown vmnet status",
    }
}

fn vmnet_error(call: &str, status: u32) -> io::Error {
    let errno = io::Error::from_raw_os_error(status_errno(status));
    io::Error::new(
        errno.kind(),
        format!("{call}: {} ({status}): {errno}", status_name(status)),
    )
}

/// A block literal (clang ABI) whose context is `C`. It is marked global, so
/// `Block_copy` returns it unchanged and it lives as long as its box.
#[repr(C)]
struct Block<C> {
    isa: *const c_void,
    flags: c_int,
    reserved: c_int,
    invoke: *const c_void,
    descriptor: *const BlockDescriptor,
    desc: BlockDescriptor,
    ctx: C,
}

#[repr(C)]
struct BlockDescriptor {
    reserved: usize,
    size: usize,
}

const BLOCK_IS_GLOBAL: c_int = 1 << 28;

impl<C> Block<C> {
    fn new(invoke: *const c_void, ctx: C) -> Box<Self> {
        let mut block = Box::new(Block {
            isa: ptr::addr_of!(_NSConcreteGlobalBlock).cast(),
            flags: BLOCK_IS_GLOBAL,
            reserved: 0,
            invoke,
            descriptor: null(),
            desc: BlockDescriptor {
                reserved: 0,
                size: std::mem::size_of::<Self>(),
            },
            ctx,
        });
        block.descriptor = &block.desc;
        block
    }

    fn as_ptr(&mut self) -> *mut c_void {
        ptr::from_mut(self).cast()
    }
}

/// A result handed over by a completion handler.
type Completion<T> = Arc<(Mutex<Option<T>>, Condvar)>;

fn complete<T>(done: &Completion<T>, value: T) {
    *done.0.lock().unwrap() = Some(value);
    done.1.notify_all();
}

fn wait<T>(done: &Completion<T>) -> Option<T> {
    let guard = done.0.lock().unwrap();
    let (mut guard, _) = done
        .1
        .wait_timeout_while(guard, TIMEOUT, |v| v.is_none())
        .unwrap();
    guard.take()
}

/// What `vmnet` reports about a started interface.
#[derive(Debug, Clone, Default)]
struct Params {
    mtu: u64,
    max_packet_size: u64,
    mac: Option<String>,
}

type StartBlock = Block<Completion<(u32, Params)>>;

extern "C" fn start_done(block: *mut StartBlock, status: u32, params: XpcObject) {
    let mut out = Params::default();
    if !params.is_null() {
        // SAFETY: `params` is a dictionary valid during the call; the keys are
        // vmnet's.
        unsafe {
            out.mtu = xpc_dictionary_get_uint64(params, vmnet_mtu_key);
            out.max_packet_size = xpc_dictionary_get_uint64(params, vmnet_max_packet_size_key);
            let mac = xpc_dictionary_get_string(params, vmnet_mac_address_key);
            if !mac.is_null() {
                out.mac = Some(CStr::from_ptr(mac).to_string_lossy().into_owned());
            }
        }
    }
    // SAFETY: vmnet passes the block it was given, which outlives the call.
    complete(unsafe { &(*block).ctx }, (status, out));
}

type StopBlock = Block<Completion<u32>>;

extern "C" fn stop_done(block: *mut StopBlock, status: u32) {
    // SAFETY: as in `start_done`.
    complete(unsafe { &(*block).ctx }, status);
}

type EventBlock = Block<RawFd>;

extern "C" fn on_event(block: *mut EventBlock, _mask: u32, _event: XpcObject) {
    // SAFETY: the block and its descriptor live until the callback is removed.
    let fd = unsafe { (*block).ctx };
    let byte = 1u8;
    // A full pipe already signals readability.
    // SAFETY: write of one byte from a local.
    unsafe { libc::write(fd, ptr::from_ref(&byte).cast(), 1) };
}

/// How an interface reaches the host's networks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// NAT to the host's networks.
    Shared,
    /// The host and other VMs only.
    Host,
    /// Bridged to the named host interface.
    Bridged(String),
}

impl Mode {
    fn value(&self) -> u32 {
        match self {
            Mode::Shared => VMNET_SHARED_MODE,
            Mode::Host => VMNET_HOST_MODE,
            Mode::Bridged(_) => VMNET_BRIDGED_MODE,
        }
    }
}

/// A started vmnet interface.
pub struct Interface {
    iface: InterfaceRef,
    queue: DispatchQueue,
    events: Box<EventBlock>,
    notify_rx: File,
    _notify_tx: File,
    /// The interface MTU.
    pub mtu: u64,
    /// The largest frame vmnet carries.
    pub max_packet_size: u64,
    /// The MAC address vmnet chose for the interface.
    pub mac: Option<String>,
}

impl std::fmt::Debug for Interface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Interface")
            .field("mtu", &self.mtu)
            .field("max_packet_size", &self.max_packet_size)
            .field("mac", &self.mac)
            .finish_non_exhaustive()
    }
}

// SAFETY: vmnet interface and dispatch queue references may be used from any
// thread; the event block is only read by the callback.
unsafe impl Send for Interface {}

fn pipe() -> io::Result<(File, File)> {
    let mut fds = [0; 2];
    // SAFETY: pipe into a local array.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the descriptors were just created and are owned here.
    let (rx, tx) = unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) };
    for fd in fds {
        // SAFETY: fcntl on descriptors owned here.
        unsafe {
            libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK);
            libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
        }
    }
    Ok((rx, tx))
}

impl Interface {
    /// Starts an interface.
    pub fn start(mode: &Mode) -> io::Result<Interface> {
        let (notify_rx, notify_tx) = pipe()?;
        // SAFETY: a serial queue with a static label.
        let queue = unsafe { dispatch_queue_create(c"firecracker.vmnet".as_ptr(), null()) };
        if queue.is_null() {
            return Err(io::Error::from_raw_os_error(libc::ENOMEM));
        }
        let mut iface = Interface {
            iface: null_mut(),
            queue,
            events: Block::new(on_event as *const c_void, notify_tx.as_raw_fd()),
            notify_rx,
            _notify_tx: notify_tx,
            mtu: 0,
            max_packet_size: 0,
            mac: None,
        };

        let done: Completion<(u32, Params)> = Arc::default();
        let mut block = Block::new(start_done as *const c_void, done.clone());
        // SAFETY: an empty dictionary.
        let desc = unsafe { xpc_dictionary_create(null(), null(), 0) };
        let started = (|| {
            let raw = match (mode, network_api()) {
                (Mode::Shared | Mode::Host, Some(api)) => {
                    let net = network(api, mode.value())?;
                    // SAFETY: valid network, dictionary, queue and block.
                    unsafe { (api.start_with_network)(net, desc, queue, block.as_ptr()) }
                }
                _ => {
                    // SAFETY: setting keys of a dictionary owned here.
                    unsafe {
                        xpc_dictionary_set_uint64(
                            desc,
                            vmnet_operation_mode_key,
                            u64::from(mode.value()),
                        );
                    }
                    if let Mode::Bridged(name) = mode {
                        let name = CString::new(name.as_str())
                            .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
                        // SAFETY: as above; xpc copies the string.
                        unsafe {
                            xpc_dictionary_set_string(
                                desc,
                                vmnet_shared_interface_name_key,
                                name.as_ptr(),
                            );
                        }
                    }
                    // SAFETY: valid dictionary, queue and block.
                    unsafe { vmnet_start_interface(desc, queue, block.as_ptr()) }
                }
            };
            Ok::<_, io::Error>(raw)
        })();
        // SAFETY: the dictionary is owned here; vmnet retains what it keeps.
        unsafe { xpc_release(desc) };
        let raw = started?;
        if raw.is_null() {
            // The handler may still run: keep its block.
            std::mem::forget(block);
            return Err(io::Error::other("vmnet: interface could not be created"));
        }
        let Some((status, params)) = wait(&done) else {
            std::mem::forget(block);
            return Err(io::Error::from(io::ErrorKind::TimedOut));
        };
        if status != VMNET_SUCCESS {
            return Err(vmnet_error("vmnet: starting the interface", status));
        }
        iface.iface = raw;
        iface.mtu = params.mtu;
        iface.max_packet_size = params.max_packet_size;
        iface.mac = params.mac;

        // SAFETY: valid interface, queue and block; the block lives in `iface`.
        let status = unsafe {
            vmnet_interface_set_event_callback(
                raw,
                VMNET_INTERFACE_PACKETS_AVAILABLE,
                queue,
                iface.events.as_ptr(),
            )
        };
        if status != VMNET_SUCCESS {
            return Err(vmnet_error("vmnet_interface_set_event_callback", status));
        }
        Ok(iface)
    }

    /// The descriptor that becomes readable when packets may have arrived.
    pub fn as_raw_fd(&self) -> RawFd {
        self.notify_rx.as_raw_fd()
    }

    /// Consumes the arrival notifications.
    pub fn drain_notifications(&self) {
        let mut buf = [0u8; 64];
        while matches!((&self.notify_rx).read(&mut buf), Ok(n) if n > 0) {}
    }

    /// Reads one frame into `iovs`; `None` if no frame is waiting.
    pub fn read(&self, iovs: &mut [libc::iovec]) -> io::Result<Option<usize>> {
        let mut desc = VmPktDesc {
            vm_pkt_size: iovs.iter().map(|v| v.iov_len).sum(),
            vm_pkt_iov: iovs.as_mut_ptr(),
            vm_pkt_iovcnt: u32::try_from(iovs.len()).map_err(|_| einval())?,
            vm_flags: 0,
        };
        let mut count = 1;
        // SAFETY: the descriptor names buffers the caller owns.
        let status = unsafe { vmnet_read(self.iface, &mut desc, &mut count) };
        if status != VMNET_SUCCESS {
            return Err(io::Error::from_raw_os_error(status_errno(status)));
        }
        Ok((count > 0).then_some(desc.vm_pkt_size))
    }

    /// Writes one frame.
    pub fn write(&self, frame: &[u8]) -> io::Result<()> {
        let mut iov = libc::iovec {
            iov_base: frame.as_ptr().cast_mut().cast(),
            iov_len: frame.len(),
        };
        let mut desc = VmPktDesc {
            vm_pkt_size: frame.len(),
            vm_pkt_iov: &mut iov,
            vm_pkt_iovcnt: 1,
            vm_flags: 0,
        };
        let mut count = 1;
        // SAFETY: vmnet only reads the buffer.
        let status = unsafe { vmnet_write(self.iface, &mut desc, &mut count) };
        if status != VMNET_SUCCESS {
            return Err(io::Error::from_raw_os_error(status_errno(status)));
        }
        if count == 0 {
            return Err(io::Error::from_raw_os_error(libc::ENOBUFS));
        }
        Ok(())
    }
}

fn einval() -> io::Error {
    io::Error::from_raw_os_error(libc::EINVAL)
}

impl Drop for Interface {
    fn drop(&mut self) {
        if !self.iface.is_null() {
            // SAFETY: valid interface; removing the callback before stopping.
            unsafe {
                vmnet_interface_set_event_callback(
                    self.iface,
                    VMNET_INTERFACE_PACKETS_AVAILABLE,
                    null_mut(),
                    null_mut(),
                );
            }
            let done: Completion<u32> = Arc::default();
            let mut block = Block::new(stop_done as *const c_void, done.clone());
            // SAFETY: valid interface, queue and block.
            let status = unsafe { vmnet_stop_interface(self.iface, self.queue, block.as_ptr()) };
            if status != VMNET_SUCCESS || wait(&done).is_none() {
                // The queue may still run the blocks: keep them.
                std::mem::forget(block);
                let events =
                    std::mem::replace(&mut self.events, Block::new(on_event as *const c_void, -1));
                std::mem::forget(events);
                return;
            }
        }
        // SAFETY: the queue was created here and has no work left.
        unsafe { dispatch_release(self.queue) };
    }
}

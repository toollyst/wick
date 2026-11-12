// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The API server's HTTP side in a process of its own, where the host
//! sandbox is per process (docs/PORTING.md, row 4).
//!
//! On Linux the API thread installs a seccomp filter of its own, narrower
//! than the VMM thread's (upstream's `api` filter): the code that reads the
//! API socket runs with only the calls an HTTP server needs. macOS and
//! Windows sandbox a process, not a thread. So the part of the API thread
//! that faces the socket runs in a process of its own, sandboxed with the
//! `api` filter's counterpart:
//!
//! - the API process ([`split`], a fork of Firecracker made while it has one
//!   thread) owns the HTTP server: it accepts connections, reads and parses
//!   requests (HTTP, then upstream's request parsing, so that every byte from
//!   the socket is parsed first under the API sandbox) and writes responses;
//! - Firecracker's API thread ([`ApiLink`]) gets each request from it, in a
//!   canonical form, and handles it with upstream's code (`ApiServer::
//!   handle_request`: the same parsing, logging, metrics and VMM requests as
//!   on Linux), and sends the response back.
//!
//! The two are joined by a Unix socket pair. If Firecracker ends, the API
//! process reads the end of it and exits. If the API process ends other
//! than by the API server's shutdown, Firecracker's API thread panics, as
//! the API thread's death ends Firecracker on Linux (upstream builds with
//! `panic = "abort"`).
//!
//! On Windows there is no fork: the API process is a second process from
//! Firecracker's binary (the `windows` module), made by Firecracker itself, or by the
//! jailer in a jail, with its end of the link and a handle to Firecracker
//! inherited; it finds them in its environment and serves before anything
//! else of Firecracker's start-up runs. Its sandbox is the whole mitigation
//! profile at once (`sandbox::apply_api`).
//!
//! Messages, each a 4-byte little-endian length and that many bytes:
//!
//! - API process to Firecracker: `R` + a request (`METHOD path HTTP/1.1`,
//!   `Content-Length`, the body: what upstream's handling reads of a
//!   request), `E` + an error message upstream's API thread logs, or `S` (the
//!   server shut down);
//! - Firecracker to the API process: a response ([`encode_response`]).

use std::io::{self, Read, Write};

use micro_http::{Body, MediaType, Method, Request, Response, StatusCode, Version};

/// What can go wrong between the two processes.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum ApiProcessError {
    /// The API process cannot be made while Firecracker has {0} threads: a fork copies only the calling one
    Threads(usize),
    /// Failed to make the API process: {0}
    Fork(io::Error),
    /// Failed to bind the API socket at {0}: {1}
    Bind(std::path::PathBuf, io::Error),
    /// The link to the API process failed: {0}
    Link(io::Error),
    /// A malformed message on the link to the API process: {0}
    Message(String),
}

/// What the API process sends.
#[derive(Debug)]
pub enum FromApi {
    /// A request read from the API socket.
    Request(Request),
    /// An error upstream's API thread logs.
    Error(String),
    /// The API server shut down (its kill switch).
    Shutdown,
}

const MAX_MESSAGE: usize = 1 << 30;

fn write_message(link: &mut impl Write, parts: &[&[u8]]) -> io::Result<()> {
    // The API process's report of a denied call ([`macos`]) is written
    // whole between two messages.
    #[cfg(target_os = "macos")]
    let _whole = macos::LINK_WRITE.lock().unwrap_or_else(|e| e.into_inner());
    let len: usize = parts.iter().map(|p| p.len()).sum();
    let len = u32::try_from(len).map_err(|_| io::Error::other("message too long"))?;
    let mut buf = Vec::with_capacity(4 + len as usize);
    buf.extend_from_slice(&len.to_le_bytes());
    for p in parts {
        buf.extend_from_slice(p);
    }
    link.write_all(&buf)?;
    link.flush()
}

/// Reads one message; `None` at the end of the link.
fn read_message(link: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match link.read_exact(&mut len) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err),
    }
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_MESSAGE {
        return Err(io::Error::other(format!("message of {len} bytes")));
    }
    let mut buf = vec![0u8; len];
    link.read_exact(&mut buf)?;
    Ok(Some(buf))
}

/// A request in the canonical form the API process sends: what upstream's
/// handling of a request reads (method, path, body).
pub fn encode_request(request: &Request) -> Vec<u8> {
    let body = request.body.as_ref().map(|b| b.raw()).unwrap_or(&[]);
    let mut out = format!(
        "{} {} HTTP/1.1\r\n",
        request.method().to_str(),
        request.uri().get_abs_path()
    )
    .into_bytes();
    if !body.is_empty() {
        out.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    out
}

/// The request [`encode_request`] encoded.
pub fn decode_request(bytes: &[u8]) -> Result<Request, ApiProcessError> {
    Request::try_from(bytes, None).map_err(|err| ApiProcessError::Message(format!("request: {err:?}")))
}

fn media_type(t: MediaType) -> u8 {
    match t {
        MediaType::PlainText => 0,
        MediaType::ApplicationJson => 1,
    }
}

fn status_code(raw: &[u8]) -> Option<StatusCode> {
    use StatusCode::*;
    [
        Continue,
        OK,
        NoContent,
        BadRequest,
        Unauthorized,
        NotFound,
        MethodNotAllowed,
        Conflict,
        PayloadTooLarge,
        TooManyRequests,
        InternalServerError,
        NotImplemented,
        ServiceUnavailable,
    ]
    .into_iter()
    .find(|s| s.raw() == raw)
}

fn put_str(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&u32::try_from(s.len()).unwrap().to_le_bytes());
    out.extend_from_slice(s);
}

/// A response, with everything of it upstream's API sets: status, content
/// type, deprecation, allowed methods, custom headers, body.
pub fn encode_response(response: &Response) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(response.status().raw());
    out.push(match response.http_version() {
        Version::Http10 => 0,
        Version::Http11 => 1,
    });
    out.push(media_type(response.content_type()));
    out.push(u8::from(response.deprecation()));
    let allow = response.allow();
    out.push(u8::try_from(allow.len()).unwrap());
    for m in allow {
        put_str(&mut out, m.raw());
    }
    let mut headers: Vec<_> = response.custom_headers().iter().collect();
    headers.sort();
    out.extend_from_slice(&u32::try_from(headers.len()).unwrap().to_le_bytes());
    for (k, v) in headers {
        put_str(&mut out, k.as_bytes());
        put_str(&mut out, v.as_bytes());
    }
    match response.body() {
        Some(body) => {
            out.push(1);
            put_str(&mut out, body.raw());
        }
        None => out.push(0),
    }
    out
}

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ApiProcessError> {
        if self.0.len() < n {
            return Err(ApiProcessError::Message("response: truncated".into()));
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }
    fn byte(&mut self) -> Result<u8, ApiProcessError> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<usize, ApiProcessError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()) as usize)
    }
    fn bytes(&mut self) -> Result<&'a [u8], ApiProcessError> {
        let n = self.u32()?;
        self.take(n)
    }
    fn string(&mut self) -> Result<String, ApiProcessError> {
        String::from_utf8(self.bytes()?.to_vec())
            .map_err(|_| ApiProcessError::Message("response: not UTF-8".into()))
    }
}

/// The response [`encode_response`] encoded.
pub fn decode_response(bytes: &[u8]) -> Result<Response, ApiProcessError> {
    let bad = |what: &str| ApiProcessError::Message(format!("response: {what}"));
    let mut c = Cursor(bytes);
    let status = status_code(c.take(3)?).ok_or_else(|| bad("status"))?;
    let version = match c.byte()? {
        0 => Version::Http10,
        1 => Version::Http11,
        _ => return Err(bad("version")),
    };
    let mut response = Response::new(version, status);
    let content_type = match c.byte()? {
        0 => MediaType::PlainText,
        1 => MediaType::ApplicationJson,
        _ => return Err(bad("content type")),
    };
    let deprecation = c.byte()? != 0;
    let mut allow = Vec::new();
    for _ in 0..c.byte()? {
        allow.push(Method::try_from(c.bytes()?).map_err(|_| bad("method"))?);
    }
    let mut headers = std::collections::HashMap::new();
    for _ in 0..c.u32()? {
        let k = c.string()?;
        headers.insert(k, c.string()?);
    }
    let body = match c.byte()? {
        0 => None,
        1 => Some(Body::new(c.bytes()?.to_vec())),
        _ => return Err(bad("body")),
    };
    if !c.0.is_empty() {
        return Err(bad("trailing bytes"));
    }
    if let Some(body) = body {
        response.set_body(body);
    }
    response.set_content_type(content_type);
    if deprecation {
        response.set_deprecation();
    }
    if !allow.is_empty() {
        response.set_allow(allow);
    }
    if !headers.is_empty() {
        response.set_custom_headers(&headers).map_err(|_| bad("custom headers"))?;
    }
    Ok(response)
}

/// Firecracker's end of the link: requests from the API process, responses
/// to it.
#[derive(Debug)]
pub struct ApiLink<S: Read + Write> {
    link: S,
}

impl<S: Read + Write> ApiLink<S> {
    /// A link over `link`.
    pub fn new(link: S) -> Self {
        Self { link }
    }

    /// What the API process sent next.
    ///
    /// # Panics
    /// If the API process ended without the server's shutdown, as the API
    /// thread's end ends Firecracker on Linux.
    pub fn receive(&mut self) -> Result<FromApi, ApiProcessError> {
        let msg = match read_message(&mut self.link) {
            Ok(Some(msg)) => msg,
            Ok(None) => {
                // A denied call ended it, but its report did not come.
                #[cfg(target_os = "macos")]
                if macos::api_process_was_denied() {
                    crate::logger::error_unrestricted!(
                        "The API server process ended after its sandbox denied a system call."
                    );
                    crate::ext::sandbox::denied_elsewhere();
                }
                panic!("The API server process ended")
            }
            // A Windows process that ends resets its connections rather
            // than closing them (`boot-test.ps1 api-process`).
            #[cfg(windows)]
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                ) =>
            {
                panic!("The API server process ended")
            }
            Err(err) => return Err(ApiProcessError::Link(err)),
        };
        match msg.split_first() {
            Some((b'R', rest)) => decode_request(rest).map(FromApi::Request),
            Some((b'E', rest)) => Ok(FromApi::Error(String::from_utf8_lossy(rest).into_owned())),
            Some((b'S', [])) => Ok(FromApi::Shutdown),
            // The API process's sandbox denied a call: Firecracker ends as
            // for one of its own, as the API thread's ends it on Linux. (The
            // API process could end Firecracker anyway, by ending the link.)
            #[cfg(target_os = "macos")]
            Some((b'D', [])) => {
                crate::logger::error_unrestricted!(
                    "The API server process's sandbox denied a system call."
                );
                crate::ext::sandbox::denied_elsewhere()
            }
            _ => Err(ApiProcessError::Message("unknown message".into())),
        }
    }

    /// Sends the response to the request [`Self::receive`] returned last.
    pub fn respond(&mut self, response: &Response) -> Result<(), ApiProcessError> {
        write_message(&mut self.link, &[&encode_response(response)]).map_err(ApiProcessError::Link)
    }
}

/// The API process's end of the link.
#[derive(Debug)]
pub struct ServerLink<S: Read + Write> {
    link: S,
}

impl<S: Read + Write> ServerLink<S> {
    /// A link over `link`.
    pub fn new(link: S) -> Self {
        Self { link }
    }

    /// Hands `request` to Firecracker and returns its response; `None` if
    /// Firecracker ended.
    pub fn handle(&mut self, request: &Request) -> Result<Option<Response>, ApiProcessError> {
        let fail = ApiProcessError::Link;
        write_message(&mut self.link, &[b"R", &encode_request(request)]).map_err(fail)?;
        match read_message(&mut self.link).map_err(fail)? {
            Some(msg) => decode_response(&msg).map(Some),
            None => Ok(None),
        }
    }

    /// Hands Firecracker an error to log.
    pub fn error(&mut self, message: &str) -> Result<(), ApiProcessError> {
        write_message(&mut self.link, &[b"E", message.as_bytes()]).map_err(ApiProcessError::Link)
    }

    /// Tells Firecracker the server shut down.
    pub fn shutdown(&mut self) -> Result<(), ApiProcessError> {
        write_message(&mut self.link, &[b"S"]).map_err(ApiProcessError::Link)
    }
}

/// Upstream's request parsing, which the API process runs on each request
/// before it hands it over (its result is not used: Firecracker's API thread
/// parses the request again, with upstream's logging and metrics). Set by
/// Firecracker's `main` before the jail ([`super::jail::enter`]), which may
/// make the API process.
static VALIDATE: std::sync::OnceLock<fn(&Request)> = std::sync::OnceLock::new();

/// Sets the parsing the API process runs ([`VALIDATE`]).
pub fn set_validator(validate: fn(&Request)) {
    let _ = VALIDATE.set(validate);
}

#[cfg(target_os = "macos")]
pub use macos::{set_waiting, split, wait_for_server, watch_child};

#[cfg(windows)]
pub use windows::{
    API_PROCESS_ENV, FIRECRACKER_ENV, LINK_ENV, WAITING_ENV, serve_if_api_process, split,
    take_waiting, wait_for_server,
};

#[cfg(target_os = "macos")]
mod macos {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
    use std::os::unix::net::UnixStream;
    use std::path::Path;
    use std::sync::Mutex;

    use micro_http::{HttpServer, ServerError};
    use vmm_sys_util::eventfd::EventFd;
    use vmm_sys_util::sock_ctrl_msg::ScmSocket;

    use super::{ApiLink, ApiProcessError, ServerLink, VALIDATE};
    use crate::ext::sandbox::{self, Policy};

    /// Held while a message is written to the link ([`super::write_message`]).
    pub(super) static LINK_WRITE: Mutex<()> = Mutex::new(());

    /// The API process's end of the link, for [`report_denied`].
    static LINK: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

    /// The API process's report that its sandbox denied a call (the
    /// waiter's, in place of upstream's handler): a `D` message, written
    /// whole between two others. The waiter then exits 148.
    fn report_denied() {
        let _whole = LINK_WRITE.lock().unwrap_or_else(|e| e.into_inner());
        let msg = [1u8, 0, 0, 0, b'D'];
        let fd = LINK.load(std::sync::atomic::Ordering::Acquire);
        let mut done = 0;
        while done < msg.len() {
            // SAFETY: the rest of `msg` to the link.
            let n = unsafe { libc::write(fd, msg[done..].as_ptr().cast(), msg.len() - done) };
            if n > 0 {
                done += n.unsigned_abs();
            } else if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                return;
            }
        }
    }

    /// A kqueue with the API process's exit (the fork's: its parent may ask
    /// for its exit status, xnu bsd/kern/kern_event.c `filt_procattach`),
    /// -1 when the jail made it.
    static CHILD_EXIT: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

    /// Watches the API process's exit, with its status: Firecracker forked
    /// it ([`split`], or the jail).
    pub fn watch_child(pid: libc::pid_t) {
        // SAFETY: no arguments.
        let kq = unsafe { libc::kqueue() };
        if kq < 0 {
            return;
        }
        let change = libc::kevent {
            ident: usize::try_from(pid).unwrap(),
            filter: libc::EVFILT_PROC,
            flags: libc::EV_ADD | libc::EV_ONESHOT,
            fflags: libc::NOTE_EXIT | libc::NOTE_EXITSTATUS,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        // SAFETY: one change, no output buffer.
        if unsafe { libc::kevent(kq, &change, 1, std::ptr::null_mut(), 0, std::ptr::null()) } == 0 {
            CHILD_EXIT.store(kq, std::sync::atomic::Ordering::Release);
        }
    }

    /// Whether the forked API process exited 148, the code of a denied call
    /// (its waiter's, when its report could not be written), waiting for its
    /// exit at most [`sandbox::SIGSYS_DEADLINE`] after the link's end.
    pub(super) fn api_process_was_denied() -> bool {
        let kq = CHILD_EXIT.load(std::sync::atomic::Ordering::Acquire);
        if kq < 0 {
            return false;
        }
        let d = sandbox::SIGSYS_DEADLINE;
        let timeout = libc::timespec {
            tv_sec: d.as_secs().try_into().unwrap(),
            tv_nsec: d.subsec_nanos().into(),
        };
        // SAFETY: a zeroed event for the output.
        let mut event: libc::kevent = unsafe { std::mem::zeroed() };
        // SAFETY: one output event, with the timeout.
        let n = unsafe { libc::kevent(kq, std::ptr::null(), 0, &mut event, 1, &timeout) };
        let status = i32::try_from(event.data).unwrap_or(0);
        n == 1
            && libc::WIFEXITED(status)
            && libc::WEXITSTATUS(status) == crate::FcExitCode::BadSyscall as i32
    }

    /// The API process the jail made (`ext::jail::enter`), which waits for
    /// its server.
    static WAITING: Mutex<Option<UnixStream>> = Mutex::new(None);

    /// Keeps the link to the API process the jail made.
    pub fn set_waiting(link: UnixStream) {
        *WAITING.lock().unwrap() = Some(link);
    }

    /// Threads of this process.
    fn threads() -> Result<usize, ApiProcessError> {
        // SAFETY: an all-zero proc_taskinfo is a valid output buffer.
        let mut info: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
        let size = i32::try_from(std::mem::size_of::<libc::proc_taskinfo>()).unwrap();
        // SAFETY: a valid output buffer of the size passed.
        let got = unsafe {
            libc::proc_pidinfo(
                libc::getpid(),
                libc::PROC_PIDTASKINFO,
                0,
                std::ptr::from_mut(&mut info).cast(),
                size,
            )
        };
        if got != size {
            return Err(ApiProcessError::Fork(std::io::Error::last_os_error()));
        }
        Ok(usize::try_from(info.pti_threadnum).unwrap())
    }

    /// Lets the API socket's connections raise SIGPIPE on a write after the
    /// client has gone, as on Linux, where upstream's handler counts it
    /// (`platform::socket`): cleared on the HTTP server's listener, made by
    /// std, before the API process has it, so every connection it accepts
    /// has it clear (xnu's `sonewconn` copies the flag).
    fn listener_raises_sigpipe(path: &Path) -> Result<(), ApiProcessError> {
        crate::platform::socket::sigpipe_as_linux(listener_fd(path)?)
            .map(drop)
            .map_err(|e| ApiProcessError::Bind(path.to_owned(), e))
    }

    /// The listening socket bound to `path` (the HTTP server's, which it
    /// does not hand out). macOS has no `SO_ACCEPTCONN` to read
    /// (`ENOPROTOOPT`); a listener is the socket bound there with no peer,
    /// as an accepted connection names the same path.
    fn listener_fd(path: &Path) -> Result<RawFd, ApiProcessError> {
        let canonical = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
        let want = canonical(path);
        // SAFETY: no arguments.
        let max = unsafe { libc::getdtablesize() };
        for fd in 0..max {
            // SAFETY: an all-zero sockaddr_un is a valid output buffer.
            let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
            let mut len =
                libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_un>()).unwrap();
            // SAFETY: a valid output buffer and its length.
            if unsafe { libc::getsockname(fd, std::ptr::from_mut(&mut addr).cast(), &mut len) } != 0
                || libc::c_int::from(addr.sun_family) != libc::AF_UNIX
            {
                continue;
            }
            // SAFETY: an all-zero sockaddr_un is a valid output buffer.
            let mut peer: libc::sockaddr_un = unsafe { std::mem::zeroed() };
            let mut peer_len =
                libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_un>()).unwrap();
            // SAFETY: a valid output buffer and its length.
            let connected =
                unsafe { libc::getpeername(fd, std::ptr::from_mut(&mut peer).cast(), &mut peer_len) };
            if connected == 0
                || std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOTCONN)
            {
                continue;
            }
            // SAFETY: sun_path is NUL-terminated (zeroed above, and the
            // kernel writes less than its size).
            let name = unsafe { std::ffi::CStr::from_ptr(addr.sun_path.as_ptr()) };
            if canonical(Path::new(std::ffi::OsStr::from_bytes(name.to_bytes()))) == want {
                return Ok(fd);
            }
        }
        Err(ApiProcessError::Message(format!("no listening socket at {}", path.display())))
    }

    /// Moves the HTTP server into a process of its own, sandboxed as
    /// upstream's API thread is filtered, and returns Firecracker's end of
    /// the link to it: the API process the jail made, given the server's
    /// socket and kill switch, or else a fork made now.
    ///
    /// A fork copies only the calling thread, so it needs Firecracker to have
    /// one thread (where upstream starts the API thread, it has): with more,
    /// the API process could inherit a lock another thread held; that fails.
    pub fn split(
        mut server: HttpServer,
        kill_switch: EventFd,
        socket_path: &Path,
        payload_limit: usize,
    ) -> Result<ApiLink<UnixStream>, ApiProcessError> {
        listener_raises_sigpipe(socket_path)?;
        if let Some(link) = WAITING.lock().unwrap().take() {
            let listener = listener_fd(socket_path)?;
            let mut msg = u64::try_from(payload_limit).unwrap().to_le_bytes().to_vec();
            msg.push(u8::from(sandbox::selected() == Policy::Default));
            link.send_with_fds(&[&msg[..]], &[listener, kill_switch.as_raw_fd()])
                .map_err(|e| ApiProcessError::Link(std::io::Error::other(e.to_string())))?;
            // The API process has its own descriptors now.
            drop(server);
            drop(kill_switch);
            return Ok(ApiLink::new(link));
        }
        let n = threads()?;
        if n != 1 {
            return Err(ApiProcessError::Threads(n));
        }
        let (ours, theirs) = UnixStream::pair().map_err(ApiProcessError::Link)?;
        // SAFETY: one thread (checked above), so the child is a whole copy.
        match unsafe { libc::fork() } {
            -1 => Err(ApiProcessError::Fork(std::io::Error::last_os_error())),
            0 => {
                drop(ours);
                // As upstream's API thread, the API process opens no
                // network interface: it keeps no way into the jail's network.
                // SAFETY: the child of a fork made with one thread.
                unsafe { crate::ext::jail::close_netns_in_child() };
                // The server's epoll is a kqueue here, which a fork does not
                // inherit.
                let result = server
                    .epoll()
                    .reopen_after_fork()
                    .map_err(ApiProcessError::Fork)
                    .and_then(|()| {
                        server
                            .add_kill_switch(kill_switch)
                            .map_err(|e| ApiProcessError::Message(format!("{e:?}")))
                    });
                exit(result.and_then(|()| serve(&mut server, theirs, payload_limit)))
            }
            child => {
                drop(theirs);
                drop(server);
                drop(kill_switch);
                watch_child(child);
                Ok(ApiLink::new(ours))
            }
        }
    }

    /// The API process the jail made: waits for its server ([`split`]), or
    /// ends with Firecracker if it never gets one (`--no-api`, an error).
    pub fn wait_for_server(link: UnixStream) -> ! {
        let mut buf = [0u8; 16];
        let mut fds = [-1 as RawFd; 2];
        let mut iov = [libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() }];
        // SAFETY: the iovec points at `buf`, which outlives the call.
        let got = unsafe { link.recv_with_fds(&mut iov, &mut fds) };
        let (len, nfds) = match got {
            Ok((0, _)) => exit(Ok(())),
            Ok(got) => got,
            Err(err) => exit(Err(ApiProcessError::Link(std::io::Error::other(err.to_string())))),
        };
        if len != 9 || nfds != 2 {
            exit(Err(ApiProcessError::Message(format!(
                "start: {len} bytes, {nfds} descriptors"
            ))));
        }
        let payload_limit =
            usize::try_from(u64::from_le_bytes(buf[..8].try_into().unwrap())).unwrap();
        sandbox::select(if buf[8] == 1 { Policy::Default } else { Policy::None });
        // SAFETY: the API socket's listening descriptor, received for this
        // server to own.
        let mut server = match unsafe { HttpServer::new_from_fd(fds[0]) } {
            Ok(server) => server,
            Err(err) => exit(Err(ApiProcessError::Message(format!("{err:?}")))),
        };
        // SAFETY: the kill switch's descriptor, received for it to own.
        let kill_switch = unsafe { EventFd::from_raw_fd(fds[1]) };
        let result = server
            .add_kill_switch(kill_switch)
            .map_err(|e| ApiProcessError::Message(format!("{e:?}")))
            .and_then(|()| serve(&mut server, link, payload_limit));
        exit(result)
    }

    /// Ends the API process (without Firecracker's exit code, which belongs
    /// to Firecracker).
    fn exit(result: Result<(), ApiProcessError>) -> ! {
        let code = match result {
            Ok(()) => 0,
            Err(err) => {
                eprintln!("The API server process failed: {err}");
                1
            }
        };
        // SAFETY: ends this process.
        unsafe { libc::_exit(code) }
    }

    /// Ends the API process when Firecracker ends, as the API thread ends
    /// with it on Linux: a thread that waits for Firecracker's exit (made
    /// before the sandbox, which has no thread creation; it then only waits
    /// in `kevent`).
    fn end_with_firecracker() -> Result<(), ApiProcessError> {
        let fail = |e| ApiProcessError::Fork(e);
        // SAFETY: no arguments.
        let firecracker = unsafe { libc::getppid() };
        // SAFETY: no arguments; the result is checked.
        let kq = unsafe { libc::kqueue() };
        if kq < 0 {
            return Err(fail(std::io::Error::last_os_error()));
        }
        let change = libc::kevent {
            ident: usize::try_from(firecracker).unwrap(),
            filter: libc::EVFILT_PROC,
            flags: libc::EV_ADD | libc::EV_ONESHOT,
            fflags: libc::NOTE_EXIT,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        // SAFETY: one change, no output buffer.
        let ret = unsafe { libc::kevent(kq, &change, 1, std::ptr::null_mut(), 0, std::ptr::null()) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ESRCH) {
                // Firecracker has ended already.
                exit(Ok(()));
            }
            return Err(fail(err));
        }
        // An orphan's parent is launchd: Firecracker ended before the kevent.
        // SAFETY: no arguments.
        if unsafe { libc::getppid() } != firecracker {
            exit(Ok(()));
        }
        // The thread's start (its QoS, bsdthread_ctl) is done before the
        // sandbox, which does not allow it: the thread says when it waits.
        let (started, wait) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .name("fc_api_watch".into())
            .spawn(move || {
                let _ = started.send(());
                loop {
                    // SAFETY: an output buffer for one event.
                    let mut event: libc::kevent = unsafe { std::mem::zeroed() };
                    // SAFETY: as above, waiting with no timeout.
                    let n = unsafe {
                        libc::kevent(kq, std::ptr::null(), 0, &mut event, 1, std::ptr::null())
                    };
                    if n > 0 {
                        exit(Ok(()));
                    }
                }
            })
            .map_err(fail)?;
        wait.recv().map_err(|_| fail(std::io::Error::other("the watching thread ended")))
    }

    fn serve(
        server: &mut HttpServer,
        link: UnixStream,
        payload_limit: usize,
    ) -> Result<(), ApiProcessError> {
        end_with_firecracker()?;
        // Firecracker's API thread logs; this process only parses.
        log::set_max_level(log::LevelFilter::Off);
        // A call its sandbox denies ends Firecracker, told over the link.
        LINK.store(link.as_raw_fd(), std::sync::atomic::Ordering::Release);
        sandbox::set_sigsys_report(report_denied);
        sandbox::apply_api().map_err(|e| ApiProcessError::Message(e.to_string()))?;
        #[cfg(test)]
        tests::misbehave();
        let validate = VALIDATE.get().copied();
        let mut link = ServerLink::new(link);
        server.set_payload_max_size(payload_limit);
        server.start_server().map_err(|e| ApiProcessError::Message(format!("{e:?}")))?;
        loop {
            let requests = match server.requests() {
                Ok(requests) => requests,
                Err(ServerError::ShutdownEvent) => {
                    server.flush_outgoing_writes();
                    return link.shutdown();
                }
                Err(err) => {
                    link.error(&format!("API Server error on retrieving incoming request: {err}"))?;
                    continue;
                }
            };
            for request in requests {
                let mut ended = false;
                let mut failed = None;
                let response = request.process(|request| {
                    if let Some(validate) = validate {
                        validate(request);
                    }
                    let status = |code| micro_http::Response::new(micro_http::Version::Http11, code);
                    match link.handle(request) {
                        Ok(Some(response)) => response,
                        Ok(None) => {
                            ended = true;
                            status(micro_http::StatusCode::ServiceUnavailable)
                        }
                        Err(err) => {
                            failed = Some(err);
                            status(micro_http::StatusCode::InternalServerError)
                        }
                    }
                });
                if ended {
                    return Ok(());
                }
                if let Some(err) = failed {
                    return Err(err);
                }
                if let Err(err) = server.respond(response) {
                    link.error(&format!("API Server encountered an error on response: {err}"))?;
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use std::os::unix::io::AsRawFd;
        use std::os::unix::net::{UnixListener, UnixStream};

        use super::listener_fd;

        #[test]
        fn test_listener_is_found_among_connections_to_it() {
            let dir = tempfile_dir();
            let path = dir.join("api.sock");
            let listener = UnixListener::bind(&path).unwrap();
            // A connection each way names the same path.
            let client = UnixStream::connect(&path).unwrap();
            let (accepted, _) = listener.accept().unwrap();
            assert_eq!(listener_fd(&path).unwrap(), listener.as_raw_fd());
            drop((client, accepted));
            listener_fd(&dir.join("other.sock")).unwrap_err();
            std::fs::remove_dir_all(&dir).unwrap();
        }

        // A write to a connection of the API socket after the client has
        // closed raises SIGPIPE, counted as on Linux (upstream's API thread
        // writes a response to a client that has gone).
        #[test]
        fn test_the_api_socket_raises_sigpipe() {
            crate::platform::socket::test_util::run_sigpipe_child(
                "ext::api_process::macos::tests::api_socket_sigpipe_child",
            );
        }

        #[test]
        #[ignore = "run by test_the_api_socket_raises_sigpipe in a separate process"]
        fn api_socket_sigpipe_child() {
            let dir = tempfile_dir();
            let path = dir.join("sigpipe.sock");
            let _server = micro_http::HttpServer::new(&path).unwrap();
            super::listener_raises_sigpipe(&path).unwrap();
            crate::platform::socket::test_util::sigpipe_child(|| {
                let client = UnixStream::connect(&path).unwrap();
                let listener = listener_fd(&path).unwrap();
                // SAFETY: a listening socket; no address asked for.
                let accepted = unsafe { libc::accept(listener, std::ptr::null_mut(), std::ptr::null_mut()) };
                assert!(accepted >= 0);
                drop(client);
                // SAFETY: one byte from a valid buffer, to the accepted socket.
                let n = unsafe { libc::write(accepted, b"x".as_ptr().cast(), 1) };
                assert_eq!(n, -1);
                assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EPIPE));
            });
            std::fs::remove_dir_all(&dir).unwrap();
        }

        /// A short directory: a Unix socket path is at most 104 bytes.
        fn tempfile_dir() -> std::path::PathBuf {
            let dir = std::path::PathBuf::from(format!("/tmp/wick-api-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            dir
        }

        /// What the API process of `api_violation_child` does once
        /// sandboxed (`WICK_TEST_API`): makes a call its sandbox denies
        /// (`getppid`, outside API_SYSCALLS), exits 148 without telling
        /// Firecracker, or is killed.
        pub(super) fn misbehave() {
            match std::env::var("WICK_TEST_API").as_deref() {
                Ok("deny") => {
                    // SAFETY: no arguments; denied, which raises SIGSYS.
                    unsafe { libc::getppid() };
                    // (A sleep's clock is not in the API sandbox either.)
                    loop {
                        std::thread::park();
                    }
                }
                // SAFETY: ends this process.
                Ok("exit148") => unsafe { libc::_exit(crate::FcExitCode::BadSyscall as i32) },
                // SAFETY: ends this process.
                Ok("kill") => unsafe {
                    libc::kill(libc::getpid(), libc::SIGKILL);
                },
                _ => {}
            }
        }

        /// Runs `case` as Firecracker would: its API process split off, the
        /// sandbox on, the API thread's loop. Returns the status, stdout
        /// (logs and metrics) and stderr.
        fn api_violation(case: &str) -> std::process::Output {
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "ext::api_process::macos::tests::api_violation_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env("WICK_TEST_API", case)
                .output()
                .unwrap()
        }

        fn text(out: &std::process::Output) -> String {
            format!(
                "{:?}\n--- stdout\n{}\n--- stderr\n{}",
                out.status,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
        }

        const FAULT_METRIC: &str = "\"seccomp\":{\"num_faults\":1}";

        // A call the API process's sandbox denies ends Firecracker with the
        // bad-syscall code, its log line and metrics, as a call the API
        // thread's filter traps does on Linux (it aborted: the API process
        // exited 148 alone, and Firecracker panicked at the link's end).
        #[test]
        fn test_a_denied_call_in_the_api_process_ends_firecracker_as_its_own() {
            let out = api_violation("deny");
            assert_eq!(out.status.code(), Some(crate::FcExitCode::BadSyscall as i32), "{}", text(&out));
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(stdout.contains("The API server process's sandbox denied a system call."), "{}", text(&out));
            assert!(stdout.contains(FAULT_METRIC), "{}", text(&out));
        }

        // If the report does not come (the API process exited 148 by its
        // deadline, or before it could write), Firecracker reads the forked
        // process's exit status and ends the same way.
        #[test]
        fn test_an_api_process_that_exits_148_ends_firecracker_as_its_own() {
            let out = api_violation("exit148");
            assert_eq!(out.status.code(), Some(crate::FcExitCode::BadSyscall as i32), "{}", text(&out));
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(stdout.contains("ended after its sandbox denied a system call"), "{}", text(&out));
            assert!(stdout.contains(FAULT_METRIC), "{}", text(&out));
        }

        // Any other end of the API process ends Firecracker as before: the
        // API thread panics (an abort, with upstream's panic = "abort").
        #[test]
        fn test_a_killed_api_process_ends_firecracker_with_a_panic() {
            let out = api_violation("kill");
            assert_eq!(out.status.code(), Some(101), "{}", text(&out));
            assert!(
                String::from_utf8_lossy(&out.stderr).contains("The API server process ended"),
                "{}",
                text(&out)
            );
        }

        #[test]
        #[ignore = "run by the test_*_api_process_* tests in a separate process"]
        fn api_violation_child() {
            use std::os::fd::FromRawFd;

            use crate::ext::sandbox::{self, Policy};
            use crate::logger::{LOGGER, METRICS};
            // In a fork, whose only thread is this one: the API process is
            // split off a process with one thread.
            // SAFETY: the fork runs Firecracker's side and ends; this
            // process waits for it and ends as it ended.
            match unsafe { libc::fork() } {
                0 => {}
                // SAFETY: the fork's pid; ends this process as it ended.
                pid => unsafe {
                    let mut status = 0;
                    libc::waitpid(pid, &mut status, 0);
                    if libc::WIFEXITED(status) {
                        libc::_exit(libc::WEXITSTATUS(status));
                    }
                    libc::_exit(128 + libc::WTERMSIG(status));
                },
            }
            let result = std::panic::catch_unwind(|| {
                crate::signal_handler::register_signal_handlers().unwrap();
                let _ = LOGGER.init();
                // SAFETY: a new descriptor of standard output, owned here.
                let out = unsafe { std::fs::File::from_raw_fd(libc::dup(1)) };
                METRICS.init(std::io::LineWriter::new(out)).unwrap();
                sandbox::select(Policy::Default);
                let dir = std::path::PathBuf::from(format!("/tmp/wick-apiv-{}", std::process::id()));
                std::fs::create_dir_all(&dir).unwrap();
                let path = dir.join("api.sock");
                let server = micro_http::HttpServer::new(&path).unwrap();
                let kill_switch = vmm_sys_util::eventfd::EventFd::new(libc::O_NONBLOCK).unwrap();
                let mut link = super::split(server, kill_switch, &path, 51200).unwrap();
                let _ = std::fs::remove_dir_all(&dir);
                // Firecracker's sandbox, as the API thread's filter is
                // applied (seccomp::apply_filter).
                sandbox::apply().unwrap();
                loop {
                    link.receive().unwrap();
                }
            });
            let message = result
                .err()
                .and_then(|p| {
                    p.downcast_ref::<&str>()
                        .map(|s| s.to_string())
                        .or_else(|| p.downcast_ref::<String>().cloned())
                })
                .unwrap_or_default();
            eprintln!("PANICKED: {message}");
            // SAFETY: ends the fork as a panic does in a test.
            unsafe { libc::_exit(101) }
        }
    }
}

/// The API process on Windows: a second process from Firecracker's binary.
///
/// The link between the two is a connection the API process accepts: it
/// listens on a Unix socket at a path it is given ([`LINK_ENV`]) and
/// Firecracker connects there. Each end's peer is then the other process,
/// which passing descriptors over the link needs (`sock_ctrl_msg`
/// duplicates handles into the peer `SIO_AF_UNIX_GETPEERPID` names); the
/// ends of a socket pair both name the process that made the pair, wherever
/// they are inherited. Without the jailer, [`split`] makes the API process
/// ([`spawn`]): `CreateProcess` of the running binary, before the sandbox's
/// child process policy is set, with the link's path and a `SYNCHRONIZE`
/// handle to Firecracker ([`FIRECRACKER_ENV`], inherited: the API process
/// ends with Firecracker, from before the link is made); the new process
/// finds them first thing (`ext::jail::enter`, [`serve_if_api_process`])
/// and listens. In a jail the jailer makes the API process the same way,
/// first, as a process of the jail (the same token, Job Object and drive),
/// listening inside the jail, and gives Firecracker the path and a handle to
/// it ([`WAITING_ENV`], [`API_PROCESS_ENV`]; [`take_waiting`]), on which
/// Firecracker's connecting waits. The first frame over the link carries the
/// server's listening socket and kill switch, as on macOS, and a
/// `SYNCHRONIZE` handle to Firecracker, which the API process ends with.
#[cfg(windows)]
mod windows {
    use std::ffi::OsStr;
    use std::io;
    use std::os::fd::from_handle;
    use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use micro_http::{HttpServer, ServerError};
    use vmm_sys_util::eventfd::EventFd;
    use vmm_sys_util::sock_ctrl_msg::ScmSocket;
    use windows_sys::Win32::Foundation::{
        CloseHandle, DuplicateHandle, HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation,
        WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::System::Threading::{
        CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
        EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, INFINITE,
        InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_INFORMATION, STARTF_USESTDHANDLES,
        STARTUPINFOEXW, UpdateProcThreadAttribute, WaitForSingleObject,
    };

    use super::{ApiLink, ApiProcessError, ServerLink, VALIDATE};
    use crate::ext::sandbox::{self, Policy};

    /// In the API process: the path of the socket it listens on for
    /// Firecracker.
    pub const LINK_ENV: &str = "WICK_API_LINK";
    /// In an API process Firecracker made: the handle value of a
    /// `SYNCHRONIZE` handle to Firecracker. The jailer makes the API process
    /// before Firecracker and sets none; that API process gets Firecracker's
    /// handle over the link.
    pub const FIRECRACKER_ENV: &str = "WICK_API_FIRECRACKER";
    /// In a jailed Firecracker: the path of the socket the API process the
    /// jailer made listens on.
    pub const WAITING_ENV: &str = "WICK_API_WAITING";
    /// In a jailed Firecracker: the handle value of a handle to that API
    /// process, `SYNCHRONIZE` (connecting waits on it) and
    /// `PROCESS_DUP_HANDLE` (the server's descriptors are duplicated into
    /// it: two processes of one jail may not open each other).
    pub const API_PROCESS_ENV: &str = "WICK_API_PROCESS";

    /// `SYNCHRONIZE` (winnt.h).
    const SYNCHRONIZE: u32 = 0x0010_0000;

    /// How long Firecracker keeps trying to connect to an API process that
    /// is alive but has not opened the link: it binds first thing, so this
    /// only bounds a process that cannot.
    const CONNECT_LIMIT: Duration = Duration::from_secs(30);

    // windows-sys gates it behind Win32_System_Console, which the vmm crate
    // does not otherwise need.
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetStdHandle(id: u32) -> HANDLE;
    }
    /// `STD_INPUT_HANDLE`, `STD_OUTPUT_HANDLE`, `STD_ERROR_HANDLE`.
    const STD_HANDLES: [u32; 3] = [-10i32 as u32, -11i32 as u32, -12i32 as u32];

    /// The API process the jail made (`ext::jail::enter`): where it listens,
    /// and a handle to it.
    static WAITING: Mutex<Option<(PathBuf, OwnedHandle)>> = Mutex::new(None);

    /// The API process this process made ([`spawn`]).
    static API_PROCESS: Mutex<Option<OwnedHandle>> = Mutex::new(None);

    fn bad_handle(what: &str, value: &OsStr) -> ApiProcessError {
        ApiProcessError::Message(format!("{what}: not a handle value: {}", value.to_string_lossy()))
    }

    fn handle_value(value: &OsStr) -> Option<HANDLE> {
        let v: usize = value.to_str()?.parse().ok()?;
        (v != 0).then_some(v as HANDLE)
    }

    /// A process handle whose value a parent put in the environment, for
    /// this process to own.
    fn process_from_env(what: &str, value: &OsStr) -> Result<OwnedHandle, ApiProcessError> {
        let h = handle_value(value).ok_or_else(|| bad_handle(what, value))?;
        // SAFETY: a handle this process inherited, for it to own.
        Ok(unsafe { OwnedHandle::from_raw_handle(h) })
    }

    /// Keeps what the jailer set for the API process it made, if it did
    /// ([`WAITING_ENV`] and [`API_PROCESS_ENV`], removed from the
    /// environment): where it listens, and a handle to it.
    ///
    /// # Safety
    ///
    /// Changes the environment: before any other thread exists.
    pub unsafe fn take_waiting() -> Result<(), ApiProcessError> {
        let Some(path) = std::env::var_os(WAITING_ENV) else {
            return Ok(());
        };
        let process = std::env::var_os(API_PROCESS_ENV)
            .ok_or_else(|| ApiProcessError::Message(format!("{API_PROCESS_ENV} is not set")))?;
        // SAFETY: the caller's.
        unsafe {
            std::env::remove_var(WAITING_ENV);
            std::env::remove_var(API_PROCESS_ENV);
        }
        let process = process_from_env("the API process's handle", &process)?;
        *WAITING.lock().unwrap() = Some((PathBuf::from(path), process));
        Ok(())
    }

    /// Serves as the API process if this process was started as one
    /// ([`LINK_ENV`] set): never returns then. Nothing otherwise.
    pub fn serve_if_api_process() -> Result<(), ApiProcessError> {
        let Some(path) = std::env::var_os(LINK_ENV) else {
            return Ok(());
        };
        let firecracker = std::env::var_os(FIRECRACKER_ENV);
        // SAFETY: called first thing in main, before any other thread exists.
        unsafe {
            std::env::remove_var(LINK_ENV);
            std::env::remove_var(FIRECRACKER_ENV);
        }
        let firecracker = firecracker
            .map(|value| process_from_env("Firecracker's handle", &value))
            .transpose()?;
        wait_for_server(Path::new(&path), firecracker)
    }

    fn inheritable(h: HANDLE) -> io::Result<()> {
        // SAFETY: a handle this process holds.
        if unsafe { SetHandleInformation(h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// A `SYNCHRONIZE` handle to this process, inheritable or not.
    fn own_process(inherit: bool) -> io::Result<OwnedHandle> {
        let mut h: HANDLE = std::ptr::null_mut();
        // SAFETY: duplicates this process's pseudo handle, for waiting only.
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                GetCurrentProcess(),
                GetCurrentProcess(),
                &mut h,
                SYNCHRONIZE,
                i32::from(inherit),
                0,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the handle just made.
        Ok(unsafe { OwnedHandle::from_raw_handle(h) })
    }

    fn wide(s: impl AsRef<OsStr>) -> Vec<u16> {
        s.as_ref().encode_wide().chain(std::iter::once(0)).collect()
    }

    /// `"<program>" "<arg>"...`, as the C runtime's parsing reads it back
    /// (no argument here holds a quote or ends with a backslash).
    fn command_line(program: &Path, args: &[&str]) -> String {
        std::iter::once(program.to_string_lossy().into_owned())
            .chain(args.iter().map(|a| (*a).to_owned()))
            .map(|a| format!("\"{a}\""))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// This process's environment plus `extra`, as a Unicode environment block.
    fn environment(extra: &[(&str, String)]) -> Vec<u16> {
        let mut block = Vec::new();
        for (k, v) in std::env::vars_os() {
            block.extend(k.encode_wide());
            block.push(u16::from(b'='));
            block.extend(v.encode_wide());
            block.push(0);
        }
        for (k, v) in extra {
            block.extend(format!("{k}={v}").encode_utf16());
            block.push(0);
        }
        block.push(0);
        block
    }

    /// A path of this process's own for the link, in the temporary
    /// directory.
    fn link_path() -> PathBuf {
        use std::hash::{BuildHasher, Hasher};
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_u32(std::process::id());
        std::env::temp_dir().join(format!("wick-api-{}-{:016x}", std::process::id(), h.finish()))
    }

    /// Makes the API process: this binary again, with `args`, the path it
    /// is to listen on and a handle to this process inherited, and connects
    /// to it. Returns Firecracker's end of the link and a handle to the
    /// process. Before the sandbox: its child process policy allows no
    /// process after it.
    fn spawn(args: &[&str]) -> Result<(UnixStream, OwnedHandle), ApiProcessError> {
        let fail = ApiProcessError::Fork;
        let path = link_path();
        let fc = own_process(true).map_err(fail)?;
        let fc_h = fc.as_raw_handle();
        let exe = std::env::current_exe().map_err(fail)?;
        let mut cmd = wide(command_line(&exe, args));
        let env = environment(&[
            (LINK_ENV, path.to_string_lossy().into_owned()),
            (FIRECRACKER_ENV, (fc_h as usize).to_string()),
        ]);
        // The handles it inherits: the one above and the standard handles.
        let mut handles = vec![fc_h];
        // SAFETY: plain calls.
        let std_handles = STD_HANDLES.map(|id| unsafe { GetStdHandle(id) });
        for h in std_handles {
            if !h.is_null() && h != -1isize as HANDLE && !handles.contains(&h) && inheritable(h).is_ok()
            {
                handles.push(h);
            }
        }
        let mut size = 0usize;
        // SAFETY: a size query.
        unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut size) };
        let mut attrs = vec![0u64; size.div_ceil(8)];
        let list: LPPROC_THREAD_ATTRIBUTE_LIST = attrs.as_mut_ptr().cast();
        // SAFETY: a buffer of the size asked for.
        if unsafe { InitializeProcThreadAttributeList(list, 1, 0, &mut size) } == 0 {
            return Err(fail(io::Error::last_os_error()));
        }
        // SAFETY: the handle array outlives the process creation.
        if unsafe {
            UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_ptr().cast(),
                std::mem::size_of_val(handles.as_slice()),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        } == 0
        {
            let err = io::Error::last_os_error();
            // SAFETY: initialised above.
            unsafe { DeleteProcThreadAttributeList(list) };
            return Err(fail(err));
        }
        // SAFETY: plain data.
        let mut si: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
        si.StartupInfo.cb = u32::try_from(std::mem::size_of::<STARTUPINFOEXW>()).unwrap();
        si.lpAttributeList = list;
        si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        si.StartupInfo.hStdInput = std_handles[0];
        si.StartupInfo.hStdOutput = std_handles[1];
        si.StartupInfo.hStdError = std_handles[2];
        // SAFETY: plain data.
        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: NUL-terminated application path, command line and
        // environment; the attribute list outlives the call.
        let created = unsafe {
            CreateProcessW(
                wide(&exe).as_ptr(),
                cmd.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                1,
                CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
                env.as_ptr().cast(),
                std::ptr::null(),
                &si.StartupInfo,
                &mut pi,
            )
        };
        let err = io::Error::last_os_error();
        // SAFETY: initialised above.
        unsafe { DeleteProcThreadAttributeList(list) };
        if created == 0 {
            return Err(fail(err));
        }
        // SAFETY: handles CreateProcess gave us.
        let process = unsafe {
            CloseHandle(pi.hThread);
            OwnedHandle::from_raw_handle(pi.hProcess)
        };
        // The API process has its own copy now.
        drop(fc);
        let link = connect(&path, &process)?;
        let kept = process.try_clone().map_err(fail)?;
        *API_PROCESS.lock().unwrap() = Some(kept);
        Ok((link, process))
    }

    /// Connects to the API process at `path`, where it listens once it has
    /// started: tried again while `process` runs, within [`CONNECT_LIMIT`].
    fn connect(path: &Path, process: &OwnedHandle) -> Result<UnixStream, ApiProcessError> {
        let start = Instant::now();
        loop {
            let err = match UnixStream::connect(path) {
                Ok(link) => return Ok(link),
                Err(err) => err,
            };
            // SAFETY: a handle we own; a short wait, which is the retry's pause.
            match unsafe { WaitForSingleObject(process.as_raw_handle(), 10) } {
                WAIT_TIMEOUT => {}
                WAIT_OBJECT_0 => {
                    return Err(ApiProcessError::Message(format!(
                        "the API process ended before opening its link (connecting to {}: {err})",
                        path.display()
                    )));
                }
                _ => return Err(ApiProcessError::Fork(io::Error::last_os_error())),
            }
            if start.elapsed() > CONNECT_LIMIT {
                return Err(ApiProcessError::Message(format!(
                    "the API process did not open its link at {} within {} s: {err}",
                    path.display(),
                    CONNECT_LIMIT.as_secs()
                )));
            }
        }
    }

    /// Binds the API socket and moves the HTTP server into a process of its
    /// own, sandboxed as upstream's API thread is filtered: the API process
    /// the jail made, or else one made now. Returns Firecracker's end of the
    /// link to it.
    pub fn split(
        kill_switch: EventFd,
        socket_path: &Path,
        payload_limit: usize,
    ) -> Result<ApiLink<UnixStream>, ApiProcessError> {
        split_with(&[], kill_switch, socket_path, payload_limit)
    }

    fn split_with(
        args: &[&str],
        kill_switch: EventFd,
        socket_path: &Path,
        payload_limit: usize,
    ) -> Result<ApiLink<UnixStream>, ApiProcessError> {
        let listener = UnixListener::bind(socket_path)
            .map_err(|e| ApiProcessError::Bind(socket_path.to_path_buf(), e))?;
        let waiting = WAITING.lock().unwrap().take();
        let (link, process) = match waiting {
            Some((path, process)) => (connect(&path, &process)?, process),
            None => spawn(args)?,
        };
        // The API process is the link's peer, by the handle: two processes
        // of one jail may not open each other by pid.
        vmm_sys_util::sock_ctrl_msg::set_peer_process(link.as_raw_fd(), process.as_raw_handle())
            .map_err(|e| ApiProcessError::Link(io::Error::other(e.to_string())))?;
        let mut msg = u64::try_from(payload_limit).unwrap().to_le_bytes().to_vec();
        msg.push(u8::from(sandbox::selected() == Policy::Default));
        // A handle to this process, for the API process to end with.
        let fc = own_process(false).map_err(ApiProcessError::Fork)?;
        let fc_fd = from_handle(fc.as_raw_handle());
        link.send_with_fds(&[&msg[..]], &[listener.as_raw_fd(), kill_switch.as_raw_fd(), fc_fd])
            .map_err(|e| ApiProcessError::Link(io::Error::other(e.to_string())))?;
        // The API process has its own handles now.
        drop(listener);
        drop(kill_switch);
        drop(fc);
        Ok(ApiLink::new(link))
    }

    /// The API process: listens at `path` for Firecracker, waits for its
    /// server ([`split`]), or ends with Firecracker if it never gets one
    /// (`--no-api`, an error; `firecracker` when its maker gave one, else
    /// the jail's Job Object, which ends with the jailer as Firecracker
    /// does).
    pub fn wait_for_server(path: &Path, firecracker: Option<OwnedHandle>) -> ! {
        let watched = match firecracker {
            Some(firecracker) => exit_on(end_with_firecracker(firecracker)),
            None => false,
        };
        // A listener left by an earlier process of the same name is nobody's.
        if let Err(err) = std::fs::remove_file(path) {
            if err.kind() != io::ErrorKind::NotFound {
                exit(Err(ApiProcessError::Bind(path.to_path_buf(), err)));
            }
        }
        let listener = match UnixListener::bind(path) {
            Ok(listener) => listener,
            Err(err) => exit(Err(ApiProcessError::Bind(path.to_path_buf(), err))),
        };
        let link = match listener.accept() {
            Ok((link, _)) => link,
            Err(err) => exit(Err(ApiProcessError::Link(err))),
        };
        drop(listener);
        exit_on(std::fs::remove_file(path).map_err(|e| ApiProcessError::Bind(path.to_path_buf(), e)));

        let mut buf = [0u8; 16];
        let mut fds = [-1 as RawFd; 3];
        let mut iov = [libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() }];
        // SAFETY: the iovec points at `buf`, which outlives the call.
        let got = unsafe { link.recv_with_fds(&mut iov, &mut fds) };
        let (len, nfds) = match got {
            Ok((0, _)) => exit(Ok(())),
            Ok(got) => got,
            Err(err) => exit(Err(ApiProcessError::Link(io::Error::other(err.to_string())))),
        };
        if len != 9 || nfds != 3 {
            exit(Err(ApiProcessError::Message(format!(
                "start: {len} bytes, {nfds} descriptors"
            ))));
        }
        let payload_limit =
            usize::try_from(u64::from_le_bytes(buf[..8].try_into().unwrap())).unwrap();
        sandbox::select(if buf[8] == 1 { Policy::Default } else { Policy::None });
        // SAFETY: the API socket's listening descriptor, received for this
        // server to own.
        let mut server = match unsafe { HttpServer::new_from_fd(fds[0]) } {
            Ok(server) => server,
            Err(err) => exit(Err(ApiProcessError::Message(format!("{err:?}")))),
        };
        // SAFETY: the kill switch's descriptor, received for it to own.
        let kill_switch = unsafe { EventFd::from_raw_fd(fds[1]) };
        // SAFETY: Firecracker's process handle, received for it to own.
        let firecracker = unsafe { OwnedHandle::from_raw_handle(std::os::fd::handle(fds[2])) };
        let firecracker = (!watched).then_some(firecracker);
        let result = server
            .add_kill_switch(kill_switch)
            .map_err(|e| ApiProcessError::Message(format!("{e:?}")))
            .and_then(|()| serve(&mut server, link, payload_limit, firecracker));
        exit(result)
    }

    /// `true`, or the API process ends with the error.
    fn exit_on(result: Result<(), ApiProcessError>) -> bool {
        match result {
            Ok(()) => true,
            Err(err) => exit(Err(err)),
        }
    }

    /// Ends the API process (without Firecracker's exit code, which belongs
    /// to Firecracker).
    fn exit(result: Result<(), ApiProcessError>) -> ! {
        let code = match result {
            Ok(()) => 0,
            Err(err) => {
                eprintln!("The API server process failed: {err}");
                1
            }
        };
        std::process::exit(code)
    }

    /// Ends the API process when Firecracker ends, as the API thread ends
    /// with it on Linux: a thread that waits on Firecracker's process handle.
    fn end_with_firecracker(firecracker: OwnedHandle) -> Result<(), ApiProcessError> {
        let fail = ApiProcessError::Fork;
        // SAFETY: a handle we own.
        match unsafe { WaitForSingleObject(firecracker.as_raw_handle(), 0) } {
            WAIT_OBJECT_0 => exit(Ok(())),
            WAIT_TIMEOUT => {}
            _ => return Err(fail(io::Error::last_os_error())),
        }
        std::thread::Builder::new()
            .name("fc_api_watch".into())
            .spawn(move || {
                // SAFETY: a handle we own, waited on for good.
                unsafe { WaitForSingleObject(firecracker.as_raw_handle(), INFINITE) };
                exit(Ok(()))
            })
            .map_err(fail)?;
        Ok(())
    }

    /// The API process's loop: the server's requests to Firecracker, its
    /// responses back (as on macOS). `firecracker` is the handle to end
    /// with, unless one is watched already.
    fn serve(
        server: &mut HttpServer,
        link: UnixStream,
        payload_limit: usize,
        firecracker: Option<OwnedHandle>,
    ) -> Result<(), ApiProcessError> {
        if let Some(firecracker) = firecracker {
            end_with_firecracker(firecracker)?;
        }
        // Firecracker's API thread logs; this process only parses.
        log::set_max_level(log::LevelFilter::Off);
        sandbox::apply_api().map_err(|e| ApiProcessError::Message(e.to_string()))?;
        let validate = VALIDATE.get().copied();
        let mut link = ServerLink::new(link);
        server.set_payload_max_size(payload_limit);
        server.start_server().map_err(|e| ApiProcessError::Message(format!("{e:?}")))?;
        loop {
            let requests = match server.requests() {
                Ok(requests) => requests,
                Err(ServerError::ShutdownEvent) => {
                    server.flush_outgoing_writes();
                    return link.shutdown();
                }
                Err(err) => {
                    link.error(&format!("API Server error on retrieving incoming request: {err}"))?;
                    continue;
                }
            };
            for request in requests {
                let mut ended = false;
                let mut failed = None;
                let response = request.process(|request| {
                    if let Some(validate) = validate {
                        validate(request);
                    }
                    let status = |code| micro_http::Response::new(micro_http::Version::Http11, code);
                    match link.handle(request) {
                        Ok(Some(response)) => response,
                        Ok(None) => {
                            ended = true;
                            status(micro_http::StatusCode::ServiceUnavailable)
                        }
                        Err(err) => {
                            failed = Some(err);
                            status(micro_http::StatusCode::InternalServerError)
                        }
                    }
                });
                if ended {
                    return Ok(());
                }
                if let Some(err) = failed {
                    return Err(err);
                }
                if let Err(err) = server.respond(response) {
                    link.error(&format!("API Server encountered an error on response: {err}"))?;
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use std::io::{Read, Write};

        use micro_http::{Body, Response, StatusCode, Version};
        use windows_sys::Win32::System::Threading::{
            GetExitCodeProcess, GetProcessMitigationPolicy, PROCESS_MITIGATION_POLICY,
        };

        use super::super::FromApi;
        use super::*;
        use crate::ext::sandbox::MITIGATIONS;

        fn flags_of(process: HANDLE, policy: PROCESS_MITIGATION_POLICY) -> u32 {
            let mut flags = 0u32;
            // SAFETY: a 4-byte buffer of the size passed.
            let ok = unsafe {
                GetProcessMitigationPolicy(process, policy, std::ptr::from_mut(&mut flags).cast(), 4)
            };
            assert_ne!(ok, 0, "{}", io::Error::last_os_error());
            flags
        }

        // The API process (this test binary, started by `split` as
        // Firecracker starts it) has the whole mitigation profile where this
        // process has none, serves a request through the link and ends with
        // the server's shutdown.
        #[test]
        fn test_the_api_process_serves_under_the_api_profile() {
            let dir = std::env::temp_dir().join(format!("wick-api-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("api.sock");
            sandbox::select(Policy::Default);
            let kill_switch = EventFd::new(0).unwrap();
            let mut link = split_with(
                &[
                    "--exact",
                    "ext::api_process::windows::tests::api_process_child",
                    "--ignored",
                    "--nocapture",
                ],
                kill_switch.try_clone().unwrap(),
                &path,
                1024,
            )
            .unwrap();
            sandbox::select(Policy::None);
            // A request, answered through the link.
            let client_path = path.clone();
            let client = std::thread::spawn(move || {
                let mut c = UnixStream::connect(&client_path).unwrap();
                c.write_all(b"GET /version HTTP/1.1\r\n\r\n").unwrap();
                let mut got = Vec::new();
                let mut buf = [0u8; 1024];
                loop {
                    let n = c.read(&mut buf).unwrap();
                    got.extend_from_slice(&buf[..n]);
                    if n == 0 || got.ends_with(b"{\"v\":1}") {
                        break;
                    }
                }
                String::from_utf8(got).unwrap()
            });
            match link.receive().unwrap() {
                FromApi::Request(r) => assert_eq!(r.uri().get_abs_path(), "/version"),
                other => panic!("{other:?}"),
            }
            let mut response = Response::new(Version::Http11, StatusCode::OK);
            response.set_body(Body::new("{\"v\":1}"));
            link.respond(&response).unwrap();
            let got = client.join().unwrap();
            // micro_http writes no reason phrase.
            assert!(got.starts_with("HTTP/1.1 200 "), "{got}");
            // The profile, in force in the API process and not here.
            let api = API_PROCESS.lock().unwrap().as_ref().unwrap().as_raw_handle();
            for m in MITIGATIONS {
                assert_eq!(flags_of(api, m.policy) & m.flags, m.flags, "{} in the API process", m.name);
                // SAFETY: plain call.
                let here = flags_of(unsafe { GetCurrentProcess() }, m.policy);
                assert_eq!(here & m.flags, 0, "{} here", m.name);
            }
            // The shutdown ends it, with success.
            kill_switch.write(1).unwrap();
            assert!(matches!(link.receive().unwrap(), FromApi::Shutdown));
            // SAFETY: a handle we own.
            let ended = unsafe { WaitForSingleObject(api, 10_000) };
            assert_eq!(ended, WAIT_OBJECT_0, "the API process did not end");
            let mut code = 1u32;
            // SAFETY: a handle we own, the process ended.
            unsafe { GetExitCodeProcess(api, &mut code) };
            assert_eq!(code, 0);
            std::fs::remove_dir_all(&dir).unwrap();
        }

        #[test]
        #[ignore = "run by test_the_api_process_serves_under_the_api_profile as the API process"]
        fn api_process_child() {
            serve_if_api_process().unwrap();
            panic!("not started as the API process");
        }

        // Firecracker's connecting waits for an API process that has not
        // bound its link yet, and ends with the process: a signalled
        // handle, as an ended process's is.
        #[test]
        fn test_connecting_ends_with_the_api_process() {
            use windows_sys::Win32::System::Threading::CreateEventW;
            // SAFETY: a manual-reset event, signalled from the start.
            let ended = unsafe { CreateEventW(std::ptr::null(), 1, 1, std::ptr::null()) };
            assert!(!ended.is_null(), "{}", io::Error::last_os_error());
            // SAFETY: the handle just made.
            let ended = unsafe { OwnedHandle::from_raw_handle(ended) };
            let path = link_path();
            let err = connect(&path, &ended).err().expect("nothing listens there");
            assert!(err.to_string().contains("ended before opening its link"), "{err}");
        }

        #[test]
        fn test_command_line_quotes_each_argument() {
            let line = command_line(Path::new(r"C:\a b\fc.exe"), &["--exact", "x y"]);
            assert_eq!(line, r#""C:\a b\fc.exe" "--exact" "x y""#);
        }

        #[test]
        fn test_handle_values() {
            assert!(handle_value(OsStr::new("0")).is_none());
            assert!(handle_value(OsStr::new("x")).is_none());
            assert_eq!(handle_value(OsStr::new("1234")).unwrap() as usize, 1234);
        }
    }
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;

    #[test]
    fn test_request_round_trip() {
        for raw in [
            &b"GET /machine-config HTTP/1.1\r\n\r\n"[..],
            b"PUT /drives/root HTTP/1.1\r\nContent-Length: 13\r\nContent-Type: application/json\r\n\r\n{\"a\": \"b c\"}\n",
            b"PATCH /vm HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}",
        ] {
            let request = Request::try_from(raw, None).unwrap();
            let back = decode_request(&encode_request(&request)).unwrap();
            assert_eq!(back.method(), request.method());
            assert_eq!(back.uri().get_abs_path(), request.uri().get_abs_path());
            assert_eq!(
                back.body.as_ref().map(|b| b.raw().to_vec()),
                request.body.as_ref().map(|b| b.raw().to_vec())
            );
        }
    }

    #[test]
    fn test_response_round_trip() {
        let mut full = Response::new(Version::Http11, StatusCode::MethodNotAllowed);
        full.set_body(Body::new("{\"fault_message\": \"x\"}"));
        full.set_deprecation();
        full.set_allow(vec![Method::Get, Method::Put]);
        let mut headers = std::collections::HashMap::new();
        headers.insert("X-A".to_string(), "1".to_string());
        full.set_custom_headers(&headers).unwrap();
        let mut plain = Response::new(Version::Http10, StatusCode::NoContent);
        plain.set_content_type(MediaType::PlainText);
        for response in [full, plain, Response::new(Version::Http11, StatusCode::OK)] {
            let back = decode_response(&encode_response(&response)).unwrap();
            // The bytes on the socket are the same.
            let (mut a, mut b) = (Vec::new(), Vec::new());
            response.write_all(&mut a).unwrap();
            back.write_all(&mut b).unwrap();
            assert_eq!(String::from_utf8_lossy(&a), String::from_utf8_lossy(&b));
        }
    }

    #[test]
    fn test_malformed_messages_are_errors() {
        let ok = encode_response(&Response::new(Version::Http11, StatusCode::OK));
        for bad in [&b""[..], b"999", &ok[..ok.len() - 1], &[&ok[..], b"x"].concat()] {
            decode_response(bad).unwrap_err();
        }
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut link = ApiLink::new(a);
        let mut other = b;
        write_message(&mut other, &[b"Z"]).unwrap();
        link.receive().unwrap_err();
    }

    #[test]
    fn test_link_round_trip() {
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut ours = ApiLink::new(a);
        let server = std::thread::spawn(move || {
            let mut theirs = ServerLink::new(b);
            let request = Request::try_from(b"GET /version HTTP/1.1\r\n\r\n", None).unwrap();
            theirs.error("an error").unwrap();
            let response = theirs.handle(&request).unwrap().unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            theirs.shutdown().unwrap();
        });
        assert!(matches!(ours.receive().unwrap(), FromApi::Error(e) if e == "an error"));
        match ours.receive().unwrap() {
            FromApi::Request(r) => assert_eq!(r.uri().get_abs_path(), "/version"),
            other => panic!("{other:?}"),
        }
        ours.respond(&Response::new(Version::Http11, StatusCode::OK)).unwrap();
        assert!(matches!(ours.receive().unwrap(), FromApi::Shutdown));
        server.join().unwrap();
    }

    #[test]
    #[should_panic(expected = "The API server process ended")]
    fn test_end_of_the_api_process_panics() {
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        drop(b);
        let _ = ApiLink::new(a).receive();
    }
}

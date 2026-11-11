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
        let Some(msg) = read_message(&mut self.link).map_err(ApiProcessError::Link)? else {
            panic!("The API server process ended");
        };
        match msg.split_first() {
            Some((b'R', rest)) => decode_request(rest).map(FromApi::Request),
            Some((b'E', rest)) => Ok(FromApi::Error(String::from_utf8_lossy(rest).into_owned())),
            Some((b'S', [])) => Ok(FromApi::Shutdown),
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
pub use macos::{set_waiting, split, wait_for_server};

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

    /// The listening socket bound to `path` (the HTTP server's, which it
    /// does not hand out).
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
            let mut listening: libc::c_int = 0;
            let mut optlen =
                libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>()).unwrap();
            // SAFETY: a valid output buffer and its length.
            let ret = unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_ACCEPTCONN,
                    std::ptr::from_mut(&mut listening).cast(),
                    &mut optlen,
                )
            };
            if ret != 0 || listening == 0 {
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
            _ => {
                drop(theirs);
                drop(server);
                drop(kill_switch);
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

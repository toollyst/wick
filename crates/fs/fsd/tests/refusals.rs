// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The wick-fsd binary on macOS (docs/design-fs.md §6.2): one refusal per
//! confinement step. Each refusal is real: the server runs with a library
//! the test builds and inserts (`DYLD_INSERT_LIBRARIES`, the macOS stand-in
//! for Linux's test filter in `server.rs`) that makes that step's call fail
//! or lie, or, for a profile already in force, applies one before `main`.
//! The server must then refuse to serve, naming the step. wick-fsd has no
//! switch that skips a step, and the library is only ever the test's.
//!
//! What they need: a wick-fsd dyld inserts libraries into, as cargo builds
//! it (an ad-hoc linker signature, no hardened runtime, no restricting
//! entitlement). A binary signed with the hardened runtime, or restricted,
//! has `DYLD_INSERT_LIBRARIES` ignored (dyld(1)); there each refusal test
//! fails as "served", never passes without its library.
//!
//! Not made to fail here, with why: the descriptor walk under the profile
//! (`fcntl(F_GETFD)` over every number below the soft limit) cannot be
//! made to lie for one call without lying for every `fcntl` the server
//! makes; the list before the profile, which the same equality checks, is
//! (`test_refused_when_a_descriptor_survives_its_close`).

#![cfg(target_os = "macos")]
// An integration test file is itself the test crate.
#![allow(clippy::tests_outside_test_module)]

mod common;

use std::path::{Path, PathBuf};

use common::remote::{Remote, Server, base_args, give_share};
use common::*;
use wick_fs_sys as sys;

/// The inserted library: `WICK_FSD_TEST_FAIL` picks what it does, and with
/// no value it changes nothing.
const LIBRARY: &str = r#"
#include <errno.h>
#include <grp.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

void *sandbox_compile_string(const char *profile, void *params, char **error);
int sandbox_apply(const void *profile);
int sandbox_init(const char *profile, uint64_t flags, char **error);

static int is(const char *m) {
    const char *v = getenv("WICK_FSD_TEST_FAIL");
    return v && strcmp(v, m) == 0;
}

static void *compile_fails(const char *profile, void *params, char **error) {
    if (is("compile")) { if (error) *error = NULL; errno = EINVAL; return NULL; }
    return sandbox_compile_string(profile, params, error);
}
static int apply_fails(const void *profile) {
    if (is("apply")) { errno = EPERM; return -1; }
    return sandbox_apply(profile);
}
/* The drop: a server that is not root is taken for root, so that it drops,
   and setgroups, its first call, is refused as the kernel refuses a user. */
static uid_t root_said(void) { return is("drop") ? 0 : geteuid(); }
static int setgroups_fails(int n, const gid_t *groups) {
    if (is("drop")) { errno = EPERM; return -1; }
    return setgroups(n, groups);
}
/* The listener's close said done and not done. The listener is the
   descriptor listen() was called on (no call at the close: under the
   profile one the server does not make would kill it there; and macOS's
   getsockopt has no SO_ACCEPTCONN, measured). */
static int listening = -1;
static int listen_noted(int fd, int backlog) {
    int r = listen(fd, backlog);
    if (r == 0) listening = fd;
    return r;
}
static int listener_kept(int fd) {
    if (is("listener") && fd == listening) { listening = -1; return 0; }
    return close(fd);
}
/* seteuid(0) said done: a saved id of 0 left, as the read-back sees it. */
static int seteuid_lies(uid_t uid) {
    if (is("saved") && uid == 0) return 0;
    return seteuid(uid);
}
/* Another profile, with a denial, in force before main. */
__attribute__((constructor)) static void another_profile(void) {
    if (is("profile")) {
        char *error = NULL;
        if (sandbox_init("(version 1)(allow default)(deny file-read-data (literal \"/private/var/empty/wick-none\"))", 0, &error) != 0) abort();
    }
}

__attribute__((used)) static const struct { const void *with, *instead; } interposed[]
    __attribute__((section("__DATA,__interpose"))) = {
    { (const void *)compile_fails, (const void *)sandbox_compile_string },
    { (const void *)apply_fails, (const void *)sandbox_apply },
    { (const void *)root_said, (const void *)geteuid },
    { (const void *)setgroups_fails, (const void *)setgroups },
    { (const void *)listen_noted, (const void *)listen },
    { (const void *)listener_kept, (const void *)close },
    { (const void *)seteuid_lies, (const void *)seteuid },
};
"#;

/// The library built into `dir` with the host's C compiler (Xcode's
/// command line tools, which building wick needs anyway), linked with
/// libsandbox for the two calls it wraps.
fn library(dir: &Path) -> PathBuf {
    let src = dir.join("insert.c");
    let lib = dir.join("insert.dylib");
    std::fs::write(&src, LIBRARY).unwrap();
    let mut cc = std::process::Command::new("cc");
    cc.args(["-dynamiclib", "-Wall", "-Werror", "-o"]).arg(&lib).arg(&src).arg("-lsandbox");
    let out = cc.output().unwrap_or_else(|e| panic!("{cc:?}: {e}"));
    assert!(
        out.status.success(),
        "{cc:?} ended {:?}\nstdout: {}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    lib
}

/// Runs a server with the library doing `what` and checks it refuses to
/// serve, naming `step`.
fn refused_when(tag: &str, what: &str, step: &str) {
    let base = scratch(tag);
    let share = base.join("share");
    std::fs::create_dir(&share).unwrap();
    give_share(&share);
    let lib = library(&base);
    let mut args = base_args(&share, &remote::socket_in(&base));
    if what == "drop" && sys::euid() != 0 {
        // Taken for root, it needs the ids to drop to, and its peer by
        // number (by default its own uid, which it takes for 0).
        args.extend(["--uid", "65534", "--gid", "65534", "--peer-uid"].map(String::from));
        args.push(sys::euid().to_string());
    }
    let server = Server::start(&args, |cmd| {
        cmd.env("DYLD_INSERT_LIBRARIES", &lib).env("WICK_FSD_TEST_FAIL", what);
    });
    match Remote::connect(server) {
        Ok(mut r) => {
            let (status, err) = r.finish();
            panic!("served with {what} ({status:?}): {err}");
        }
        Err((mut server, _)) => {
            let (status, err) = server.wait();
            assert_eq!(status.code(), Some(1), "{what}: {err}");
            assert!(err.contains(step), "{what}: expected a refusal naming {step:?}: {err}");
            assert!(err.contains("does not serve unconfined"), "{err}");
        }
    }
    remove(&base);
}

/// The library inserted and doing nothing: the server serves, so each
/// refusal below is the step's.
#[test]
fn test_the_inserted_library_alone_changes_nothing() {
    let base = scratch("ref-none");
    let share = base.join("share");
    std::fs::create_dir(&share).unwrap();
    give_share(&share);
    let lib = library(&base);
    let server = Server::start(&base_args(&share, &remote::socket_in(&base)), |cmd| {
        cmd.env("DYLD_INSERT_LIBRARIES", &lib).env("WICK_FSD_TEST_FAIL", "");
    });
    let mut r = Remote::connect(server).unwrap_or_else(|(mut s, why)| panic!("{why}: {:?}", s.wait()));
    remote::finish_clean(&mut r);
    remove(&base);
}

#[test]
fn test_refused_when_the_profile_does_not_compile() {
    refused_when("ref-compile", "compile", "confinement: compiling the profile failed");
}

#[test]
fn test_refused_when_the_profile_is_not_applied() {
    refused_when("ref-apply", "apply", "confinement: applying the profile failed");
}

#[test]
fn test_refused_when_the_id_drop_fails() {
    refused_when("ref-drop", "drop", "confinement: dropping to --uid/--gid failed");
}

#[test]
fn test_refused_when_a_descriptor_survives_its_close() {
    refused_when("ref-listener", "listener", "descriptors open that wick-fsd did not open or keep");
}

#[test]
fn test_refused_when_a_saved_id_is_left() {
    refused_when("ref-saved", "saved", "a saved id of 0 is left");
}

#[test]
fn test_refused_under_another_profile() {
    refused_when("ref-profile", "profile", "the profile is not in force: another Seatbelt profile was");
}

// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! docs/design-fs.md row 1 and §11 item 2: every name-taking opcode with
//! every name of the traversal corpus, against a real host directory. Every
//! refusal must come from layer 1 (the decoder's name check) or be an
//! ordinary error of the operation: a layer-2 refusal (`openat2`'s or
//! `O_RESOLVE_BENEATH`'s) means layer 1 let a name through and fails the
//! test, as does any change outside the share.

#![cfg(any(target_os = "linux", target_os = "macos"))]
// An integration test file is itself the test crate.
#![allow(clippy::tests_outside_test_module)]

mod common;

use std::os::unix::ffi::OsStrExt;

use common::*;
use wick_fsd::fuse::name::Name;
use wick_fsd::fuse::{Errno, Opcode};

/// §11 item 2's names, and a few more of the same kinds.
fn corpus() -> Vec<Vec<u8>> {
    let mut c: Vec<Vec<u8>> = [
        &b".."[..],
        b".",
        b"",
        b"a/b",
        b"/etc/x",
        b"../../x",
        b"../outside/secret",
        b"..\\outside",
        b"C:\\x",
        b"\\\\?\\C:\\x",
        b"\\??\\x",
        b"CON",
        b"con",
        b"NUL.txt",
        b"COM1",
        b"f:s",
        b"f::$DATA",
        b"d::$INDEX_ALLOCATION",
        b"PROGRA~1",
        b"dot.",
        b"space ",
        b" lead",
        b"...",
        b"a\0b",
        b"\xff\xfe",
        b"\xc0\xaf",
        b"e\xcc\x81",
        "\u{e9}".as_bytes(),
        b"Case",
        b"case",
        "\u{F03A}".as_bytes(),
        "\u{F02F}".as_bytes(),
        "\u{F001}x".as_bytes(),
        b"secret",
        b"outside",
    ]
    .iter()
    .map(|n| n.to_vec())
    .collect();
    c.push(vec![b'n'; 255]);
    c.push(vec![b'n'; 256]);
    c.push(vec![b'n'; 4096]);
    c
}

fn rn2(newdir: u64, flags: u32) -> Vec<u8> {
    [&le64(newdir)[..], &le32(flags), &le32(0)].concat()
}

#[test]
fn test_traversal_corpus() {
    traversal_corpus(&mut H::new("corpus"));
}

/// The corpus against a confined wick-fsd over its socket: the same
/// answers, the server never killed (on macOS a denial of its profile would
/// kill it), and no layer-2 or layer-3 refusal in the counters it reports at
/// the end.
#[test]
fn test_traversal_corpus_confined() {
    let (base, share, outside) = share_and_outside("corpus-confined", |_| {});
    let canaries = snapshot(&outside);
    let Some(r) = remote::confined_over(&share, &remote::socket_in(&base)) else {
        remove(&base);
        return;
    };
    let mut h = H::over(r, base, share, outside, canaries);
    traversal_corpus(&mut h);
    remote::finish_clean(&mut h.s);
}

fn traversal_corpus<L: Link>(h: &mut H<L>) {
    let (f, fh) = h.create(ROOT, b"file").unwrap();
    h.release(f, fh);
    let (x, xh) = h.create(ROOT, b"x").unwrap();
    h.release(x, xh);
    let sub = h.mkdir(ROOT, b"sub");
    let mut outcomes = Vec::new();
    for n in corpus() {
        let valid = Name::new(&n).is_ok();
        let shown = String::from_utf8_lossy(&n).into_owned();
        let mut results: Vec<(&str, i32)> = Vec::new();
        let mut run = |h: &mut H<L>, what: &'static str, op: Opcode, node: u64, args: &[&[u8]]| {
            let (e, _) = h.call(op, node, args);
            results.push((what, e));
            e
        };
        run(h, "lookup", Opcode::Lookup, ROOT, &[&name(&n)]);
        // The name without its NUL.
        run(h, "lookup without NUL", Opcode::Lookup, ROOT, &[&n]);
        let create = [&le32(2)[..], &le32(0o644), &le32(0), &le32(0)].concat();
        run(h, "create", Opcode::Create, ROOT, &[&create, &name(&n)]);
        run(h, "rename away", Opcode::Rename, ROOT, &[&le64(sub), &name(&n), &name(b"moved")]);
        run(h, "rename back", Opcode::Rename, sub, &[&le64(ROOT), &name(b"moved"), &name(&n)]);
        run(h, "rename onto", Opcode::Rename, ROOT, &[&le64(ROOT), &name(b"x"), &name(&n)]);
        run(h, "rename2 noreplace", Opcode::Rename2, ROOT, &[&rn2(ROOT, 1), &name(&n), &name(b"file")]);
        run(h, "rename2 exchange", Opcode::Rename2, ROOT, &[&rn2(ROOT, 2), &name(&n), &name(b"file")]);
        run(h, "rename2 exchange back", Opcode::Rename2, ROOT, &[&rn2(ROOT, 2), &name(&n), &name(b"file")]);
        run(h, "unlink", Opcode::Unlink, ROOT, &[&name(&n)]);
        run(h, "link", Opcode::Link, ROOT, &[&le64(f), &name(&n)]);
        run(h, "unlink link", Opcode::Unlink, ROOT, &[&name(&n)]);
        run(h, "mkdir", Opcode::Mkdir, ROOT, &[&le32(0o755), &le32(0), &name(&n)]);
        run(h, "mkdir beneath", Opcode::Mkdir, sub, &[&le32(0o755), &le32(0), &name(&n)]);
        run(h, "rmdir", Opcode::Rmdir, ROOT, &[&name(&n)]);
        run(h, "rmdir beneath", Opcode::Rmdir, sub, &[&name(&n)]);
        let fifo = [&le32(0o010_644)[..], &le32(0), &le32(0), &le32(0)].concat();
        run(h, "mknod", Opcode::Mknod, ROOT, &[&fifo, &name(&n)]);
        run(h, "unlink node", Opcode::Unlink, ROOT, &[&name(&n)]);
        run(h, "symlink name", Opcode::Symlink, ROOT, &[&name(&n), &name(b"target")]);
        run(h, "unlink symlink", Opcode::Unlink, ROOT, &[&name(&n)]);
        // A symlink's target is content, stored and never resolved.
        if !n.is_empty() && !n.contains(&0) && n.len() <= 4095 {
            let e = run(h, "symlink target", Opcode::Symlink, ROOT, &[&name(b"s"), &name(&n)]);
            if e == 0 {
                let s = u64_at(&h.lookup(ROOT, b"s").unwrap(), 0);
                assert_eq!(h.ok(Opcode::Readlink, s, &[]), n, "the target is kept as given");
                assert_eq!(h.open(s, 0), Err(Errno::ELOOP), "an emulated symlink is never opened");
                h.ok(Opcode::Unlink, ROOT, &[&name(b"s")]);
            }
        }
        run(h, "tmpfile", Opcode::Tmpfile, ROOT, &[&create, &name(&n)]);
        let set = |n: &[u8]| [&le32(1)[..], &le32(0), n, b"\0", b"v"].concat();
        let get = |n: &[u8]| [&le32(64)[..], &le32(0), n, b"\0"].concat();
        let user = [&b"user."[..], &n].concat();
        run(h, "setxattr", Opcode::Setxattr, f, &[&set(&n)]);
        run(h, "setxattr user.", Opcode::Setxattr, f, &[&set(&user)]);
        run(h, "getxattr", Opcode::Getxattr, f, &[&get(&n)]);
        run(h, "getxattr user.", Opcode::Getxattr, f, &[&get(&user)]);
        run(h, "removexattr", Opcode::Removexattr, f, &[&name(&n)]);
        run(h, "removexattr user.", Opcode::Removexattr, f, &[&name(&user)]);

        // Every name-taking request with a name layer 1 refuses fails.
        if !valid {
            for (what, e) in &results {
                if *what != "symlink target" && !what.contains("xattr") {
                    assert!(*e < 0, "{what} {shown:?}: a name layer 1 refuses went through");
                }
            }
        }
        // A name layer 1 lets through is an ordinary name inside the share:
        // made, renamed, linked and removed there.
        if valid {
            for what in [
                "create",
                "rename away",
                "rename back",
                "rename2 exchange",
                "rename2 exchange back",
                "unlink",
                "link",
                "mkdir",
                "rmdir",
                "mknod",
            ] {
                let e = results.iter().find(|r| r.0 == what).unwrap().1;
                assert_eq!(e, 0, "{what} {shown:?}: {:?}", errno(e));
            }
        }
        if valid {
            let e = results.iter().find(|r| r.0 == "rename2 noreplace").unwrap().1;
            assert_eq!(e, -17, "rename2 noreplace {shown:?}");
        }
        // No layer-2 refusal, ever: layer 1 must stop every escape.
        if let Some(n) = h.s.layer_refusals() {
            assert_eq!(n, 0, "after {shown:?}: {results:?}");
        }
        h.canaries_untouched();
        outcomes.push((shown, valid, results));
    }
    // Every host object the share holds now has a guest name, one level
    // or two deep, inside the share.
    let share = h.share.clone();
    for (path, _) in snapshot(&share) {
        if path == share {
            continue;
        }
        let rel = path.strip_prefix(&share).unwrap();
        assert!(rel.components().count() <= 2, "{}", rel.display());
        for c in rel.components() {
            let c = c.as_os_str().as_bytes();
            if let Err(e) = Name::new(c) {
                panic!("a host name that is no guest name: {:?} ({e:?})", String::from_utf8_lossy(c));
            }
        }
    }
    h.canaries_untouched();
    eprintln!("{} names, {} valid", outcomes.len(), outcomes.iter().filter(|o| o.1).count());
}

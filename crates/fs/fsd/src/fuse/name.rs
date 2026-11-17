// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! Guest names: layer 1 of docs/design-fs.md row 1, the same code on every
//! host.
//!
//! A name in a request is one component of the directory the request's node
//! is, never a path: [`Name::new`] takes the guest's bytes and refuses the
//! empty name, `.`, `..`, a `/` or a NUL anywhere, more than [`NAME_MAX`]
//! bytes and bytes that are not UTF-8 (APFS holds UTF-8 names only, so every
//! host takes the same set). It also refuses the code points
//! [`escape`] maps names to (U+F001–U+F01F, U+F022, U+F02A, U+F02F, U+F03A,
//! U+F03C, U+F03E, U+F03F, U+F05C, U+F07C): a host that has to escape a
//! character (Windows, as WSL's DrvFs does) writes its image, and a guest
//! name that was already an image would then be the same host name as the
//! one it is the image of. Refused on every host, so a share behaves the
//! same wherever it is served. U+F02F, the image of `/`, is refused too,
//! though no name holds a `/`: the rule is the whole image set, not one that
//! relies on another check.
//!
//! [`escape`] and [`unescape`] are pure and tested here on every host; only
//! the Windows backend calls them. A [`Name`] is always the guest's bytes.

use std::fmt;

use super::Errno;

/// The longest name, in bytes: Linux's `NAME_MAX`.
pub const NAME_MAX: usize = 255;

/// The characters a host that refuses them in names (NTFS) writes as
/// U+F000 plus the character, as WSL's DrvFs does: the controls 0x01–0x1F
/// and `" * : < > ? \ |`. `/` and NUL never reach a name.
fn escaped(c: char) -> bool {
    matches!(c, '\u{1}'..='\u{1f}' | '"' | '*' | ':' | '<' | '>' | '?' | '\\' | '|')
}

/// The first code point of the escape images; an image is this plus the
/// character it stands for.
const IMAGE_BASE: u32 = 0xF000;

/// Whether `c` is the image of a character [`escaped`] maps, or of `/`.
pub fn is_escape_image(c: char) -> bool {
    let c = u32::from(c);
    c > IMAGE_BASE
        && char::from_u32(c - IMAGE_BASE).is_some_and(|plain| escaped(plain) || plain == '/')
}

/// Why a name was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameError {
    /// No bytes.
    Empty,
    /// `.` or `..`.
    Dots,
    /// A `/` in the name.
    Slash,
    /// A NUL in the name.
    Nul,
    /// More than [`NAME_MAX`] bytes.
    TooLong,
    /// Not UTF-8.
    NotUtf8,
    /// An escape image ([`is_escape_image`]).
    EscapeImage,
}

impl NameError {
    /// The error the guest gets: `ENAMETOOLONG` for a long name, `EILSEQ`
    /// for one that is not UTF-8 (docs/design-fs.md §7, Names), `EINVAL`
    /// for the others.
    pub fn errno(self) -> Errno {
        match self {
            NameError::TooLong => Errno::ENAMETOOLONG,
            NameError::NotUtf8 => Errno::EILSEQ,
            NameError::Empty
            | NameError::Dots
            | NameError::Slash
            | NameError::Nul
            | NameError::EscapeImage => Errno::EINVAL,
        }
    }
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            NameError::Empty => "an empty name",
            NameError::Dots => "the name . or ..",
            NameError::Slash => "a name with a /",
            NameError::Nul => "a name with a NUL",
            NameError::TooLong => "a name longer than 255 bytes",
            NameError::NotUtf8 => "a name that is not UTF-8",
            NameError::EscapeImage => "a name with a code point that escaped names are written with",
        })
    }
}

impl std::error::Error for NameError {}

/// One component of a directory, as the guest sent it, checked.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Name<'a>(&'a str);

impl<'a> Name<'a> {
    /// Checks the guest's bytes (without their terminating NUL).
    pub fn new(bytes: &'a [u8]) -> Result<Name<'a>, NameError> {
        if bytes.is_empty() {
            return Err(NameError::Empty);
        }
        if bytes == b"." || bytes == b".." {
            return Err(NameError::Dots);
        }
        if bytes.contains(&b'/') {
            return Err(NameError::Slash);
        }
        if bytes.contains(&0) {
            return Err(NameError::Nul);
        }
        if bytes.len() > NAME_MAX {
            return Err(NameError::TooLong);
        }
        let name = std::str::from_utf8(bytes).map_err(|_| NameError::NotUtf8)?;
        if name.chars().any(is_escape_image) {
            return Err(NameError::EscapeImage);
        }
        Ok(Name(name))
    }

    /// The name.
    pub fn as_str(&self) -> &'a str {
        self.0
    }

    /// The name's bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for Name<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Name({:?})", self.0)
    }
}

/// The host name for `name` on a host that escapes: each of 0x01–0x1F and
/// `" * : < > ? \ |` becomes U+F000 plus the character. One-to-one on
/// names, since a [`Name`] holds no image.
pub fn escape(name: Name<'_>) -> String {
    name.as_str()
        .chars()
        .map(|c| {
            if escaped(c) {
                // An escaped character is below 0x80, so its image is a
                // code point of the Private Use Area.
                char::from_u32(IMAGE_BASE + u32::from(c)).unwrap_or(c)
            } else {
                c
            }
        })
        .collect()
}

/// Why a host name has no guest name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnescapeError {
    /// The host name holds a character [`escape`] never writes (one it
    /// escapes, or a `/` or NUL): two host names would show as one guest
    /// name.
    Unescaped,
    /// U+F02F, the image of `/`, which no guest name holds.
    SlashImage,
    /// The guest name it would be is not a [`Name`] (empty, `.`, `..`, or
    /// longer than [`NAME_MAX`] bytes).
    NotAName(NameError),
}

/// The guest name for a host name written by [`escape`]: the inverse of
/// [`escape`] on its image, and an error on every other host name, so that
/// no two host names show as the same guest name.
pub fn unescape(host: &str) -> Result<String, UnescapeError> {
    let mut out = String::with_capacity(host.len());
    for c in host.chars() {
        if escaped(c) || c == '/' || c == '\0' {
            return Err(UnescapeError::Unescaped);
        }
        if is_escape_image(c) {
            let plain = char::from_u32(u32::from(c) - IMAGE_BASE).unwrap_or(c);
            if plain == '/' {
                return Err(UnescapeError::SlashImage);
            }
            out.push(plain);
        } else {
            out.push(c);
        }
    }
    match Name::new(out.as_bytes()) {
        Ok(_) => Ok(out),
        Err(e) => Err(UnescapeError::NotAName(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IMAGES: &[u32] = &[
        0xF022, 0xF02A, 0xF02F, 0xF03A, 0xF03C, 0xF03E, 0xF03F, 0xF05C, 0xF07C,
    ];

    fn image_set() -> Vec<char> {
        (0xF001..=0xF01F)
            .chain(IMAGES.iter().copied())
            .map(|c| char::from_u32(c).unwrap())
            .collect()
    }

    #[test]
    fn test_name_refuses_what_is_not_one_component() {
        assert_eq!(Name::new(b""), Err(NameError::Empty));
        assert_eq!(Name::new(b"."), Err(NameError::Dots));
        assert_eq!(Name::new(b".."), Err(NameError::Dots));
        for bad in [&b"/"[..], b"/etc", b"a/b", b"../x", b"x/", b"//"] {
            assert_eq!(Name::new(bad), Err(NameError::Slash), "{bad:?}");
        }
        for bad in [&b"\0"[..], b"a\0", b"\0a", b"a\0b"] {
            assert_eq!(Name::new(bad), Err(NameError::Nul), "{bad:?}");
        }
        // Dotted names that are not . or .. are names.
        for good in [&b"..."[..], b".a", b"a.", b"..a", b". ", b" "] {
            assert_eq!(Name::new(good).map(|n| n.as_bytes()), Ok(good));
        }
    }

    #[test]
    fn test_name_length_bound() {
        let max = vec![b'a'; NAME_MAX];
        assert_eq!(Name::new(&max).unwrap().as_bytes().len(), NAME_MAX);
        let long = vec![b'a'; NAME_MAX + 1];
        assert_eq!(Name::new(&long), Err(NameError::TooLong));
        assert_eq!(NameError::TooLong.errno(), Errno::ENAMETOOLONG);
        // The bound is in bytes: 85 three-byte characters fit, 86 do not.
        let wide = "\u{AC00}".repeat(85);
        assert_eq!(Name::new(wide.as_bytes()).map(|n| n.as_str()), Ok(&wide[..]));
        let wider = "\u{AC00}".repeat(86);
        assert_eq!(Name::new(wider.as_bytes()), Err(NameError::TooLong));
    }

    #[test]
    fn test_name_refuses_bytes_that_are_not_utf8() {
        for bad in [&b"\xff"[..], b"a\x80", b"\xc3", b"\xed\xa0\x80", b"\xf4\x90\x80\x80"] {
            assert_eq!(Name::new(bad), Err(NameError::NotUtf8), "{bad:?}");
        }
        assert_eq!(NameError::NotUtf8.errno(), Errno::EILSEQ);
        assert_eq!(Name::new("é".as_bytes()).unwrap().as_str(), "é");
    }

    #[test]
    fn test_name_refuses_every_escape_image() {
        // The set the Windows owner gave (docs/design-fs.md, Q8 item 1),
        // and nothing else in the Private Use Area: each image alone and
        // inside a name is EINVAL; its neighbours are names.
        let images = image_set();
        assert_eq!(images.len(), 31 + IMAGES.len());
        for c in '\u{E000}'..='\u{F8FF}' {
            let alone = c.to_string();
            let inside = format!("a{c}b");
            if images.contains(&c) {
                assert!(is_escape_image(c));
                assert_eq!(Name::new(alone.as_bytes()), Err(NameError::EscapeImage));
                assert_eq!(Name::new(inside.as_bytes()), Err(NameError::EscapeImage));
            } else {
                assert!(!is_escape_image(c), "{:x}", u32::from(c));
                assert_eq!(Name::new(alone.as_bytes()).map(|n| n.as_str()), Ok(&alone[..]));
            }
        }
        assert_eq!(NameError::EscapeImage.errno(), Errno::EINVAL);
        // U+F000 is the image of NUL, which never reaches a name: not refused.
        assert_eq!(Name::new("\u{F000}".as_bytes()).map(|n| n.as_str()), Ok("\u{F000}"));
    }

    #[test]
    fn test_escape_maps_each_character_to_its_image() {
        let plain = "\u{1}\u{1f}\"*:<>?\\|";
        let name = Name::new(plain.as_bytes()).unwrap();
        assert_eq!(
            escape(name),
            "\u{F001}\u{F01F}\u{F022}\u{F02A}\u{F03A}\u{F03C}\u{F03E}\u{F03F}\u{F05C}\u{F07C}"
        );
        // Everything else is kept, including characters NTFS takes and
        // trailing dots and spaces (their handling is the Windows owner's,
        // from WSL's measured behaviour).
        let kept = "a b.é\u{7f}\u{F000}\u{F080}. ";
        assert_eq!(escape(Name::new(kept.as_bytes()).unwrap()), kept);
    }

    #[test]
    fn test_escape_round_trips_and_is_one_to_one() {
        // Every one-character name and every two-character name from the
        // characters around the escaped ones: unescape(escape(n)) == n, and
        // no two names escape to the same host name.
        let mut seen = std::collections::HashMap::new();
        let mut check = |s: &str| {
            let Ok(name) = Name::new(s.as_bytes()) else {
                return;
            };
            let host = escape(name);
            assert_eq!(unescape(&host).as_deref(), Ok(s), "{s:?}");
            if let Some(other) = seen.insert(host.clone(), s.to_string()) {
                panic!("{s:?} and {other:?} both escape to {host:?}");
            }
        };
        for c in (0..=0x10FFFF).filter_map(char::from_u32) {
            check(&c.to_string());
        }
        let around: Vec<char> = (0..0x80)
            .chain(0xEFFF..=0xF080)
            .chain([0xFFFD, 0x10FFFF])
            .filter_map(char::from_u32)
            .collect();
        for a in &around {
            for b in &around {
                check(&format!("{a}{b}"));
            }
        }
    }

    #[test]
    fn test_unescape_refuses_what_escape_never_writes() {
        // A raw escaped character, `/` or NUL on the host: another host
        // name would show as the same guest name.
        for c in ['\u{1}', '\u{1f}', '"', '*', ':', '<', '>', '?', '\\', '|', '/', '\0'] {
            assert_eq!(unescape(&format!("a{c}")), Err(UnescapeError::Unescaped), "{c:?}");
        }
        assert_eq!(unescape("\u{F02F}"), Err(UnescapeError::SlashImage));
        assert_eq!(unescape(""), Err(UnescapeError::NotAName(NameError::Empty)));
        assert_eq!(unescape(".."), Err(UnescapeError::NotAName(NameError::Dots)));
        assert_eq!(
            unescape(&"\u{AC00}".repeat(86)),
            Err(UnescapeError::NotAName(NameError::TooLong))
        );
        // An image is three bytes and the character one: 255 images are a
        // name of 255 bytes.
        assert_eq!(unescape(&"\u{F03A}".repeat(255)), Ok(":".repeat(255)));
        // escape(unescape(h)) == h wherever unescape takes h.
        for h in ["\u{F03A}x", "plain", "\u{F001}\u{F07C}", "\u{F000}"] {
            let guest = unescape(h).unwrap();
            assert_eq!(escape(Name::new(guest.as_bytes()).unwrap()), h);
        }
    }
}

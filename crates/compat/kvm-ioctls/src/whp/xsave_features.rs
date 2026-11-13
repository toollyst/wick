// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! A partition's `ProcessorXsaveFeatures` (`WHV_PROCESSOR_XSAVE_FEATURES`,
//! WinHvPlatformDefs.h), read from the Windows SDK's header itself.
//!
//! `windows-sys` declares the union as one `_bitfield: u64`, with no field
//! names; Microsoft Learn (WHvGetCapability) lists the fields. The layout a
//! partition is set with is the header's, so the record and the tests read
//! the header that the SDK installed ([`sdk_headers`]) and name each bit by
//! its field there ([`header_layout`]).
//!
//! Written without the crate's types, so that its tests run on any host:
//! `rustc --edition 2024 --test crates/compat/kvm-ioctls/src/whp/xsave_features.rs`.

use std::path::PathBuf;

/// One field of a C bitfield: its first bit, its width and its name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub bit: u32,
    pub width: u32,
    pub name: String,
}

/// The fields of `typedef union WHV_PROCESSOR_XSAVE_FEATURES` in a
/// WinHvPlatformDefs.h's text, in bit order from bit 0, as MSVC lays out a
/// `UINT64` bitfield (each field after the one before it, all in the one
/// 64-bit unit). An error names what the text lacks: no union, a field
/// whose width is not a number, or widths that do not add up to 64 bits.
pub fn header_layout(text: &str) -> Result<Vec<Field>, String> {
    const TYPE: &str = "WHV_PROCESSOR_XSAVE_FEATURES";
    // The typedef's end, `} WHV_PROCESSOR_XSAVE_FEATURES`, and the last
    // `typedef union` before it.
    let end = text
        .match_indices(TYPE)
        .map(|(at, _)| at)
        .find(|&at| text[..at].trim_end().ends_with('}'))
        .ok_or_else(|| format!("no `}} {TYPE}` in the header"))?;
    let start = text[..end].rfind("typedef union").ok_or_else(|| format!("no `typedef union` before `}} {TYPE}`"))?;
    let mut fields = Vec::new();
    let mut bit = 0u32;
    for line in text[start..end].lines() {
        let line = line.split("//").next().unwrap_or("").trim();
        // `UINT64 Name : width;`; `UINT64 AsUINT64;` has no width.
        let Some(decl) = line.strip_prefix("UINT64").and_then(|d| d.strip_suffix(';')) else { continue };
        let Some((name, width)) = decl.split_once(':') else { continue };
        let width: u32 = width.trim().parse().map_err(|_| format!("the field `{}` has a width of `{}`", name.trim(), width.trim()))?;
        fields.push(Field { bit, width, name: name.trim().to_string() });
        bit += width;
    }
    if bit != 64 {
        return Err(format!("the fields of {TYPE} come to {bit} bits, not 64"));
    }
    Ok(fields)
}

/// The fields of `layout` that `value` has, by name (a field wider than a
/// bit, such as `Reserved`, with its value).
pub fn names(layout: &[Field], value: u64) -> String {
    let mut out = Vec::new();
    for f in layout {
        let v = value >> f.bit & ((1u128 << f.width) - 1) as u64;
        match (v, f.width) {
            (0, _) => {}
            (_, 1) => out.push(f.name.clone()),
            _ => out.push(format!("{}={v:#x}", f.name)),
        }
    }
    out.join(", ")
}

/// Every Windows SDK's WinHvPlatformDefs.h on this host, newest first, each
/// with its SDK version: `WICK_WINHV_HEADER`'s file alone if that is set
/// (its version then the variable's name), else
/// `%ProgramFiles(x86)%\Windows Kits\10\Include\<version>\um\WinHvPlatformDefs.h`,
/// where the SDK installs it. Empty if there is none.
pub fn sdk_headers() -> Vec<(String, PathBuf)> {
    if let Some(path) = std::env::var_os("WICK_WINHV_HEADER") {
        return vec![("WICK_WINHV_HEADER".to_string(), PathBuf::from(path))];
    }
    let Some(kits) = std::env::var_os("ProgramFiles(x86)") else { return Vec::new() };
    let include = PathBuf::from(kits).join("Windows Kits").join("10").join("Include");
    let Ok(dirs) = std::fs::read_dir(&include) else { return Vec::new() };
    let mut found: Vec<(Vec<u32>, String, PathBuf)> = dirs
        .filter_map(|d| d.ok())
        .filter_map(|d| {
            let version = d.file_name().to_string_lossy().into_owned();
            let parts: Option<Vec<u32>> = version.split('.').map(|p| p.parse().ok()).collect();
            let path = d.path().join("um").join("WinHvPlatformDefs.h");
            Some((parts?, version, path)).filter(|(_, _, p)| p.is_file())
        })
        .collect();
    found.sort_by(|a, b| b.0.cmp(&a.0));
    found.into_iter().map(|(_, version, path)| (version, path)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // The union as the SDK writes it (braces on their own lines, a comment).
    const SAMPLE: &str = "
typedef union WHV_PROCESSOR_PERFMON_FEATURES
{
    struct { UINT64 PmuSupport : 1; UINT64 Reserved : 63; };
    UINT64 AsUINT64;
} WHV_PROCESSOR_PERFMON_FEATURES;

typedef union WHV_PROCESSOR_XSAVE_FEATURES
{
    struct
    {
        UINT64 XsaveSupport : 1;
        UINT64 XsaveoptSupport : 1; // a comment
        UINT64 AvxSupport : 1;
        UINT64 Reserved : 61;
    };

    UINT64 AsUINT64;
} WHV_PROCESSOR_XSAVE_FEATURES, *PWHV_PROCESSOR_XSAVE_FEATURES;

C_ASSERT(sizeof(WHV_PROCESSOR_XSAVE_FEATURES) == sizeof(UINT64));
";

    #[test]
    fn test_header_layout() {
        let layout = header_layout(SAMPLE).unwrap();
        let got: Vec<(u32, u32, &str)> = layout.iter().map(|f| (f.bit, f.width, f.name.as_str())).collect();
        assert_eq!(
            got,
            [(0, 1, "XsaveSupport"), (1, 1, "XsaveoptSupport"), (2, 1, "AvxSupport"), (3, 61, "Reserved")]
        );
        assert_eq!(names(&layout, 0b101), "XsaveSupport, AvxSupport");
        assert_eq!(names(&layout, 1 << 4), "Reserved=0x2");
        assert_eq!(names(&layout, 0), "");
    }

    #[test]
    fn test_header_layout_refuses_what_it_cannot_read() {
        assert!(header_layout("typedef union X { UINT64 A : 1; } X;").unwrap_err().contains("no `}"));
        let short = SAMPLE.replace("Reserved : 61", "Reserved : 60");
        assert!(header_layout(&short).unwrap_err().contains("63 bits"));
        let odd = SAMPLE.replace("AvxSupport : 1", "AvxSupport : ONE");
        assert!(header_layout(&odd).unwrap_err().contains("AvxSupport"));
    }
}

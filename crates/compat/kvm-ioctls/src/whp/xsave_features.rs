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
//! [`MAP`] is each field with the CPUID bit that names the feature, and
//! [`from_cpuid`] the fields a CPUID table has: from it a partition can be
//! given the components of a guest's CPUID, as KVM gives a guest those of
//! its leaf 0xD (Linux v6.1 x86.c, `__kvm_set_xcr`; `xcr`).
//!
//! Written without the crate's types, so that its tests run on any host:
//! `rustc --edition 2024 --test crates/compat/kvm-ioctls/src/whp/xsave_features.rs`,
//! with `WICK_WINHV_HEADER` naming a WinHvPlatformDefs.h where no SDK is
//! installed (on Windows the SDK's are found).

use std::path::PathBuf;

/// A CPUID register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reg {
    Eax,
    Ebx,
    Ecx,
    Edx,
}

/// Where a CPUID table says a processor has a field's feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cpuid {
    /// A bit of leaf `function`, sub-leaf `index`.
    Bit(u32, u32, Reg, u32),
    /// AVX10 version 1 or later (leaf 7.1 EDX bit 19; leaf 0x24 EBX bits
    /// 7:0, the version) with the vector length of leaf 0x24 EBX's bit
    /// given (17: 256 bits, 18: 512 bits).
    Avx10(u32),
}

/// One field of `WHV_PROCESSOR_XSAVE_FEATURES`: its bit, its name in
/// WinHvPlatformDefs.h, the CPUID bit of its feature (Linux v6.16
/// arch/x86/include/asm/cpufeatures.h and arch/x86/kvm/reverse_cpuid.h:
/// word 4 is leaf 1 ECX, 9 leaf 7.0 EBX, 10 leaf 0xD.1 EAX, 12 leaf 7.1
/// EAX, 16 leaf 7.0 ECX, 18 leaf 7.0 EDX), and the XCR0 state components
/// it works on (`XFEATURE_MASK_*`; 0 for one with a legacy-SSE form or no
/// state of its own).
pub struct Entry {
    pub bit: u32,
    pub name: &'static str,
    pub cpuid: Cpuid,
    pub state: u64,
}

const YMM: u64 = 1 << 2;
const MPX: u64 = 0b11 << 3;
const ZMM: u64 = YMM | 0b111 << 5;
const XTILE: u64 = 0b11 << 17;

const fn e(bit: u32, name: &'static str, cpuid: Cpuid, state: u64) -> Entry {
    Entry { bit, name, cpuid, state }
}

use Cpuid::{Avx10, Bit};
use Reg::{Eax, Ebx, Ecx, Edx};

/// Every field Microsoft Learn's WHvGetCapability lists, in bit order.
pub const MAP: [Entry; 38] = [
    e(0, "XsaveSupport", Bit(1, 0, Ecx, 26), 0),
    e(1, "XsaveoptSupport", Bit(0xd, 1, Eax, 0), 0),
    e(2, "AvxSupport", Bit(1, 0, Ecx, 28), YMM),
    e(3, "Avx2Support", Bit(7, 0, Ebx, 5), YMM),
    e(4, "FmaSupport", Bit(1, 0, Ecx, 12), YMM),
    e(5, "MpxSupport", Bit(7, 0, Ebx, 14), MPX),
    e(6, "Avx512Support", Bit(7, 0, Ebx, 16), ZMM),
    e(7, "Avx512DQSupport", Bit(7, 0, Ebx, 17), ZMM),
    e(8, "Avx512CDSupport", Bit(7, 0, Ebx, 28), ZMM),
    e(9, "Avx512BWSupport", Bit(7, 0, Ebx, 30), ZMM),
    e(10, "Avx512VLSupport", Bit(7, 0, Ebx, 31), ZMM),
    e(11, "XsaveCompSupport", Bit(0xd, 1, Eax, 1), 0),
    e(12, "XsaveSupervisorSupport", Bit(0xd, 1, Eax, 3), 0),
    e(13, "Xcr1Support", Bit(0xd, 1, Eax, 2), 0),
    e(14, "Avx512BitalgSupport", Bit(7, 0, Ecx, 12), ZMM),
    e(15, "Avx512IfmaSupport", Bit(7, 0, Ebx, 21), ZMM),
    e(16, "Avx512VBmiSupport", Bit(7, 0, Ecx, 1), ZMM),
    e(17, "Avx512VBmi2Support", Bit(7, 0, Ecx, 6), ZMM),
    e(18, "Avx512VnniSupport", Bit(7, 0, Ecx, 11), ZMM),
    e(19, "GfniSupport", Bit(7, 0, Ecx, 8), 0),
    e(20, "VaesSupport", Bit(7, 0, Ecx, 9), 0),
    e(21, "Avx512VPopcntdqSupport", Bit(7, 0, Ecx, 14), ZMM),
    e(22, "VpclmulqdqSupport", Bit(7, 0, Ecx, 10), 0),
    e(23, "Avx512Bf16Support", Bit(7, 1, Eax, 5), ZMM),
    e(24, "Avx512Vp2IntersectSupport", Bit(7, 0, Edx, 8), ZMM),
    e(25, "Avx512Fp16Support", Bit(7, 0, Edx, 23), ZMM),
    e(26, "XfdSupport", Bit(0xd, 1, Eax, 4), 0),
    e(27, "AmxTileSupport", Bit(7, 0, Edx, 24), XTILE),
    e(28, "AmxBf16Support", Bit(7, 0, Edx, 22), XTILE),
    e(29, "AmxInt8Support", Bit(7, 0, Edx, 25), XTILE),
    e(30, "AvxVnniSupport", Bit(7, 1, Eax, 4), YMM),
    e(31, "AvxIfmaSupport", Bit(7, 1, Eax, 23), YMM),
    e(32, "AvxNeConvertSupport", Bit(7, 1, Edx, 5), YMM),
    e(33, "AvxVnniInt8Support", Bit(7, 1, Edx, 4), YMM),
    e(34, "AvxVnniInt16Support", Bit(7, 1, Edx, 10), YMM),
    e(35, "Avx10_1_256Support", Avx10(17), ZMM),
    e(36, "Avx10_1_512Support", Avx10(18), ZMM),
    e(37, "AmxFp16Support", Bit(7, 1, Eax, 21), XTILE),
];

/// The fields of [`MAP`] that a CPUID table has: its feature's CPUID bit
/// set, and every state component it works on in the table's leaf 0xD
/// sub-leaf 0 (EDX:EAX), the components KVM lets the guest enable.
/// `leaf(function, index)` is the table's entry (EAX, EBX, ECX, EDX), `None`
/// where the table has none (read as zeros, as KVM reads a missing leaf).
pub fn from_cpuid(leaf: impl Fn(u32, u32) -> Option<[u32; 4]>) -> u64 {
    let get = |function, index| leaf(function, index).unwrap_or([0; 4]);
    let d0 = get(0xd, 0);
    let components = u64::from(d0[3]) << 32 | u64::from(d0[0]);
    let mut out = 0;
    for f in &MAP {
        let has = match f.cpuid {
            Bit(function, index, reg, bit) => get(function, index)[reg as usize] >> bit & 1 != 0,
            Avx10(length) => {
                let l24 = get(0x24, 0)[1];
                get(7, 1)[3] >> 19 & 1 != 0 && l24 & 0xff >= 1 && l24 >> length & 1 != 0
            }
        };
        if has && components & f.state == f.state {
            out |= 1 << f.bit;
        }
    }
    out
}

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

    // MAP against each Windows SDK's header on this host: every field the
    // header has is MAP's, at the same bit and by the same name, in MAP's
    // order from bit 0, and the rest of the header's 64 bits is one
    // `Reserved`. A header older than Learn's list then has a prefix of it.
    // No header is a failure, not a pass.
    #[test]
    fn test_map_is_the_sdk_headers_layout() {
        let headers = sdk_headers();
        assert!(
            !headers.is_empty(),
            "no WinHvPlatformDefs.h: none under %ProgramFiles(x86)%\\Windows Kits\\10\\Include\\<version>\\um, and \
             WICK_WINHV_HEADER is not set"
        );
        for (version, path) in headers {
            let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            let layout = header_layout(&text).unwrap_or_else(|e| panic!("SDK {version}: {e}"));
            let (reserved, fields) = layout.split_last().unwrap();
            assert_eq!(reserved.name, "Reserved", "SDK {version}: the last field");
            assert!(fields.len() <= MAP.len(), "SDK {version}: {} fields, MAP {}", fields.len(), MAP.len());
            for (h, m) in fields.iter().zip(&MAP) {
                assert_eq!((h.bit, h.width, h.name.as_str()), (m.bit, 1, m.name), "SDK {version}");
            }
            eprintln!("XSAVEFEAT SDK {version} {}: {} of MAP's {} fields", path.display(), fields.len(), MAP.len());
        }
    }

    // MAP's bits are 0 to 37, each once.
    #[test]
    fn test_map_bits_in_order() {
        for (i, f) in MAP.iter().enumerate() {
            assert_eq!(f.bit as usize, i, "{}", f.name);
        }
    }

    // A table with one entry's CPUID bit and the state it works on has that
    // field alone, or with the fields that share the same CPUID bit (none
    // do); without the state, not even that one.
    #[test]
    fn test_from_cpuid_one_field_at_a_time() {
        for f in &MAP {
            let mut leaves: Vec<((u32, u32), [u32; 4])> = vec![((0xd, 0), [(f.state & 0xffff_ffff) as u32, 0, 0, (f.state >> 32) as u32])];
            let mut set = |function, index, reg: Reg, bit: u32| {
                if let Some(l) = leaves.iter_mut().find(|l| l.0 == (function, index)) {
                    l.1[reg as usize] |= 1 << bit;
                } else {
                    let mut regs = [0; 4];
                    regs[reg as usize] = 1 << bit;
                    leaves.push(((function, index), regs));
                }
            };
            match f.cpuid {
                Bit(function, index, reg, bit) => set(function, index, reg, bit),
                Avx10(length) => {
                    set(7, 1, Edx, 19);
                    set(0x24, 0, Ebx, length);
                    set(0x24, 0, Ebx, 0);
                }
            }
            let table = |function, index| leaves.iter().find(|l| l.0 == (function, index)).map(|l| l.1);
            assert_eq!(from_cpuid(table), 1 << f.bit, "{}", f.name);
            if f.state != 0 {
                let without = |function, index| if (function, index) == (0xd, 0) { None } else { table(function, index) };
                assert_eq!(from_cpuid(without), 0, "{} without its state", f.name);
            }
        }
    }

    // AVX10 needs a version of 1 or later; an empty table has nothing.
    #[test]
    fn test_from_cpuid_avx10_version_and_an_empty_table() {
        let leaves = |version: u32| move |function, index| match (function, index) {
            (0xd, 0) => Some([0xe7, 0, 0, 0]),
            (7, 1) => Some([0, 0, 0, 1 << 19]),
            (0x24, 0) => Some([0, version | 0b11 << 17, 0, 0]),
            _ => None,
        };
        assert_eq!(from_cpuid(leaves(1)), 1 << 35 | 1 << 36);
        assert_eq!(from_cpuid(leaves(0)), 0);
        assert_eq!(from_cpuid(|_, _| None), 0);
    }

    // A table with AVX-512 and its BF16, without AMX or AVX-VNNI, whose
    // leaf 0xD has x87, SSE, AVX and AVX-512 (0xe7, the PC's: Ryzen 9 7900,
    // Windows 11 build 26300, its leaf 0xD.0 EAX under WHP), and the
    // same table with C3's leaf 0xD (x87, SSE, AVX): every AVX-512 field
    // goes, AVX and AVX2 stay.
    #[test]
    fn test_from_cpuid_of_an_avx512_table_and_of_a_template() {
        const L1_ECX: u32 = 1 << 26 | 1 << 28 | 1 << 12;
        const L7_EBX: u32 = 1 << 5 | 1 << 16 | 1 << 17 | 1 << 21 | 1 << 28 | 1 << 30 | 1 << 31;
        const L7_ECX: u32 = 1 << 1 | 1 << 6 | 1 << 8 | 1 << 9 | 1 << 10 | 1 << 11 | 1 << 12 | 1 << 14;
        let table = |xcr0: u32| move |function, index| match (function, index) {
            (1, 0) => Some([0, 0, L1_ECX, 0]),
            (7, 0) => Some([0, L7_EBX, L7_ECX, 0]),
            (7, 1) => Some([1 << 5, 0, 0, 0]),
            (0xd, 0) => Some([xcr0, 0, 0, 0]),
            (0xd, 1) => Some([0b1111, 0, 0, 0]),
            _ => None,
        };
        let names = |v: u64| MAP.iter().filter(|f| v >> f.bit & 1 != 0).map(|f| f.name).collect::<Vec<_>>();
        assert_eq!(
            names(from_cpuid(table(0xe7))),
            [
                "XsaveSupport", "XsaveoptSupport", "AvxSupport", "Avx2Support", "FmaSupport", "Avx512Support",
                "Avx512DQSupport", "Avx512CDSupport", "Avx512BWSupport", "Avx512VLSupport", "XsaveCompSupport",
                "XsaveSupervisorSupport", "Xcr1Support", "Avx512BitalgSupport", "Avx512IfmaSupport",
                "Avx512VBmiSupport", "Avx512VBmi2Support", "Avx512VnniSupport", "GfniSupport", "VaesSupport",
                "Avx512VPopcntdqSupport", "VpclmulqdqSupport", "Avx512Bf16Support",
            ]
        );
        assert_eq!(
            names(from_cpuid(table(0x7))),
            [
                "XsaveSupport", "XsaveoptSupport", "AvxSupport", "Avx2Support", "FmaSupport", "XsaveCompSupport",
                "XsaveSupervisorSupport", "Xcr1Support", "GfniSupport", "VaesSupport", "VpclmulqdqSupport",
            ]
        );
    }

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

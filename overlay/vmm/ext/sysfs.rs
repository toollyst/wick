// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The Linux sysfs files about the host that upstream Firecracker reads, on
//! macOS, which has no sysfs: each file's contents in Linux's format, from
//! the macOS source that says the same thing. A path not served here is not
//! found, as a file the host's kernel does not have is on Linux.
//!
//! The caches of `/sys/devices/system/cpu/cpu0/cache/index<N>`, which
//! Firecracker gives the guest in its device tree (`arch::aarch64::cache_info`):
//! - the leaves are those of the CLIDR_EL1 Hypervisor.framework gives a vCPU
//!   (`hv_vcpu_config_get_feature_reg`), in Linux's order (a level with
//!   separate caches is a data leaf, then an instruction leaf: Linux v6.1
//!   arch/arm64/kernel/cacheinfo.c `populate_cache_leaves`);
//! - `size` is XNU's (`hw.l1dcachesize`, `hw.l1icachesize`, `hw.l2cachesize`,
//!   `hw.l3cachesize`), in Linux's `<KiB>K` (drivers/base/cacheinfo.c
//!   `size_show`);
//! - `number_of_sets` and `coherency_line_size` are the vCPU's CCSIDR_EL1
//!   (`hv_vcpu_config_get_ccsidr_el1_sys_reg_values`), which no sysctl gives;
//!   sets times ways times line size must be XNU's size, or the leaf's files
//!   are not read and say why;
//! - `shared_cpu_map` has as many CPUs as XNU's `hw.cacheconfig` says share
//!   the level (Firecracker counts them, `mask_str2bit_count`), from cpu0 on,
//!   in Linux's bitmap format.
//!
//! XNU's top-level `hw.*` cache values are those of the lowest performance
//! level (xnu-12377.1.9 bsd/kern/kern_mib.c `sysctl_hw_generic`: `perflevel =
//! n_perflevels - 1`; `hw.cacheconfig`, `sysctl_mib_init`:
//! `min_perflevel_cluster_type`), which is also the geometry Hypervisor.framework
//! gives every vCPU in CCSIDR_EL1 (measured on an M1 Pro: 64 KiB, 128 KiB and
//! 4 MiB, its Efficiency cores'). Linux reads cpu0's; on that Mac cpu0 is an
//! Efficiency core (IODeviceTree `cpus/cpu0` `cluster-type` "E").

use std::io;

/// The file at `path`, as Linux's sysfs shows it, without its newline.
pub fn read(path: &str) -> io::Result<String> {
    let Some(rest) = path.strip_prefix("/sys/devices/system/cpu/cpu0/cache/index") else {
        return Err(io::ErrorKind::NotFound.into());
    };
    let (index, name) = rest.split_once('/').ok_or(io::ErrorKind::NotFound)?;
    let index: usize = index.parse().map_err(|_| io::ErrorKind::NotFound)?;
    let leaves = leaves(&Hvf::query()?)?;
    let leaf = leaves.get(index).ok_or(io::ErrorKind::NotFound)?;
    let value = match name {
        "level" => leaf.level.to_string(),
        "type" => leaf.kind.name().to_string(),
        "size" => format!("{}K", leaf.size()? >> 10),
        "coherency_line_size" => leaf.geometry()?.line.to_string(),
        "number_of_sets" => leaf.geometry()?.sets.to_string(),
        "shared_cpu_map" => bitmap(leaf.sharing()?, ncpu()?),
        _ => return Err(io::ErrorKind::NotFound.into()),
    };
    Ok(value)
}

/// A cache leaf's kind, as Linux names it in `type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Data,
    Instruction,
    Unified,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::Data => "Data",
            Kind::Instruction => "Instruction",
            Kind::Unified => "Unified",
        }
    }
}

/// A CCSIDR_EL1's geometry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Geometry {
    sets: u64,
    ways: u64,
    line: u64,
}

/// What Hypervisor.framework gives a vCPU: CLIDR_EL1, and CCSIDR_EL1 of
/// each level for data (and unified) caches and for instruction caches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Hvf {
    clidr: u64,
    ccidx: bool,
    data: [u64; 8],
    instruction: [u64; 8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Leaf {
    level: u8,
    kind: Kind,
    ccsidr: u64,
    ccidx: bool,
}

impl Leaf {
    /// XNU's size of the leaf's cache, in bytes.
    fn size(&self) -> io::Result<u64> {
        let name = match (self.level, self.kind) {
            (1, Kind::Data) => "hw.l1dcachesize",
            (1, Kind::Instruction) => "hw.l1icachesize",
            (2, Kind::Unified) => "hw.l2cachesize",
            (3, Kind::Unified) => "hw.l3cachesize",
            (level, kind) => {
                return Err(io::Error::other(format!(
                    "no sysctl gives the size of the level {level} {} cache",
                    kind.name()
                )));
            }
        };
        sysctl_u64(name)
    }

    /// The vCPU's CCSIDR_EL1 for the leaf, checked against XNU's size.
    fn geometry(&self) -> io::Result<Geometry> {
        let g = geometry(self.ccsidr, self.ccidx);
        let size = self.size()?;
        if g.sets * g.ways * g.line != size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "the level {} {} cache: CCSIDR_EL1 {:#x} ({} sets of {} ways of {} bytes) is not XNU's {size} bytes",
                    self.level,
                    self.kind.name(),
                    self.ccsidr,
                    g.sets,
                    g.ways,
                    g.line
                ),
            ));
        }
        Ok(g)
    }

    /// How many CPUs share the leaf's level (`hw.cacheconfig`).
    fn sharing(&self) -> io::Result<u64> {
        let mut config = [0u64; 10];
        let mut len = size_of_val(&config);
        // SAFETY: a NUL-terminated name, a buffer and its length.
        let r = unsafe {
            libc::sysctlbyname(
                c"hw.cacheconfig".as_ptr(),
                config.as_mut_ptr().cast(),
                &raw mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if r != 0 {
            return Err(io::Error::last_os_error());
        }
        match config.get(usize::from(self.level)) {
            Some(&n) if n > 0 && len >= (usize::from(self.level) + 1) * 8 => Ok(n),
            _ => Err(io::Error::other(format!(
                "hw.cacheconfig gives no CPU count for level {}",
                self.level
            ))),
        }
    }
}

/// The leaves CLIDR_EL1 describes, in Linux's order.
fn leaves(hvf: &Hvf) -> io::Result<Vec<Leaf>> {
    let mut leaves = Vec::new();
    for level in 1..=7u8 {
        let i = usize::from(level - 1);
        let leaf = |kind, ccsidr| Leaf { level, kind, ccsidr, ccidx: hvf.ccidx };
        match (hvf.clidr >> (3 * i)) & 7 {
            0 => break,
            1 => leaves.push(leaf(Kind::Instruction, hvf.instruction[i])),
            2 => leaves.push(leaf(Kind::Data, hvf.data[i])),
            3 => {
                leaves.push(leaf(Kind::Data, hvf.data[i]));
                leaves.push(leaf(Kind::Instruction, hvf.instruction[i]));
            }
            4 => leaves.push(leaf(Kind::Unified, hvf.data[i])),
            ctype => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("CLIDR_EL1 {:#x}: level {level} has the reserved Ctype {ctype}", hvf.clidr),
                ));
            }
        }
    }
    Ok(leaves)
}

/// A CCSIDR_EL1's geometry (Arm ARM D23.2 CCSIDR_EL1: with FEAT_CCIDX
/// NumSets is bits 55:32 and Associativity 23:3, without it 27:13 and
/// 12:3; LineSize is log2(bytes) - 4 in both).
fn geometry(ccsidr: u64, ccidx: bool) -> Geometry {
    let (sets, ways) = if ccidx {
        ((ccsidr >> 32) & 0xff_ffff, (ccsidr >> 3) & 0x1f_ffff)
    } else {
        ((ccsidr >> 13) & 0x7fff, (ccsidr >> 3) & 0x3ff)
    };
    Geometry { sets: sets + 1, ways: ways + 1, line: 1 << ((ccsidr & 7) + 4) }
}

/// Linux's `%*pb` of the lowest `n` of `cpus` CPUs: hexadecimal, in groups
/// of 32 bits separated by commas, as many digits as `cpus` needs (lib/
/// vsprintf.c `bitmap_string`).
fn bitmap(n: u64, cpus: u64) -> String {
    let digits = cpus.div_ceil(4).max(1);
    let mut out = String::new();
    for d in (0..digits).rev() {
        let bits = n.saturating_sub(d * 4).min(4);
        out.push(char::from_digit(((1u32 << bits) - 1) & 0xf, 16).unwrap());
        if d % 8 == 0 && d != 0 {
            out.push(',');
        }
    }
    out
}

fn ncpu() -> io::Result<u64> {
    sysctl_int("hw.ncpu")
}

fn sysctl_int(name: &str) -> io::Result<u64> {
    let cname = std::ffi::CString::new(name).map_err(io::Error::other)?;
    let mut v: libc::c_int = 0;
    let mut len = size_of_val(&v);
    // SAFETY: a NUL-terminated name, a buffer and its length.
    let r = unsafe { libc::sysctlbyname(cname.as_ptr(), (&raw mut v).cast(), &raw mut len, std::ptr::null_mut(), 0) };
    if r != 0 {
        let e = io::Error::last_os_error();
        return Err(io::Error::new(e.kind(), format!("{name}: {e}")));
    }
    u64::try_from(v).map_err(|e| io::Error::other(format!("{name}: {e}")))
}

fn sysctl_u64(name: &str) -> io::Result<u64> {
    let cname = std::ffi::CString::new(name).map_err(io::Error::other)?;
    let mut v: u64 = 0;
    let mut len = size_of_val(&v);
    // SAFETY: a NUL-terminated name, a buffer and its length.
    let r = unsafe { libc::sysctlbyname(cname.as_ptr(), (&raw mut v).cast(), &raw mut len, std::ptr::null_mut(), 0) };
    if r != 0 {
        let e = io::Error::last_os_error();
        return Err(io::Error::new(e.kind(), format!("{name}: {e}")));
    }
    if len != size_of_val(&v) || v == 0 {
        return Err(io::Error::other(format!("{name}: no size ({len} bytes, {v})")));
    }
    Ok(v)
}

type HvObject = *mut libc::c_void;

// Hypervisor.framework's vCPU configuration (hv_vcpu_config.h, macOS 11);
// the framework is linked by the compatibility kvm-ioctls. Read without a VM.
#[link(name = "Hypervisor", kind = "framework")]
unsafe extern "C" {
    fn hv_vcpu_config_create() -> HvObject;
    fn hv_vcpu_config_get_feature_reg(config: HvObject, reg: u32, value: *mut u64) -> i32;
    fn hv_vcpu_config_get_ccsidr_el1_sys_reg_values(config: HvObject, cache_type: u32, values: *mut u64) -> i32;
    fn os_release(object: HvObject);
}

/// `hv_feature_reg_t`: ID_AA64MMFR2_EL1 and CLIDR_EL1.
const HV_FEATURE_REG_ID_AA64MMFR2_EL1: u32 = 6;
const HV_FEATURE_REG_CLIDR_EL1: u32 = 10;
/// `hv_cache_type_t`.
const HV_CACHE_TYPE_DATA: u32 = 0;
const HV_CACHE_TYPE_INSTRUCTION: u32 = 1;
/// `hv_return_t` (hv_error.h): the host has no Hypervisor.framework, as a
/// virtual machine has none (`kern.hv_support` 0), and the call is refused.
const HV_UNSUPPORTED: i32 = 0xfae9_400f_u32.cast_signed();
const HV_DENIED: i32 = 0xfae9_4007_u32.cast_signed();

/// A status of the calls above, named as hv_error.h names it.
fn hv_status(r: i32) -> String {
    match r {
        HV_UNSUPPORTED => format!("HV_UNSUPPORTED ({r:#x}): this host has no Hypervisor.framework"),
        HV_DENIED => format!("HV_DENIED ({r:#x})"),
        _ => format!("{r:#x}"),
    }
}

impl Hvf {
    fn query() -> io::Result<Hvf> {
        let fail = |what: &str, r: i32| io::Error::other(format!("Hypervisor.framework {what}: {}", hv_status(r)));
        // SAFETY: plain calls into a configuration made here and released
        // before returning; each buffer is as large as the call writes.
        unsafe {
            let config = hv_vcpu_config_create();
            if config.is_null() {
                return Err(io::Error::other("Hypervisor.framework: no vCPU configuration"));
            }
            let mut hvf = Hvf { clidr: 0, ccidx: false, data: [0; 8], instruction: [0; 8] };
            let mut mmfr2 = 0;
            let result = (|| {
                let r = hv_vcpu_config_get_feature_reg(config, HV_FEATURE_REG_CLIDR_EL1, &mut hvf.clidr);
                if r != 0 {
                    return Err(fail("CLIDR_EL1", r));
                }
                let r = hv_vcpu_config_get_feature_reg(config, HV_FEATURE_REG_ID_AA64MMFR2_EL1, &mut mmfr2);
                if r != 0 {
                    return Err(fail("ID_AA64MMFR2_EL1", r));
                }
                let r = hv_vcpu_config_get_ccsidr_el1_sys_reg_values(config, HV_CACHE_TYPE_DATA, hvf.data.as_mut_ptr());
                if r != 0 {
                    return Err(fail("CCSIDR_EL1 (data)", r));
                }
                let r = hv_vcpu_config_get_ccsidr_el1_sys_reg_values(
                    config,
                    HV_CACHE_TYPE_INSTRUCTION,
                    hvf.instruction.as_mut_ptr(),
                );
                if r != 0 {
                    return Err(fail("CCSIDR_EL1 (instruction)", r));
                }
                Ok(())
            })();
            os_release(config);
            result?;
            // ID_AA64MMFR2_EL1.CCIDX, bits 23:20: the 64-bit CCSIDR_EL1.
            hvf.ccidx = (mmfr2 >> 20) & 0xf != 0;
            Ok(hvf)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CACHE: &str = "/sys/devices/system/cpu/cpu0/cache/index";

    // What Hypervisor.framework gave on an M1 Pro (macOS 27.2): L1 data
    // 128 sets x 8 ways x 64 bytes, L1 instruction 256 x 8 x 64, L2 2048 x
    // 16 x 128.
    const M1_PRO: Hvf = Hvf {
        clidr: 0x8100_0023,
        ccidx: false,
        data: [0x700f_e03a, 0x70ff_e07b, 0, 0, 0, 0, 0, 0],
        instruction: [0x201f_e03a, 0, 0, 0, 0, 0, 0, 0],
    };

    #[test]
    fn test_leaves_are_linux_order() {
        let found = leaves(&M1_PRO).unwrap();
        let shape: Vec<_> = found.iter().map(|l| (l.level, l.kind)).collect();
        assert_eq!(shape, [(1, Kind::Data), (1, Kind::Instruction), (2, Kind::Unified)]);
        let g: Vec<_> = found.iter().map(|l| geometry(l.ccsidr, l.ccidx)).collect();
        assert_eq!(
            g,
            [
                Geometry { sets: 128, ways: 8, line: 64 },
                Geometry { sets: 256, ways: 8, line: 64 },
                Geometry { sets: 2048, ways: 16, line: 128 },
            ]
        );
        let mut reserved = M1_PRO;
        reserved.clidr = 0x5;
        leaves(&reserved).unwrap_err();
    }

    #[test]
    fn test_ccidx_geometry() {
        // 2048 sets, 16 ways, 128-byte lines in the 64-bit format.
        let ccsidr = (2047u64 << 32) | (15 << 3) | 3;
        assert_eq!(geometry(ccsidr, true), Geometry { sets: 2048, ways: 16, line: 128 });
    }

    #[test]
    fn test_bitmap_is_linux_format() {
        assert_eq!(bitmap(1, 10), "001");
        assert_eq!(bitmap(2, 10), "003");
        assert_eq!(bitmap(10, 10), "3ff");
        assert_eq!(bitmap(4, 4), "f");
        assert_eq!(bitmap(33, 40), "01,ffffffff");
        assert_eq!(bitmap(1, 64), "00000000,00000001");
    }

    /// Whether this host has Hypervisor.framework: `kern.hv_support`, the
    /// sysctl Apple names for that question (xnu-12377.1.9
    /// bsd/kern/kern_sysctl.c, only in a kernel built with HYPERVISOR, so
    /// no such sysctl is no support; on arm64 the value is set outside the
    /// open source). 1 on an M1 Pro (macOS 27.2); that GitHub's runners,
    /// virtual machines, read 0 is inferred from their HV_UNSUPPORTED, and
    /// printed here so a run shows it.
    fn hv_support() -> bool {
        let support = match sysctl_int("kern.hv_support") {
            Ok(v) => v == 1,
            Err(e) if e.kind() == io::ErrorKind::NotFound => false,
            Err(e) => panic!("{e}"),
        };
        println!("kern.hv_support: {support}");
        support
    }

    /// Hypervisor.framework's view of the vCPU, which needs the framework
    /// but no entitlement. On a host without it (CI run 43442912128's
    /// runner: CLIDR_EL1 refused with HV_UNSUPPORTED) the query must fail
    /// and name that, which is what a file read gives there; `None` then.
    fn hvf_or_its_refusal() -> Option<Hvf> {
        if hv_support() {
            return Some(Hvf::query().unwrap());
        }
        let err = Hvf::query().unwrap_err().to_string();
        assert!(
            err.contains("HV_UNSUPPORTED") && err.contains("no Hypervisor.framework"),
            "kern.hv_support 0, and the query failed otherwise: {err}"
        );
        let read = read(&format!("{CACHE}0/level")).unwrap_err().to_string();
        assert_eq!(read, err);
        println!("kern.hv_support 0: refused as it should be: {err}");
        None
    }

    #[test]
    fn test_hv_status_names() {
        assert_eq!(hv_status(HV_UNSUPPORTED), "HV_UNSUPPORTED (0xfae9400f): this host has no Hypervisor.framework");
        assert_eq!(hv_status(HV_DENIED), "HV_DENIED (0xfae94007)");
        assert_eq!(hv_status(0xfae9_4001_u32.cast_signed()), "0xfae94001");
    }

    // This host's caches: each leaf's files, with sizes XNU's and geometry
    // the vCPU's, and nothing past the last leaf.
    #[test]
    fn test_host_caches() {
        let Some(hvf) = hvf_or_its_refusal() else { return };
        let found = leaves(&hvf).unwrap();
        assert!(!found.is_empty());
        for (i, leaf) in found.iter().enumerate() {
            let file = |name: &str| read(&format!("{CACHE}{i}/{name}")).unwrap();
            assert_eq!(file("level"), leaf.level.to_string());
            assert_eq!(file("type"), leaf.kind.name());
            let size = leaf.size().unwrap();
            assert_eq!(file("size"), format!("{}K", size >> 10));
            let sets: u64 = file("number_of_sets").parse().unwrap();
            let line: u64 = file("coherency_line_size").parse().unwrap();
            assert_eq!(size % (sets * line), 0, "{leaf:?}");
            let map = file("shared_cpu_map");
            let bits: u32 = map
                .split(',')
                .map(|g| u32::from_str_radix(g, 16).unwrap().count_ones())
                .sum();
            assert_eq!(u64::from(bits), leaf.sharing().unwrap(), "{map}");
            println!("index{i}: level {} {} {}K, {sets} sets, {line}-byte lines, {map}", leaf.level, leaf.kind.name(), size >> 10);
        }
        let past = found.len();
        assert_eq!(read(&format!("{CACHE}{past}/level")).unwrap_err().kind(), io::ErrorKind::NotFound);
        assert_eq!(read(&format!("{CACHE}0/ways_of_associativity")).unwrap_err().kind(), io::ErrorKind::NotFound);
        assert_eq!(read("/sys/devices/system/cpu/cpu1/cache/index0/level").unwrap_err().kind(), io::ErrorKind::NotFound);
    }

    // The sizes are the lowest performance level's, as kern_mib.c gives
    // them: XNU only, on every host.
    #[test]
    fn test_sizes_are_the_lowest_perflevel() {
        let low = sysctl_int("hw.nperflevels").unwrap() - 1;
        let level = |name: &str| sysctl_int(&format!("hw.perflevel{low}.{name}")).unwrap();
        assert_eq!(sysctl_u64("hw.l1dcachesize").unwrap(), level("l1dcachesize"));
        assert_eq!(sysctl_u64("hw.l1icachesize").unwrap(), level("l1icachesize"));
        assert_eq!(sysctl_u64("hw.l2cachesize").unwrap(), level("l2cachesize"));
    }

    // The vCPU's CCSIDR_EL1 describes caches of XNU's sizes.
    #[test]
    fn test_vcpu_geometry_is_xnus_sizes() {
        let Some(hvf) = hvf_or_its_refusal() else { return };
        for leaf in &leaves(&hvf).unwrap() {
            leaf.geometry().unwrap();
        }
    }
}

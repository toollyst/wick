// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The SMCCC TRNG service (Arm DEN0098) as KVM answers it for a guest on
//! Linux (arch/arm64/kvm/trng.c, since v5.12; on by default:
//! hypercalls.c `KVM_ARM_SMCCC_STD_FEATURES` holds
//! `KVM_REG_ARM_STD_BIT_TRNG_V1_0`): version 1.0, its features, KVM's UUID
//! and up to 192 bits of entropy a call. A Linux guest finds it by
//! TRNG_VERSION (drivers/firmware/smccc/smccc.c `smccc_probe_trng`), makes
//! the `smccc_trng` platform device, and seeds its random number generator
//! from it at boot (arch/arm64/include/asm/archrandom.h).
//!
//! KVM's bits are `get_random_long()`, the host kernel's generator. Here
//! they are `getentropy(2)`, the host kernel's generator as well (xnu
//! bsd/dev/random/randomdev.c `getentropy` copies out `read_random`, the
//! kernel's generator; it is the call that seeds `arc4random(3)`): each
//! call's bits come from the kernel, none from a generator in this process
//! that a snapshot or a fork could copy. Firecracker's sandbox allows the
//! call in both phases (`vmm::ext::sandbox`: upstream's filter has
//! `getrandom`).

/// ARM_SMCCC_TRNG_VERSION (include/linux/arm-smccc.h).
pub const VERSION: u32 = 0x8400_0050;
/// ARM_SMCCC_TRNG_FEATURES.
pub const FEATURES: u32 = 0x8400_0051;
/// ARM_SMCCC_TRNG_GET_UUID.
pub const GET_UUID: u32 = 0x8400_0052;
/// ARM_SMCCC_TRNG_RND32.
pub const RND32: u32 = 0x8400_0053;
/// ARM_SMCCC_TRNG_RND64, the one SMC64 call.
pub const RND64: u32 = 0xc400_0053;

/// ARM_SMCCC_TRNG_VERSION_1_0 (trng.c).
pub const VERSION_1_0: u64 = 0x1_0000;
/// TRNG_SUCCESS.
pub const SUCCESS: u64 = 0;
/// TRNG_NOT_SUPPORTED: -1 in the whole register, as trng.c writes it.
pub const NOT_SUPPORTED: u64 = -1i64 as u64;
/// TRNG_INVALID_PARAMETER.
pub const INVALID_PARAMETER: u64 = -2i64 as u64;
/// TRNG_NO_ENTROPY.
pub const NO_ENTROPY: u64 = -3i64 as u64;

/// KVM's TRNG UUID as TRNG_GET_UUID returns it in W0 to W3: trng.c
/// `arm_smc_trng_uuid`, 0d21e000-4384-11eb-8070-52 44 55 4e 5a 4c, its 16
/// bytes read as four little-endian words.
pub const UUID: [u64; 4] = [0x00e0_210d, 0xeb11_8443, 0x4452_7080, 0x4c5a_4e55];

/// TRNG_FEATURES of X1 (`kvm_trng_call`): SUCCESS for the five calls,
/// NOT_SUPPORTED for anything else; KVM compares the whole register.
pub fn features(x1: u64) -> u64 {
    match u32::try_from(x1) {
        Ok(VERSION | FEATURES | GET_UUID | RND32 | RND64) => SUCCESS,
        _ => NOT_SUPPORTED,
    }
}

/// TRNG_RND32 (`size` 32) or TRNG_RND64 (`size` 64) for `num_bits` bits
/// (W1), as `kvm_trng_do_rnd`: X0 to X3. More than 3 * `size` bits is
/// INVALID_PARAMETER; else X0 is SUCCESS and the bits are in X3 upwards,
/// the rest zero: three 64-bit words for RND64, the low 96 bits as three
/// 32-bit words for RND32. No bits at all is SUCCESS too, as KVM answers
/// it. `entropy` gives 64 bits a call, or `None`: NO_ENTROPY then, where
/// KVM's source cannot fail.
pub fn rnd(size: u32, num_bits: u32, mut entropy: impl FnMut() -> Option<u64>) -> [u64; 4] {
    if num_bits > 3 * size {
        return [INVALID_PARAMETER, 0, 0, 0];
    }
    let mut bits = [0u64; 3];
    for word in bits.iter_mut().take(num_bits.div_ceil(64) as usize) {
        match entropy() {
            Some(v) => *word = v,
            None => return [NO_ENTROPY, 0, 0, 0],
        }
    }
    // bitmap_clear(bits, num_bits, 192 - num_bits).
    for (i, word) in bits.iter_mut().enumerate() {
        let below = num_bits.saturating_sub(64 * i as u32);
        if below < 64 {
            *word &= (1u64 << below) - 1;
        }
    }
    if size == 32 {
        [SUCCESS, bits[1] & 0xffff_ffff, bits[0] >> 32, bits[0] & 0xffff_ffff]
    } else {
        [SUCCESS, bits[2], bits[1], bits[0]]
    }
}

/// 64 bits from the host kernel's generator (`getentropy(2)`); `None` if
/// the call fails (it does not for 8 bytes into a valid buffer).
pub fn host_entropy() -> Option<u64> {
    let mut buf = [0u8; 8];
    // SAFETY: 8 bytes into `buf`.
    (unsafe { libc::getentropy(buf.as_mut_ptr().cast(), buf.len()) } == 0).then(|| u64::from_ne_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_features_are_the_five_calls() {
        for id in [VERSION, FEATURES, GET_UUID, RND32, RND64] {
            assert_eq!(features(u64::from(id)), SUCCESS, "{id:#x}");
        }
        // Another id, PSCI's, and a call's id with the upper half set.
        for x1 in [0x8400_0054, 0x8400_0000, 0xc400_0050, 0, 1 << 32 | u64::from(RND64)] {
            assert_eq!(features(x1), NOT_SUPPORTED, "{x1:#x}");
        }
    }

    // trng.c's UUID_INIT bytes, read as kvm_trng_call reads them.
    #[test]
    fn test_uuid_is_kvms() {
        let bytes: [u8; 16] =
            [0x0d, 0x21, 0xe0, 0x00, 0x43, 0x84, 0x11, 0xeb, 0x80, 0x70, 0x52, 0x44, 0x55, 0x4e, 0x5a, 0x4c];
        for (i, word) in UUID.iter().enumerate() {
            assert_eq!(*word, u64::from(u32::from_le_bytes(bytes[4 * i..4 * i + 4].try_into().unwrap())));
        }
    }

    // The layout of kvm_trng_do_rnd's answer, with every source bit set:
    // exactly `num_bits` bits come back, from X3 upwards.
    #[test]
    fn test_rnd_returns_the_bits_asked_for_as_kvm_lays_them_out() {
        let ones = || Some(u64::MAX);
        for n in 0..=192u32 {
            let [x0, x1, x2, x3] = rnd(64, n, ones);
            assert_eq!(x0, SUCCESS, "{n}");
            let got = u128::from(x3).count_ones() + x2.count_ones() + x1.count_ones();
            assert_eq!(got, n, "RND64 {n}: {x1:#x} {x2:#x} {x3:#x}");
            // Filled from the low end: X3 before X2 before X1.
            assert_eq!(x3, if n >= 64 { u64::MAX } else { (1 << n) - 1 }, "{n}");
            assert_eq!(x1, if n > 128 { u64::MAX >> (192 - n) } else { 0 }, "{n}");
        }
        for n in 0..=96u32 {
            let [x0, x1, x2, x3] = rnd(32, n, ones);
            assert_eq!(x0, SUCCESS, "{n}");
            assert!(x1 >> 32 == 0 && x2 >> 32 == 0 && x3 >> 32 == 0, "RND32 {n}: {x1:#x} {x2:#x} {x3:#x}");
            assert_eq!(x1.count_ones() + x2.count_ones() + x3.count_ones(), n, "RND32 {n}");
            assert_eq!(x3, if n >= 32 { 0xffff_ffff } else { (1 << n) - 1 }, "{n}");
        }
        // Which word is which: one draw of 64 bits.
        let mut words = [0x1111_2222_3333_4444u64, 0x5555_6666_7777_8888, 0x9999_aaaa_bbbb_cccc].into_iter();
        assert_eq!(rnd(64, 192, || words.next()), [
            SUCCESS,
            0x9999_aaaa_bbbb_cccc,
            0x5555_6666_7777_8888,
            0x1111_2222_3333_4444
        ]);
        let mut words = [0x1111_2222_3333_4444u64, 0x5555_6666_7777_8888].into_iter();
        assert_eq!(rnd(32, 96, || words.next()), [SUCCESS, 0x7777_8888, 0x1111_2222, 0x3333_4444]);
        // Only as many draws as the bits need.
        let mut draws = 0;
        rnd(64, 65, || {
            draws += 1;
            Some(0)
        });
        assert_eq!(draws, 2);
    }

    #[test]
    fn test_rnd_refuses_more_bits_than_a_call_holds() {
        let ones = || Some(u64::MAX);
        for (size, n) in [(64, 193), (64, u32::MAX), (32, 97), (32, 192)] {
            assert_eq!(rnd(size, n, ones), [INVALID_PARAMETER, 0, 0, 0], "{size} {n}");
        }
        assert_eq!(rnd(64, 1, || None), [NO_ENTROPY, 0, 0, 0]);
        // No bits: no draw, SUCCESS, as KVM.
        assert_eq!(rnd(64, 0, || None), [SUCCESS, 0, 0, 0]);
    }

    // The host's source gives different bits each call.
    #[test]
    fn test_host_entropy_differs_from_call_to_call() {
        let draws: std::collections::HashSet<u64> = (0..64).map(|_| host_entropy().unwrap()).collect();
        assert_eq!(draws.len(), 64);
    }
}

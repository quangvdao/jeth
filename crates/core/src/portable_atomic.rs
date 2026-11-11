//! Compiler atomic libcalls for a single hart without interrupts or other writers.
//!
//! This runtime contract lets RV64IM guests use reference-counted allocations
//! without the A extension. These functions provide no synchronization between
//! harts, threads, interrupts, or DMA. Ordering arguments are immaterial under
//! this contract. Every pointer must be aligned, initialized, and valid for its
//! indicated read or write. Compare-exchange uses LLVM's five-argument sized
//! libcall ABI; failure replaces the expected value with the observed value.

use core::ptr::{read_volatile, write_volatile};

macro_rules! atomic_access {
    ($load:ident, $store:ident, $compare:ident, $scalar:ty) => {
        #[cfg_attr(
            all(
                feature = "portable",
                target_arch = "riscv64",
                target_os = "none",
                not(target_feature = "a")
            ),
            no_mangle
        )]
        unsafe extern "C" fn $load(pointer: *const $scalar, _order: i32) -> $scalar {
            // SAFETY: the caller supplies an aligned, initialized readable object.
            unsafe { read_volatile(pointer) }
        }

        #[cfg_attr(
            all(
                feature = "portable",
                target_arch = "riscv64",
                target_os = "none",
                not(target_feature = "a")
            ),
            no_mangle
        )]
        unsafe extern "C" fn $store(pointer: *mut $scalar, value: $scalar, _order: i32) {
            // SAFETY: the caller supplies an aligned writable object with no concurrent access.
            unsafe { write_volatile(pointer, value) };
        }

        #[cfg_attr(
            all(
                feature = "portable",
                target_arch = "riscv64",
                target_os = "none",
                not(target_feature = "a")
            ),
            no_mangle
        )]
        unsafe extern "C" fn $compare(
            pointer: *mut $scalar,
            expected: *mut $scalar,
            desired: $scalar,
            _success: i32,
            _failure: i32,
        ) -> bool {
            // SAFETY: both objects satisfy the module's single-hart pointer contract.
            unsafe {
                let observed = read_volatile(pointer);
                if observed == read_volatile(expected) {
                    write_volatile(pointer, desired);
                    true
                } else {
                    write_volatile(expected, observed);
                    false
                }
            }
        }
    };
}

atomic_access!(
    __atomic_load_1,
    __atomic_store_1,
    __atomic_compare_exchange_1,
    u8
);
atomic_access!(
    __atomic_load_8,
    __atomic_store_8,
    __atomic_compare_exchange_8,
    u64
);

macro_rules! atomic_fetch {
    ($name:ident, $operation:ident) => {
        #[cfg_attr(
            all(
                feature = "portable",
                target_arch = "riscv64",
                target_os = "none",
                not(target_feature = "a")
            ),
            no_mangle
        )]
        unsafe extern "C" fn $name(pointer: *mut u64, value: u64, _order: i32) -> u64 {
            // SAFETY: the caller supplies an aligned object with no concurrent access.
            unsafe {
                let observed = read_volatile(pointer);
                write_volatile(pointer, observed.$operation(value));
                observed
            }
        }
    };
}

atomic_fetch!(__atomic_fetch_add_8, wrapping_add);
atomic_fetch!(__atomic_fetch_sub_8, wrapping_sub);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_load_store_and_compare_exchange_contract() {
        let mut value = 17_u8;
        let mut expected = 17_u8;
        // SAFETY: the local initialized objects are aligned and accessed only by this test.
        unsafe {
            assert_eq!(__atomic_load_1(&value, 2), 17);
            assert!(__atomic_compare_exchange_1(
                &mut value,
                &mut expected,
                89,
                5,
                2
            ));
            assert_eq!((value, expected), (89, 17));
            assert!(!__atomic_compare_exchange_1(
                &mut value,
                &mut expected,
                31,
                5,
                2
            ));
            assert_eq!((value, expected), (89, 89));
            __atomic_store_1(&mut value, 255, 3);
            assert_eq!(__atomic_load_1(&value, 2), 255);
        }
    }

    #[test]
    fn word_load_store_and_compare_exchange_contract() {
        let mut value = 0x1234_5678_9abc_def0_u64;
        let mut expected = value;
        // SAFETY: the local initialized objects are aligned and accessed only by this test.
        unsafe {
            assert_eq!(__atomic_load_8(&value, 2), 0x1234_5678_9abc_def0);
            assert!(__atomic_compare_exchange_8(
                &mut value,
                &mut expected,
                89,
                5,
                2
            ));
            assert_eq!((value, expected), (89, 0x1234_5678_9abc_def0));
            assert!(!__atomic_compare_exchange_8(
                &mut value,
                &mut expected,
                31,
                5,
                2
            ));
            assert_eq!((value, expected), (89, 89));
            __atomic_store_8(&mut value, u64::MAX, 3);
            assert_eq!(__atomic_load_8(&value, 2), u64::MAX);
        }
    }

    #[test]
    fn fetch_arithmetic_returns_old_value_and_wraps() {
        let mut value = u64::MAX;
        // SAFETY: the local initialized object is aligned and accessed only by this test.
        unsafe {
            assert_eq!(__atomic_fetch_add_8(&mut value, 2, 5), u64::MAX);
            assert_eq!(value, 1);
            assert_eq!(__atomic_fetch_sub_8(&mut value, 2, 5), 1);
            assert_eq!(value, u64::MAX);
        }
    }
}

//! Aligned accesses to the words containing a guest byte range.
//!
//! RV64 callers use flat, word-granular memory: any containing word is mapped.
//! Assembly accesses keep bytes outside the caller's Rust object out of Rust
//! memory operations. Native callers must own and initialize each whole word.

#[cfg(not(target_arch = "riscv64"))]
use core::ptr::{read_volatile, write_volatile};

/// Loads the 8-aligned word `I` words past `p` (the offset is an `ld`
/// immediate), which may hold bytes outside the caller's range
/// (containing-word read, see the module docs). On other targets the
/// native-test caller must own and initialize the whole word.
#[inline(always)]
pub(super) unsafe fn load_word<const I: usize>(p: *const u64) -> u64 {
    #[cfg(target_arch = "riscv64")]
    {
        let w: u64;
        core::arch::asm!(
            "ld {w}, {off}({p})",
            p = in(reg) p,
            off = const I * 8,
            w = lateout(reg) w,
            options(pure, readonly, nostack, preserves_flags)
        );
        w
    }
    #[cfg(not(target_arch = "riscv64"))]
    read_volatile(p.add(I))
}

/// Stores `v` to the 8-aligned word `I` words past `p`, which may hold bytes
/// outside the caller's range (edge word of a read-modify-write, see the
/// module docs). The caller must exclusively own the whole word, or run
/// on the single-hart guest with no concurrent access to its edge bytes.
#[inline(always)]
pub(super) unsafe fn store_word<const I: usize>(p: *mut u64, v: u64) {
    #[cfg(target_arch = "riscv64")]
    core::arch::asm!(
        "sd {v}, {off}({p})",
        p = in(reg) p,
        off = const I * 8,
        v = in(reg) v,
        options(nostack, preserves_flags)
    );
    #[cfg(not(target_arch = "riscv64"))]
    write_volatile(p.add(I), v);
}

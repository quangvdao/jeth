#![cfg_attr(target_arch = "riscv64", no_std, no_main, feature(alloc_error_handler))]

#[cfg(target_arch = "riscv64")]
mod runtime;

#[cfg(not(target_arch = "riscv64"))]
fn main() {}

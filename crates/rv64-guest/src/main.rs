#![cfg_attr(target_arch = "riscv64", no_std, no_main, feature(alloc_error_handler))]

#[cfg(target_arch = "riscv64")]
mod runtime;

#[cfg(target_arch = "riscv64")]
extern crate alloc;
#[cfg(any(target_arch = "riscv64", test))]
mod secp_software;

#[cfg(not(target_arch = "riscv64"))]
fn main() {}

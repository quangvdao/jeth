//! Compiles the guest shims natively so their differential tests run.
//! See `Cargo.toml` for the command.
#![allow(dead_code)]

#[path = "../../src/keccak.rs"]
mod keccak;
#[path = "../../src/mem.rs"]
mod mem;

#[path = "../../src/word.rs"]
mod word;

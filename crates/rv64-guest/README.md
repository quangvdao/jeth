# rv64-guest

A bare-metal RV64IM guest that validates one Ethereum block with `jeth-core`'s portable path. It needs no zkVM SDK and runs on any RV64IM tracer that maps these apertures:

| Address | Use |
|---|---|
| `0x8000_0000` | program load address (`link.ld`) |
| `0x7000_0000` | input: a postcard-framed byte string holding the encoded block container |
| `0x7800_0000` | output: state root (32 bytes), block hash (32 bytes), gas used (u64) |
| `0x7800_0048` | phase word (1 decode, 2 recover signers, 3 validate, 4 witness reveal, 5 post-state root, 0 done) |
| `0x7800_0050` | panic flag |
| `0x7800_0058` | termination flag |

The heap (1.5 GiB) starts above a 32 MiB stack placed after the program image.

Build with the pinned toolchain in `rust-toolchain.toml` and its `rust-src`
component. The signature backend also needs Clang with RISC-V target support
and `llvm-ar` to archive the guest objects. The build finds both on `PATH` by default.
Set `CC_riscv64imac_unknown_none_elf` or `AR_riscv64imac_unknown_none_elf` to
select different binaries. On macOS, put upstream LLVM
ahead of Apple Clang on `PATH`. With Homebrew LLVM, run
`export PATH="$(brew --prefix llvm)/bin:$PATH"`.

```bash
CARGO_TARGET_DIR=target/rv64-guest crates/rv64-guest/build.sh guest.elf
```

`build.sh` remaps absolute source paths, so the ELF is byte-identical from any checkout with the same Rust and C toolchains.

To use the custom-0 Keccak instructions, pass `--custom0-keccak` before the output path. This enables only `alloy-primitives/native-keccak` and the portable sponge shim. The two words are `0xc200000b` (25-lane permutation) and `0xc200100b` (XOR 17 message lanes, then permute), with pointers in `a0` and `a1` and zero instruction register fields. All shim memory accesses remain 8-aligned.

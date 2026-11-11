#!/usr/bin/env bash
set -euo pipefail
guest_sources=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
: "${CARGO_TARGET_DIR:?set CARGO_TARGET_DIR}"
guest_output=${1:?usage: build.sh OUTPUT_ELF}
repo_root=$(cd -- "$guest_sources/../.." && pwd)
cargo_home=${CARGO_HOME:-$HOME/.cargo}
sysroot=$(cd -- "$guest_sources" && rustc --print sysroot)
# Remap absolute source paths so the ELF is identical from any checkout.
remap="--remap-path-prefix=$repo_root=/jeth --remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$sysroot=/rust"
guest_flags="$remap -C panic=abort -C target-feature=+m,-a,-c,-zca,-zaamo,-zalrsc,-f,-d,-zicsr,+unaligned-scalar-mem -C relocation-model=static -C code-model=medium -C link-arg=-T${guest_sources}/link.ld -C link-arg=--no-relax -C link-arg=--nmagic --cfg sha2_backend=\"soft\""
cd -- "$guest_sources"
RUSTC_BOOTSTRAP=1 RUSTFLAGS="$guest_flags" cargo build \
    --manifest-path Cargo.toml --locked --release \
    --target riscv64imac-unknown-none-elf -Zbuild-std=core,alloc \
    -Zbuild-std-features=compiler-builtins-mem
cp -- "$CARGO_TARGET_DIR/riscv64imac-unknown-none-elf/release/ethereum-block-guest" "$guest_output"

use crate::block_allocator::BlockAllocator;
use core::{
    alloc::Layout,
    arch::{asm, global_asm},
    mem::MaybeUninit,
    panic::PanicInfo,
    ptr::{addr_of_mut, write_volatile},
};
use critical_section::{Impl, RawRestoreState};
use jeth_core::{decode_container, recover_block, validate_recovered};
#[cfg(feature = "custom0-keccak")]
use jeth_guest as _;

const INPUT: usize = 0x7000_0000;
const OUTPUT: usize = 0x7800_0000;
const PHASE: usize = OUTPUT + 72;
const PANIC: usize = OUTPUT + 80;
const TERMINATION: usize = PANIC + 8;
const HEAP_CAPACITY: usize = 1536 << 20;
extern "C" {
    // The linker supplies the base and the runtime maps this writable region.
    static mut __stack_top: [MaybeUninit<u8>; HEAP_CAPACITY];
}

#[global_allocator]
static ALLOCATOR: BlockAllocator = BlockAllocator::new();

global_asm!(
    ".section .text.start,\"ax\",@progbits",
    ".option norvc",
    ".option norelax",
    ".globl _start",
    "_start:",
    "lla sp, __stack_top",
    "andi sp, sp, -16",
    "lla gp, __global_pointer$",
    "call guest_main",
    "1: jal zero, 1b",
);

#[no_mangle]
extern "C" fn guest_main() -> ! {
    // SAFETY: the linker places a 1.5 GiB heap region above the stack top.
    unsafe { ALLOCATOR.init(addr_of_mut!(__stack_top).cast(), HEAP_CAPACITY) };
    crate::secp_software::install();

    // SAFETY: the harness maps this immutable input aperture for the entire run.
    let stream = unsafe { core::slice::from_raw_parts(INPUT as *const u8, 128 << 20) };
    let (bytes, _) = postcard::take_from_bytes::<&[u8]>(stream).expect("input framing");
    phase(1);
    let input = decode_container(bytes).expect("JEF input");
    let expected_root = input.block.header.state_root;
    phase(2);
    let recovered = recover_block(input.block, input.signers).expect("signatures");
    phase(3);
    let result = validate_recovered(recovered, input.witness).expect("state root and consensus");
    // SAFETY: the harness reserves 80 output bytes and two control words.
    unsafe {
        for (i, byte) in expected_root
            .iter()
            .chain(result.block_hash.iter())
            .enumerate()
        {
            write_volatile((OUTPUT + i) as *mut u8, *byte);
        }
        write_volatile((OUTPUT + 64) as *mut u64, result.gas_used);
        phase(0);
        write_volatile(TERMINATION as *mut u64, 1);
    }
    stall()
}
fn phase(id: u64) {
    // SAFETY: the final output word is reserved for phase transitions.
    unsafe { write_volatile(PHASE as *mut u64, id) };
}
#[no_mangle]
pub unsafe extern "C" fn jeth_phase_start(pointer: *const u8, length: usize) {
    // SAFETY: jeth-core supplies a valid static phase label.
    let label = unsafe { core::slice::from_raw_parts(pointer, length) };
    phase(match label {
        b"witness_reveal" => 4,
        b"post_root" => 5,
        _ => 3,
    });
}
#[no_mangle]
pub extern "C" fn jeth_phase_end(_pointer: *const u8, _length: usize) {
    phase(3);
}

struct SingleHart;
critical_section::set_impl!(SingleHart);
// SAFETY: execution has one hart, no interrupts, and no reentrant callbacks.
unsafe impl Impl for SingleHart {
    unsafe fn acquire() -> RawRestoreState {}
    unsafe fn release(_: RawRestoreState) {}
}
fn stall() -> ! {
    loop {
        // SAFETY: the self branch has no memory or stack effects.
        unsafe { asm!("2: jal zero, 2b", options(nomem, nostack)) };
    }
}
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    // SAFETY: these control words belong to the harness's I/O aperture.
    unsafe {
        write_volatile(PANIC as *mut u64, 1);
        write_volatile(TERMINATION as *mut u64, 1);
    }
    stall()
}
#[alloc_error_handler]
fn allocation_error(_layout: Layout) -> ! {
    panic!("guest heap exhausted")
}

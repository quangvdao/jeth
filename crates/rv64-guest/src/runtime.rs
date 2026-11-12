use core::{
    alloc::{GlobalAlloc, Layout},
    arch::{asm, global_asm},
    cell::UnsafeCell,
    panic::PanicInfo,
    ptr::{write_volatile, NonNull},
};
use critical_section::{Impl, RawRestoreState};
use jeth_core::{decode_container, recover_block, validate_recovered};
#[cfg(feature = "custom0-keccak")]
use jeth_guest as _;
use linked_list_allocator::Heap;

const INPUT: usize = 0x7000_0000;
const OUTPUT: usize = 0x7800_0000;
const PHASE: usize = OUTPUT + 72;
const PANIC: usize = OUTPUT + 80;
const TERMINATION: usize = PANIC + 8;
extern "C" {
    static __stack_top: u8;
}

struct Allocator(UnsafeCell<Heap>);
// SAFETY: _start starts one hart without interrupts or concurrent callbacks.
unsafe impl Sync for Allocator {}
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the single hart has exclusive access to the initialized heap.
        unsafe { &mut *self.0.get() }
            .allocate_first_fit(layout)
            .map_or(core::ptr::null_mut(), NonNull::as_ptr)
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: GlobalAlloc supplies an allocation from this single-hart heap.
        unsafe { (&mut *self.0.get()).deallocate(NonNull::new_unchecked(pointer), layout) };
    }
}
#[global_allocator]
static ALLOCATOR: Allocator = Allocator(UnsafeCell::new(Heap::empty()));

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
    unsafe {
        (&mut *ALLOCATOR.0.get()).init(core::ptr::addr_of!(__stack_top).cast_mut(), 1536 << 20)
    };
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

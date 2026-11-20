use core::{
    alloc::{GlobalAlloc, Layout},
    cell::UnsafeCell,
    ptr::{copy_nonoverlapping, null_mut},
};

struct Arena {
    base: *mut u8,
    next: usize,
    end: usize,
}

impl Arena {
    fn advance(&mut self, start: usize, size: usize) -> *mut u8 {
        let Some(next) = start.checked_add(size).filter(|&next| next <= self.end) else {
            return null_mut();
        };
        self.next = next;
        self.base.with_addr(start)
    }
}

/// The guest validates one block and releases the arena when it exits.
pub(super) struct BlockAllocator(UnsafeCell<Arena>);

// SAFETY: _start runs one hart without interrupts or allocator reentrancy.
unsafe impl Sync for BlockAllocator {}

impl BlockAllocator {
    pub(super) const fn new() -> Self {
        Self(UnsafeCell::new(Arena {
            base: null_mut(),
            next: 0,
            end: 0,
        }))
    }

    /// Install the sole heap region before the first allocation.
    ///
    /// SAFETY: base must cover capacity bytes of exclusive writable storage
    /// for the remainder of this allocator's use.
    pub(super) unsafe fn init(&self, base: *mut u8, capacity: usize) {
        let next = base.addr();
        let end = next
            .checked_add(capacity)
            .expect("guest heap address overflow");
        // SAFETY: initialization runs on the sole hart before any allocation.
        unsafe { *self.0.get() = Arena { base, next, end } };
    }
}

// SAFETY: allocations reserve disjoint aligned ranges from the arena. A
// failed allocation or realloc leaves all live blocks intact.
unsafe impl GlobalAlloc for BlockAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: allocation runs on the sole hart and cannot reenter.
        let arena = unsafe { &mut *self.0.get() };
        let mask = layout.align() - 1;
        let Some(start) = arena.next.checked_add(mask) else {
            return null_mut();
        };
        arena.advance(start & !mask, layout.size())
    }

    unsafe fn dealloc(&self, _pointer: *mut u8, _layout: Layout) {}

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let Ok(new_layout) = Layout::from_size_align(new_size, layout.align()) else {
            return null_mut();
        };
        // SAFETY: recalculating the cursor cannot reenter the allocator.
        let arena = unsafe { &mut *self.0.get() };
        if pointer.addr() + layout.size() == arena.next {
            return arena.advance(pointer.addr(), new_size);
        }
        if new_size <= layout.size() {
            return pointer;
        }
        // SAFETY: the new layout is valid and has nonzero size.
        let new = unsafe { self.alloc(new_layout) };
        if !new.is_null() {
            // SAFETY: both blocks are live, disjoint and cover the old size.
            unsafe { copy_nonoverlapping(pointer, new, layout.size()) };
        }
        new
    }
}

#[cfg(test)]
mod tests {
    use super::{BlockAllocator, GlobalAlloc, Layout};

    #[test]
    fn allocator_respects_alignment_and_capacity() {
        #[repr(align(128))]
        struct Storage([u8; 256]);

        let mut storage = Storage([0; 256]);
        let base = storage.0.as_mut_ptr();
        let allocator = BlockAllocator::new();
        let first_layout = Layout::from_size_align(23, 8).unwrap();
        let wide_layout = Layout::from_size_align(12, 128).unwrap();
        let half_layout = Layout::from_size_align(128, 128).unwrap();
        let byte_layout = Layout::new::<u8>();

        // SAFETY: storage is exclusive and outlives every allocation.
        unsafe {
            allocator.init(base, 256);
            let first = allocator.alloc(first_layout);
            assert_eq!(first, base);
            first.write(42);
            assert_eq!(allocator.realloc(first, first_layout, 27), first);
            assert_eq!(first.read(), 42);

            let wide = allocator.alloc(wide_layout);
            assert_eq!(wide, base.add(128));
            wide.write(43);
            assert!(allocator.realloc(wide, wide_layout, 129).is_null());
            assert_eq!(allocator.realloc(wide, wide_layout, 128), wide);
            assert_eq!(wide.read(), 43);
            assert_eq!(first.read(), 42);

            assert!(allocator.alloc(byte_layout).is_null());
            allocator.dealloc(wide, half_layout);
            assert!(allocator.alloc(byte_layout).is_null());
        }
    }
}

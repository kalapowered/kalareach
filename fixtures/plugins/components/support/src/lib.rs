//! What a KalaReach component needs that the contract does not supply.
//!
//! A component imports the four `kalareach:plugin` interfaces and nothing else. That means it
//! cannot use the parts of the Rust standard library that reach the operating system, because
//! reaching the operating system on `wasm32-wasip2` means importing `wasi:filesystem`,
//! `wasi:cli/environment`, `wasi:clocks` and the rest, and the runtime refuses a component that
//! imports any of them.
//!
//! So a component is `no_std` with `alloc`, and it needs a few things of its own:
//!
//! | Thing | Why |
//! | --- | --- |
//! | a global allocator | `alloc` needs one, and the C library's is not linked |
//! | a panic handler | `no_std` has none, and a component with no host to report to traps |
//! | `cabi_realloc` | the canonical ABI calls it, and the C library usually supplies it |
//! | `memcmp` | the compiler emits calls to it for comparisons, and expects the C library to have it |
//!
//! Linking this crate supplies all of them. A component crate is then `#![no_std]`, declares
//! `extern crate alloc`, calls `wit_bindgen::generate!` against the SDK's WIT file, and implements
//! the adapter interface.
//!
//! # Panicking
//!
//! A panic becomes an `unreachable` instruction, which the host sees as a trap. There is no
//! standard error to write to and no exit code to set: the host's own failure record is where a
//! component's collapse is described, and it names the export that was running.

#![no_std]
#![allow(
    unsafe_code,
    reason = "the canonical ABI's reallocation hook is an extern function with raw pointers, and a component that does not link the C library has to supply it"
)]

extern crate alloc;

/// The allocator every component in this workspace uses.
///
/// `dlmalloc` is what the Rust standard library itself uses on `wasm32-unknown-unknown`. It needs
/// nothing from the host: it grows the component's own linear memory, which is what the runtime's
/// 64 MiB bound is measured against.
#[global_allocator]
static ALLOCATOR: dlmalloc::GlobalDlmalloc = dlmalloc::GlobalDlmalloc;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}

/// The canonical ABI's reallocation hook.
///
/// The component model calls this to make room for values it is lifting into the component. On
/// `wasm32-wasip2` the C library normally exports it; a component that does not link the C library
/// exports it here instead, over the same allocator as everything else.
#[unsafe(no_mangle)]
unsafe extern "C" fn cabi_realloc(
    old_pointer: *mut u8,
    old_len: usize,
    align: usize,
    new_len: usize,
) -> *mut u8 {
    use core::alloc::{GlobalAlloc as _, Layout};

    if new_len == 0 {
        // A zero-length allocation returns the alignment itself, which the canonical ABI treats as
        // a valid non-null pointer to nothing.
        return align as *mut u8;
    }
    let pointer = unsafe {
        if old_len == 0 {
            ALLOCATOR.alloc(Layout::from_size_align_unchecked(new_len, align))
        } else {
            ALLOCATOR.realloc(
                old_pointer,
                Layout::from_size_align_unchecked(old_len, align),
                new_len,
            )
        }
    };
    if pointer.is_null() {
        // Out of linear memory. There is nothing to report it to from here; the host's limiter has
        // already recorded which bound was reached.
        core::arch::wasm32::unreachable();
    }
    pointer
}

/// Compares two blocks of memory.
///
/// The compiler emits a call to this for a comparison it cannot do inline, such as one between two
/// string slices, and expects the C library to define it. Nothing else here needs the C library, so
/// this is the whole of what it would have been linked for. The counterparts `memcpy`, `memset` and
/// `memmove` come from `compiler_builtins`, which the target already links.
#[unsafe(no_mangle)]
unsafe extern "C" fn memcmp(left: *const u8, right: *const u8, count: usize) -> i32 {
    let mut index = 0;
    while index < count {
        let a = unsafe { *left.add(index) };
        let b = unsafe { *right.add(index) };
        if a != b {
            return i32::from(a) - i32::from(b);
        }
        index += 1;
    }
    0
}

/// Compares two blocks of memory for equality.
///
/// The same comparison as [`memcmp`] with only the zero or non-zero answer used. The compiler emits
/// whichever of the two it prefers, so both are here.
#[unsafe(no_mangle)]
unsafe extern "C" fn bcmp(left: *const u8, right: *const u8, count: usize) -> i32 {
    unsafe { memcmp(left, right, count) }
}

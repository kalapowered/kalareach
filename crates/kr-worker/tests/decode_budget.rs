//! What the canonical decoder reserves for a message it refuses, measured rather than reasoned
//! about.
//!
//! A worker decodes every frame a local client sends it, so a declaration the decoder believed
//! before checking would let a caller make the worker reserve memory it never delivers. The error
//! alone cannot show the order: a decoder that reserved first and checked afterwards would report
//! the same limit. This binary therefore watches the allocator while one decode runs and records
//! the largest single reservation made on that thread. Reserving room for a declared collection or
//! string is one allocation of that size, so the largest one is what tells the two orders apart,
//! and keeping the record per thread keeps tests running beside each other out of it.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use kr_cbor::{CanonicalValue, Limits, decode};

thread_local! {
    /// Whether this thread's allocations are being watched.
    static WATCHING: Cell<bool> = const { Cell::new(false) };
    /// The largest single allocation this thread asked for while watched.
    static LARGEST: Cell<usize> = const { Cell::new(0) };
}

/// The system allocator, noting the largest request a watched thread makes.
struct Watching;

impl Watching {
    fn note(size: usize) {
        let _ = WATCHING.try_with(|watching| {
            if watching.get() {
                let _ = LARGEST.try_with(|largest| largest.set(largest.get().max(size)));
            }
        });
    }
}

#[expect(
    unsafe_code,
    reason = "an allocator is the one thing that can say what a decode reserved, and its trait is \
              unsafe by definition; every call below forwards to the system allocator unchanged and \
              only notes the size it was asked for"
)]
unsafe impl GlobalAlloc for Watching {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        Self::note(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        Self::note(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        Self::note(new_size);
        unsafe { System.realloc(pointer, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: Watching = Watching;

/// Decodes `bytes` and returns the outcome with the largest allocation the decode made.
fn largest_reservation(bytes: &[u8], limits: &Limits) -> (kr_cbor::Result<CanonicalValue>, usize) {
    LARGEST.with(|largest| largest.set(0));
    WATCHING.with(|watching| watching.set(true));
    let outcome = decode(bytes, limits);
    WATCHING.with(|watching| watching.set(false));
    (outcome, LARGEST.with(Cell::get))
}

/// An array head declaring `members` members, followed by that many zero bytes.
fn present_array(members: u32) -> Vec<u8> {
    let mut bytes = vec![0x9a];
    bytes.extend_from_slice(&members.to_be_bytes());
    bytes.resize(bytes.len() + members as usize, 0x00);
    bytes
}

/// A string head of `major` declaring `len` bytes, followed by that many bytes of `fill`.
fn present_string(major: u8, len: u32, fill: u8) -> Vec<u8> {
    let mut bytes = vec![(major << 5) | 26];
    bytes.extend_from_slice(&len.to_be_bytes());
    bytes.resize(bytes.len() + len as usize, fill);
    bytes
}

/// Far below what reserving any of the declarations below would take.
const SMALL: usize = 64 * 1024;

/// KR-REQ-23.04: the count, depth and length limits are checked before anything a message declares
/// is reserved. Each message below is complete, so only the limit stands between its declaration
/// and a reservation of megabytes, and the decoder refuses each one having reserved almost
/// nothing. The same array inside every limit is reserved in full, which shows the measurement
/// sees a reservation when there is one.
#[test]
fn the_limits_are_checked_before_the_declared_size_is_reserved() {
    let members = 1_000_000u32;
    let array = present_array(members);
    let whole = members as usize * std::mem::size_of::<CanonicalValue>();
    let wide = Limits {
        max_message_len: 4 << 20,
        max_collection_len: 2_000_000,
        max_items: 2_000_000,
        ..Limits::DEFAULT
    };

    // Inside every limit, the array is reserved in full.
    let (outcome, reserved) = largest_reservation(&array, &wide);
    assert!(outcome.is_ok(), "{outcome:?}");
    assert!(
        reserved >= whole,
        "an admitted array of {members} members reserves {whole} bytes, the measurement saw \
         {reserved}"
    );

    // The count limit: the members are present, and only the item budget refuses them.
    let (outcome, reserved) = largest_reservation(
        &array,
        &Limits {
            max_items: 10,
            ..wide
        },
    );
    assert_eq!(
        outcome.expect_err("over the item budget").rule(),
        "count_limit"
    );
    assert!(reserved < SMALL, "the refusal reserved {reserved} bytes");

    // The depth limit: the members would sit one level deeper than the limit allows.
    let (outcome, reserved) = largest_reservation(
        &array,
        &Limits {
            max_depth: 1,
            ..wide
        },
    );
    assert_eq!(
        outcome.expect_err("over the depth limit").rule(),
        "depth_limit"
    );
    assert!(reserved < SMALL, "the refusal reserved {reserved} bytes");

    // The collection limit.
    let (outcome, reserved) = largest_reservation(
        &array,
        &Limits {
            max_collection_len: 4_096,
            ..wide
        },
    );
    assert_eq!(
        outcome.expect_err("over the collection limit").rule(),
        "collection_limit"
    );
    assert!(reserved < SMALL, "the refusal reserved {reserved} bytes");

    // The length limits, for a byte string and a text string whose bytes are all present. Inside
    // the limits each string is copied out in full, which is the reservation the limit prevents.
    let length = 2_000_000u32;
    for (message, what) in [
        (present_string(2, length, 0xab), "bytes"),
        (present_string(3, length, b'a'), "text"),
    ] {
        let (outcome, reserved) = largest_reservation(
            &message,
            &Limits {
                max_bytes_len: 4 << 20,
                max_text_len: 4 << 20,
                ..wide
            },
        );
        assert!(outcome.is_ok(), "{what}: {outcome:?}");
        assert!(
            reserved >= length as usize,
            "an admitted {what} string of {length} bytes reserves them, the measurement saw \
             {reserved}"
        );

        let (outcome, reserved) = largest_reservation(
            &message,
            &Limits {
                max_bytes_len: 1_024,
                max_text_len: 1_024,
                ..wide
            },
        );
        assert_eq!(
            outcome.expect_err("over the length limit").rule(),
            "length_limit",
            "{what}"
        );
        assert!(
            reserved < SMALL,
            "the {what} refusal reserved {reserved} bytes"
        );
    }
}

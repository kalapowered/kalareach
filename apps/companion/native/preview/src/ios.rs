//! What Swift calls: [`super::open`] by its C name, for the notification extension.
//!
//! The text it returns is owned by this library and given back with [`kr_preview_free`].

use std::ffi::{CStr, CString, c_char};

#[allow(
    unsafe_code,
    reason = "reading the C string a caller passes is a call through a raw pointer"
)]
fn text(pointer: *const c_char) -> Option<String> {
    if pointer.is_null() {
        return None;
    }
    // SAFETY: the caller passes a NUL-terminated string that outlives this call.
    unsafe { CStr::from_ptr(pointer) }
        .to_str()
        .ok()
        .map(str::to_owned)
}

/// Opens a sealed preview: `input` is the JSON text [`super::open`] reads, and `seed` points to
/// `seed_length` bytes of the phone's preview seed. Returns null for input that is not UTF-8.
#[allow(unsafe_code, reason = "Swift finds a function by its exported C name")]
#[unsafe(no_mangle)]
pub extern "C" fn kr_preview_open(
    input: *const c_char,
    seed: *const u8,
    seed_length: usize,
) -> *mut c_char {
    let Some(input) = text(input) else {
        return std::ptr::null_mut();
    };
    if seed.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: the caller passes `seed_length` readable bytes that outlive this call.
    let seed =
        zeroize::Zeroizing::new(unsafe { std::slice::from_raw_parts(seed, seed_length) }.to_vec());
    CString::new(super::open(&input, &seed)).map_or(std::ptr::null_mut(), CString::into_raw)
}

/// Gives back a text [`kr_preview_open`] returned.
#[allow(unsafe_code, reason = "Swift finds a function by its exported C name")]
#[unsafe(no_mangle)]
pub extern "C" fn kr_preview_free(pointer: *mut c_char) {
    if !pointer.is_null() {
        // SAFETY: the pointer came from `CString::into_raw` in this library and is given back once.
        drop(unsafe { CString::from_raw(pointer) });
    }
}

/// Keeps the functions in the linked library, which Swift looks them up in by name.
#[used]
static OPEN: extern "C" fn(*const c_char, *const u8, usize) -> *mut c_char = kr_preview_open;
/// Keeps the functions in the linked library, which Swift looks them up in by name.
#[used]
static FREE: extern "C" fn(*mut c_char) = kr_preview_free;

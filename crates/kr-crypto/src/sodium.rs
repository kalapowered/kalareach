//! The only module that calls libsodium.
//!
//! Everything below is a thin translation: a Rust slice becomes a pointer and a length, a C return
//! code becomes a [`CryptoError`]. No primitive is implemented here and no buffer is sized by
//! arithmetic that libsodium does not confirm; [`initialise`] checks every length constant this
//! module relies on against the library's own accessors before the first operation runs.
//!
//! The rest of the crate calls these functions and never `unsafe`. The workspace forbids unsafe
//! code; this crate denies it and allows it here, in one file, so a reviewer reads one list of
//! calls rather than searching the tree.
#![allow(unsafe_code)]

use std::ffi::c_char;
use std::sync::OnceLock;

use libsodium_sys as sodium;

use crate::error::{CryptoError, Result};

/// Bytes in an X25519 `crypto_box` public key.
pub const BOX_PUBLIC_KEY_LEN: usize = 32;
/// Bytes in an X25519 `crypto_box` secret key.
pub const BOX_SECRET_KEY_LEN: usize = 32;
/// Bytes in a `crypto_box` seed.
pub const BOX_SEED_LEN: usize = 32;
/// Bytes in a `crypto_box_easy` nonce.
pub const BOX_NONCE_LEN: usize = 24;
/// Bytes `crypto_box_easy` adds to a plaintext.
pub const BOX_MAC_LEN: usize = 16;

/// Bytes in an X25519 shared secret.
pub const AGREEMENT_LEN: usize = 32;
/// Bytes in the scalar an X25519 agreement is taken with.
pub const AGREEMENT_SCALAR_LEN: usize = 32;

/// Bytes in an Ed25519 public key.
pub const SIGN_PUBLIC_KEY_LEN: usize = 32;
/// Bytes in libsodium's expanded Ed25519 secret key: the seed followed by the public key.
pub const SIGN_SECRET_KEY_LEN: usize = 64;
/// Bytes in an Ed25519 seed.
pub const SIGN_SEED_LEN: usize = 32;
/// Bytes in an Ed25519 detached signature.
pub const SIGN_LEN: usize = 64;

/// Bytes in an XChaCha20-Poly1305 key.
pub const AEAD_KEY_LEN: usize = 32;
/// Bytes in an XChaCha20-Poly1305 nonce.
pub const AEAD_NONCE_LEN: usize = 24;
/// Bytes XChaCha20-Poly1305 adds to a plaintext.
pub const AEAD_TAG_LEN: usize = 16;

/// Bytes in a `secretstream` key.
pub const STREAM_KEY_LEN: usize = 32;
/// Bytes in a `secretstream` header.
pub const STREAM_HEADER_LEN: usize = 24;
/// Bytes `secretstream` adds to each record.
pub const STREAM_RECORD_OVERHEAD: usize = 17;

/// Bytes in a `crypto_kdf` master key.
pub const KDF_KEY_LEN: usize = 32;
/// Bytes in a `crypto_kdf` context.
pub const KDF_CONTEXT_LEN: usize = 8;

/// The tag on an ordinary `secretstream` record.
pub const TAG_MESSAGE: u8 = 0x00;
/// The tag on the last `secretstream` record of an object.
pub const TAG_FINAL: u8 = 0x03;

static INITIALISED: OnceLock<Result<()>> = OnceLock::new();

/// Initialises libsodium once and verifies the length constants this module uses.
///
/// `sodium_init` returns 0 on the first successful call, 1 when the library is already
/// initialised, and -1 when it fails. Anything else is treated as a failure.
///
/// # Errors
///
/// Returns [`CryptoError::LibraryUnavailable`] when libsodium cannot initialise, and
/// [`CryptoError::LibraryMismatch`] when a length the wrapper relies on differs from the length
/// the linked library reports.
pub fn initialise() -> Result<()> {
    INITIALISED.get_or_init(run_initialise).clone()
}

fn run_initialise() -> Result<()> {
    // SAFETY: `sodium_init` takes no arguments, is documented as safe to call more than once and
    // from more than one thread, and `OnceLock` runs this body exactly once regardless.
    let code = unsafe { sodium::sodium_init() };
    if code < 0 {
        return Err(CryptoError::LibraryUnavailable { code });
    }
    check_lengths()
}

fn check_lengths() -> Result<()> {
    // SAFETY: every accessor below takes no arguments, returns a `usize` and reads only the
    // library's own compile-time constants. They are called after `sodium_init` has succeeded.
    let reported: [(&str, usize, usize); 19] = unsafe {
        [
            (
                "crypto_scalarmult_bytes",
                sodium::crypto_scalarmult_bytes(),
                AGREEMENT_LEN,
            ),
            (
                "crypto_scalarmult_scalarbytes",
                sodium::crypto_scalarmult_scalarbytes(),
                AGREEMENT_SCALAR_LEN,
            ),
            (
                "crypto_box_publickeybytes",
                sodium::crypto_box_publickeybytes(),
                BOX_PUBLIC_KEY_LEN,
            ),
            (
                "crypto_box_secretkeybytes",
                sodium::crypto_box_secretkeybytes(),
                BOX_SECRET_KEY_LEN,
            ),
            (
                "crypto_box_seedbytes",
                sodium::crypto_box_seedbytes(),
                BOX_SEED_LEN,
            ),
            (
                "crypto_box_noncebytes",
                sodium::crypto_box_noncebytes(),
                BOX_NONCE_LEN,
            ),
            (
                "crypto_box_macbytes",
                sodium::crypto_box_macbytes(),
                BOX_MAC_LEN,
            ),
            (
                "crypto_sign_publickeybytes",
                sodium::crypto_sign_publickeybytes(),
                SIGN_PUBLIC_KEY_LEN,
            ),
            (
                "crypto_sign_secretkeybytes",
                sodium::crypto_sign_secretkeybytes(),
                SIGN_SECRET_KEY_LEN,
            ),
            (
                "crypto_sign_seedbytes",
                sodium::crypto_sign_seedbytes(),
                SIGN_SEED_LEN,
            ),
            ("crypto_sign_bytes", sodium::crypto_sign_bytes(), SIGN_LEN),
            (
                "crypto_aead_xchacha20poly1305_ietf_keybytes",
                sodium::crypto_aead_xchacha20poly1305_ietf_keybytes(),
                AEAD_KEY_LEN,
            ),
            (
                "crypto_aead_xchacha20poly1305_ietf_npubbytes",
                sodium::crypto_aead_xchacha20poly1305_ietf_npubbytes(),
                AEAD_NONCE_LEN,
            ),
            (
                "crypto_aead_xchacha20poly1305_ietf_abytes",
                sodium::crypto_aead_xchacha20poly1305_ietf_abytes(),
                AEAD_TAG_LEN,
            ),
            (
                "crypto_secretstream_xchacha20poly1305_keybytes",
                sodium::crypto_secretstream_xchacha20poly1305_keybytes(),
                STREAM_KEY_LEN,
            ),
            (
                "crypto_secretstream_xchacha20poly1305_headerbytes",
                sodium::crypto_secretstream_xchacha20poly1305_headerbytes(),
                STREAM_HEADER_LEN,
            ),
            (
                "crypto_secretstream_xchacha20poly1305_abytes",
                sodium::crypto_secretstream_xchacha20poly1305_abytes(),
                STREAM_RECORD_OVERHEAD,
            ),
            (
                "crypto_kdf_keybytes",
                sodium::crypto_kdf_keybytes(),
                KDF_KEY_LEN,
            ),
            (
                "crypto_kdf_contextbytes",
                sodium::crypto_kdf_contextbytes(),
                KDF_CONTEXT_LEN,
            ),
        ]
    };
    for (name, actual, expected) in reported {
        if actual != expected {
            return Err(CryptoError::LibraryMismatch {
                name,
                expected,
                actual,
            });
        }
    }
    // SAFETY: both accessors take no arguments and return the library's own tag constants.
    let (message_tag, final_tag) = unsafe {
        (
            sodium::crypto_secretstream_xchacha20poly1305_tag_message(),
            sodium::crypto_secretstream_xchacha20poly1305_tag_final(),
        )
    };
    if message_tag != TAG_MESSAGE {
        return Err(CryptoError::LibraryMismatch {
            name: "crypto_secretstream_xchacha20poly1305_tag_message",
            expected: TAG_MESSAGE as usize,
            actual: message_tag as usize,
        });
    }
    if final_tag != TAG_FINAL {
        return Err(CryptoError::LibraryMismatch {
            name: "crypto_secretstream_xchacha20poly1305_tag_final",
            expected: TAG_FINAL as usize,
            actual: final_tag as usize,
        });
    }
    Ok(())
}

/// Fills `buffer` from libsodium's random generator.
///
/// # Errors
///
/// Returns an error when libsodium is unavailable.
pub fn random_bytes(buffer: &mut [u8]) -> Result<()> {
    initialise()?;
    if buffer.is_empty() {
        return Ok(());
    }
    // SAFETY: the pointer and length come from the same live, exclusively borrowed slice, so the
    // whole written range is inside it. `randombytes_buf` writes exactly `size` bytes.
    unsafe {
        sodium::randombytes_buf(buffer.as_mut_ptr().cast(), buffer.len());
    }
    Ok(())
}

/// Overwrites `buffer` with zeroes through libsodium, which the compiler may not elide.
pub fn memzero(buffer: &mut [u8]) {
    if buffer.is_empty() {
        return;
    }
    // SAFETY: the pointer and length come from the same live, exclusively borrowed slice.
    // `sodium_memzero` needs no initialisation and writes exactly `len` bytes.
    unsafe {
        sodium::sodium_memzero(buffer.as_mut_ptr().cast(), buffer.len());
    }
}

/// Compares two byte strings in constant time.
///
/// Returns false for different lengths without reading either buffer, which is what a caller
/// comparing fixed-width tags wants and what a caller comparing variable-width data must handle
/// itself.
#[must_use]
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    if left.is_empty() {
        return true;
    }
    // SAFETY: both pointers come from live slices of the same length, which is the length passed.
    unsafe { sodium::sodium_memcmp(left.as_ptr().cast(), right.as_ptr().cast(), left.len()) == 0 }
}

/// Derives an X25519 `crypto_box` keypair from a seed.
///
/// # Errors
///
/// Returns an error when libsodium is unavailable or reports a failure.
pub fn box_seed_keypair(
    seed: &[u8; BOX_SEED_LEN],
) -> Result<([u8; BOX_PUBLIC_KEY_LEN], [u8; BOX_SECRET_KEY_LEN])> {
    initialise()?;
    let mut public = [0u8; BOX_PUBLIC_KEY_LEN];
    let mut secret = [0u8; BOX_SECRET_KEY_LEN];
    // SAFETY: all three buffers are exactly the lengths `initialise` verified.
    let code = unsafe {
        sodium::crypto_box_seed_keypair(public.as_mut_ptr(), secret.as_mut_ptr(), seed.as_ptr())
    };
    check(code, "crypto_box_seed_keypair")?;
    Ok((public, secret))
}

/// Takes the X25519 agreement of `scalar` with `point`.
///
/// libsodium clamps the scalar, refuses a point of small order and refuses an all-zero result, so
/// a shared secret that carries no contribution from the scalar is a failure here rather than a
/// value a caller could use. That refusal is the reason this is a call rather than arithmetic.
///
/// # Errors
///
/// Returns an error when libsodium is unavailable, when the point is one no agreement is taken
/// with, and when the agreement is all zeroes.
pub fn scalarmult(
    scalar: &[u8; AGREEMENT_SCALAR_LEN],
    point: &[u8; AGREEMENT_LEN],
) -> Result<[u8; AGREEMENT_LEN]> {
    initialise()?;
    let mut shared = [0u8; AGREEMENT_LEN];
    // SAFETY: all three buffers are exactly the lengths `initialise` verified, and the library
    // writes the output buffer only when it returns zero.
    let code =
        unsafe { sodium::crypto_scalarmult(shared.as_mut_ptr(), scalar.as_ptr(), point.as_ptr()) };
    if let Err(error) = check(code, "crypto_scalarmult") {
        // Nothing usable was written, and what was written is wiped rather than returned.
        memzero(&mut shared);
        return Err(error);
    }
    Ok(shared)
}

/// Seals `plaintext` for `recipient` from `sender` with `crypto_box_easy`.
///
/// # Errors
///
/// Returns an error when libsodium is unavailable or reports a failure.
pub fn box_easy(
    plaintext: &[u8],
    nonce: &[u8; BOX_NONCE_LEN],
    recipient: &[u8; BOX_PUBLIC_KEY_LEN],
    sender: &[u8; BOX_SECRET_KEY_LEN],
) -> Result<Vec<u8>> {
    initialise()?;
    let mut ciphertext = vec![0u8; plaintext.len() + BOX_MAC_LEN];
    // SAFETY: the output buffer is the plaintext length plus the MAC length the library reported,
    // which is what `crypto_box_easy` writes. The key and nonce buffers are the verified lengths,
    // and `mlen` is the plaintext's own length.
    let code = unsafe {
        sodium::crypto_box_easy(
            ciphertext.as_mut_ptr(),
            plaintext.as_ptr(),
            plaintext.len() as libc_ulonglong,
            nonce.as_ptr(),
            recipient.as_ptr(),
            sender.as_ptr(),
        )
    };
    check(code, "crypto_box_easy")?;
    Ok(ciphertext)
}

/// Opens a `crypto_box_easy` ciphertext.
///
/// # Errors
///
/// Returns [`CryptoError::Authentication`] when the ciphertext does not authenticate, and
/// [`CryptoError::Truncated`] when it is shorter than the MAC.
pub fn box_open_easy(
    ciphertext: &[u8],
    nonce: &[u8; BOX_NONCE_LEN],
    sender: &[u8; BOX_PUBLIC_KEY_LEN],
    recipient: &[u8; BOX_SECRET_KEY_LEN],
) -> Result<Vec<u8>> {
    initialise()?;
    let plaintext_len =
        ciphertext
            .len()
            .checked_sub(BOX_MAC_LEN)
            .ok_or(CryptoError::Truncated {
                what: "a crypto_box_easy ciphertext",
                minimum: BOX_MAC_LEN,
                actual: ciphertext.len(),
            })?;
    let mut plaintext = vec![0u8; plaintext_len];
    // SAFETY: the output buffer is the ciphertext length minus the MAC length, which is what
    // `crypto_box_open_easy` writes on success. It writes nothing on failure.
    let code = unsafe {
        sodium::crypto_box_open_easy(
            plaintext.as_mut_ptr(),
            ciphertext.as_ptr(),
            ciphertext.len() as libc_ulonglong,
            nonce.as_ptr(),
            sender.as_ptr(),
            recipient.as_ptr(),
        )
    };
    if code != 0 {
        memzero(&mut plaintext);
        return Err(CryptoError::Authentication {
            what: "a crypto_box_easy ciphertext",
        });
    }
    Ok(plaintext)
}

/// Derives an Ed25519 keypair from a seed.
///
/// # Errors
///
/// Returns an error when libsodium is unavailable or reports a failure.
pub fn sign_seed_keypair(
    seed: &[u8; SIGN_SEED_LEN],
) -> Result<([u8; SIGN_PUBLIC_KEY_LEN], [u8; SIGN_SECRET_KEY_LEN])> {
    initialise()?;
    let mut public = [0u8; SIGN_PUBLIC_KEY_LEN];
    let mut secret = [0u8; SIGN_SECRET_KEY_LEN];
    // SAFETY: all three buffers are exactly the lengths `initialise` verified.
    let code = unsafe {
        sodium::crypto_sign_seed_keypair(public.as_mut_ptr(), secret.as_mut_ptr(), seed.as_ptr())
    };
    check(code, "crypto_sign_seed_keypair")?;
    Ok((public, secret))
}

/// Produces a detached Ed25519 signature over `message`.
///
/// # Errors
///
/// Returns an error when libsodium is unavailable or reports a failure.
pub fn sign_detached(message: &[u8], secret: &[u8; SIGN_SECRET_KEY_LEN]) -> Result<[u8; SIGN_LEN]> {
    initialise()?;
    let mut signature = [0u8; SIGN_LEN];
    // SAFETY: the signature buffer is the verified signature length; passing a null length pointer
    // is documented and means the caller does not want the length written back.
    let code = unsafe {
        sodium::crypto_sign_detached(
            signature.as_mut_ptr(),
            std::ptr::null_mut(),
            message.as_ptr(),
            message.len() as libc_ulonglong,
            secret.as_ptr(),
        )
    };
    check(code, "crypto_sign_detached")?;
    Ok(signature)
}

/// Verifies a detached Ed25519 signature.
///
/// # Errors
///
/// Returns [`CryptoError::Authentication`] when the signature does not verify.
pub fn sign_verify_detached(
    signature: &[u8; SIGN_LEN],
    message: &[u8],
    public: &[u8; SIGN_PUBLIC_KEY_LEN],
) -> Result<()> {
    initialise()?;
    // SAFETY: the signature and key buffers are the verified lengths, and `mlen` is the message's
    // own length.
    let code = unsafe {
        sodium::crypto_sign_verify_detached(
            signature.as_ptr(),
            message.as_ptr(),
            message.len() as libc_ulonglong,
            public.as_ptr(),
        )
    };
    if code != 0 {
        return Err(CryptoError::Authentication {
            what: "an Ed25519 signature",
        });
    }
    Ok(())
}

/// Encrypts `plaintext` with XChaCha20-Poly1305 and the given additional authenticated data.
///
/// # Errors
///
/// Returns an error when libsodium is unavailable or reports a failure.
pub fn aead_encrypt(
    plaintext: &[u8],
    aad: &[u8],
    nonce: &[u8; AEAD_NONCE_LEN],
    key: &[u8; AEAD_KEY_LEN],
) -> Result<Vec<u8>> {
    initialise()?;
    let mut ciphertext = vec![0u8; plaintext.len() + AEAD_TAG_LEN];
    let mut written: libc_ulonglong = 0;
    // SAFETY: the output buffer is the plaintext length plus the verified tag length, which is the
    // most this function writes. `nsec` is unused by this construction and documented as null.
    let code = unsafe {
        sodium::crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext.as_mut_ptr(),
            &raw mut written,
            plaintext.as_ptr(),
            plaintext.len() as libc_ulonglong,
            aad_ptr(aad),
            aad.len() as libc_ulonglong,
            std::ptr::null(),
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };
    check(code, "crypto_aead_xchacha20poly1305_ietf_encrypt")?;
    ciphertext.truncate(usize::try_from(written).unwrap_or(ciphertext.len()));
    Ok(ciphertext)
}

/// Decrypts an XChaCha20-Poly1305 ciphertext.
///
/// # Errors
///
/// Returns [`CryptoError::Authentication`] when the ciphertext or the additional authenticated
/// data does not match.
pub fn aead_decrypt(
    ciphertext: &[u8],
    aad: &[u8],
    nonce: &[u8; AEAD_NONCE_LEN],
    key: &[u8; AEAD_KEY_LEN],
) -> Result<Vec<u8>> {
    initialise()?;
    let plaintext_len =
        ciphertext
            .len()
            .checked_sub(AEAD_TAG_LEN)
            .ok_or(CryptoError::Truncated {
                what: "an XChaCha20-Poly1305 ciphertext",
                minimum: AEAD_TAG_LEN,
                actual: ciphertext.len(),
            })?;
    let mut plaintext = vec![0u8; plaintext_len];
    let mut written: libc_ulonglong = 0;
    // SAFETY: the output buffer is the ciphertext length minus the verified tag length, which is
    // the most this function writes. It writes nothing on failure.
    let code = unsafe {
        sodium::crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext.as_mut_ptr(),
            &raw mut written,
            std::ptr::null_mut(),
            ciphertext.as_ptr(),
            ciphertext.len() as libc_ulonglong,
            aad_ptr(aad),
            aad.len() as libc_ulonglong,
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };
    if code != 0 {
        memzero(&mut plaintext);
        return Err(CryptoError::Authentication {
            what: "an XChaCha20-Poly1305 ciphertext",
        });
    }
    plaintext.truncate(usize::try_from(written).unwrap_or(plaintext.len()));
    Ok(plaintext)
}

/// Derives a subkey with `crypto_kdf_derive_from_key`.
///
/// `context` is the eight-byte context string; `subkey_id` selects the subkey.
///
/// # Errors
///
/// Returns an error when libsodium is unavailable or reports a failure.
pub fn kdf_derive(
    subkey: &mut [u8],
    subkey_id: u64,
    context: &[u8; KDF_CONTEXT_LEN],
    key: &[u8; KDF_KEY_LEN],
) -> Result<()> {
    initialise()?;
    // The context is a fixed-width byte string rather than a C string: libsodium reads exactly
    // `crypto_kdf_CONTEXTBYTES` bytes and never looks for a terminator.
    let context: &[c_char; KDF_CONTEXT_LEN] = &context.map(|byte| byte as c_char);
    // SAFETY: the subkey buffer and its length come from the same slice; the context and key
    // buffers are the verified lengths.
    let code = unsafe {
        sodium::crypto_kdf_derive_from_key(
            subkey.as_mut_ptr(),
            subkey.len(),
            subkey_id,
            context.as_ptr(),
            key.as_ptr(),
        )
    };
    check(code, "crypto_kdf_derive_from_key")
}

/// A `secretstream` encryption state.
///
/// The state holds the stream key, so it is zeroised when it is dropped.
pub struct StreamPushState(sodium::crypto_secretstream_xchacha20poly1305_state);

impl Drop for StreamPushState {
    fn drop(&mut self) {
        memzero(&mut self.0.k);
        memzero(&mut self.0.nonce);
    }
}

/// A `secretstream` decryption state.
pub struct StreamPullState(sodium::crypto_secretstream_xchacha20poly1305_state);

impl Drop for StreamPullState {
    fn drop(&mut self) {
        memzero(&mut self.0.k);
        memzero(&mut self.0.nonce);
    }
}

fn empty_stream_state() -> sodium::crypto_secretstream_xchacha20poly1305_state {
    sodium::crypto_secretstream_xchacha20poly1305_state {
        k: [0; 32],
        nonce: [0; 12],
        _pad: [0; 8],
    }
}

/// Starts a `secretstream` and returns its header.
///
/// # Errors
///
/// Returns an error when libsodium is unavailable or reports a failure.
pub fn stream_init_push(
    key: &[u8; STREAM_KEY_LEN],
) -> Result<(StreamPushState, [u8; STREAM_HEADER_LEN])> {
    initialise()?;
    let mut state = StreamPushState(empty_stream_state());
    let mut header = [0u8; STREAM_HEADER_LEN];
    // SAFETY: the state is a live, exclusively borrowed value of the library's own type, and the
    // header buffer is the verified header length.
    let code = unsafe {
        sodium::crypto_secretstream_xchacha20poly1305_init_push(
            &raw mut state.0,
            header.as_mut_ptr(),
            key.as_ptr(),
        )
    };
    check(code, "crypto_secretstream_xchacha20poly1305_init_push")?;
    Ok((state, header))
}

/// Pushes one record into a `secretstream`.
///
/// # Errors
///
/// Returns an error when libsodium is unavailable or reports a failure.
pub fn stream_push(state: &mut StreamPushState, record: &[u8], tag: u8) -> Result<Vec<u8>> {
    let mut ciphertext = vec![0u8; record.len() + STREAM_RECORD_OVERHEAD];
    let mut written: libc_ulonglong = 0;
    // SAFETY: the output buffer is the record length plus the verified per-record overhead, which
    // is what this call writes. No additional data is supplied, so the pointer is null and the
    // length zero.
    let code = unsafe {
        sodium::crypto_secretstream_xchacha20poly1305_push(
            &raw mut state.0,
            ciphertext.as_mut_ptr(),
            &raw mut written,
            record.as_ptr(),
            record.len() as libc_ulonglong,
            std::ptr::null(),
            0,
            tag,
        )
    };
    check(code, "crypto_secretstream_xchacha20poly1305_push")?;
    ciphertext.truncate(usize::try_from(written).unwrap_or(ciphertext.len()));
    Ok(ciphertext)
}

/// Starts reading a `secretstream` from its header.
///
/// # Errors
///
/// Returns [`CryptoError::Authentication`] when the header is not a valid stream header.
pub fn stream_init_pull(
    header: &[u8; STREAM_HEADER_LEN],
    key: &[u8; STREAM_KEY_LEN],
) -> Result<StreamPullState> {
    initialise()?;
    let mut state = StreamPullState(empty_stream_state());
    // SAFETY: the state is a live, exclusively borrowed value of the library's own type, and the
    // header and key buffers are the verified lengths.
    let code = unsafe {
        sodium::crypto_secretstream_xchacha20poly1305_init_pull(
            &raw mut state.0,
            header.as_ptr(),
            key.as_ptr(),
        )
    };
    if code != 0 {
        return Err(CryptoError::Authentication {
            what: "a secretstream header",
        });
    }
    Ok(state)
}

/// Pulls one record out of a `secretstream`, returning the plaintext and its tag.
///
/// # Errors
///
/// Returns [`CryptoError::Authentication`] when the record does not authenticate, and
/// [`CryptoError::Truncated`] when it is shorter than one record's overhead.
pub fn stream_pull(state: &mut StreamPullState, record: &[u8]) -> Result<(Vec<u8>, u8)> {
    let plaintext_len =
        record
            .len()
            .checked_sub(STREAM_RECORD_OVERHEAD)
            .ok_or(CryptoError::Truncated {
                what: "a secretstream record",
                minimum: STREAM_RECORD_OVERHEAD,
                actual: record.len(),
            })?;
    let mut plaintext = vec![0u8; plaintext_len];
    let mut written: libc_ulonglong = 0;
    let mut tag = 0u8;
    // SAFETY: the output buffer is the record length minus the verified per-record overhead, which
    // is the most this call writes, and it writes nothing on failure. No additional data is
    // supplied, so the pointer is null and the length zero.
    let code = unsafe {
        sodium::crypto_secretstream_xchacha20poly1305_pull(
            &raw mut state.0,
            plaintext.as_mut_ptr(),
            &raw mut written,
            &raw mut tag,
            record.as_ptr(),
            record.len() as libc_ulonglong,
            std::ptr::null(),
            0,
        )
    };
    if code != 0 {
        memzero(&mut plaintext);
        return Err(CryptoError::Authentication {
            what: "a secretstream record",
        });
    }
    plaintext.truncate(usize::try_from(written).unwrap_or(plaintext.len()));
    Ok((plaintext, tag))
}

/// Pads `buffer` up to the next multiple of `granularity` with ISO/IEC 7816-4 padding.
///
/// `buffer` must already hold `unpadded_len` bytes of content and be long enough for the padded
/// result. libsodium always adds at least one byte, so a content length that is already a multiple
/// of the granularity grows to the next multiple.
///
/// # Errors
///
/// Returns an error when libsodium is unavailable or reports a failure.
pub fn pad(buffer: &mut [u8], unpadded_len: usize, granularity: usize) -> Result<usize> {
    initialise()?;
    if unpadded_len > buffer.len() {
        return Err(CryptoError::Truncated {
            what: "a padding buffer",
            minimum: unpadded_len,
            actual: buffer.len(),
        });
    }
    let mut padded_len = 0usize;
    // SAFETY: the buffer and its length come from the same exclusively borrowed slice, and
    // `max_buflen` is that length, which is the bound `sodium_pad` will not write past.
    let code = unsafe {
        sodium::sodium_pad(
            &raw mut padded_len,
            buffer.as_mut_ptr(),
            unpadded_len,
            granularity,
            buffer.len(),
        )
    };
    check(code, "sodium_pad")?;
    Ok(padded_len)
}

/// Returns the content length of an ISO/IEC 7816-4 padded buffer.
///
/// # Errors
///
/// Returns [`CryptoError::Authentication`] when the padding is malformed. The buffer is
/// authenticated before it reaches this function, so malformed padding means a format error rather
/// than an oracle.
pub fn unpad(buffer: &[u8], granularity: usize) -> Result<usize> {
    initialise()?;
    let mut unpadded_len = 0usize;
    // SAFETY: the buffer and its length come from the same live slice; `sodium_unpad` only reads.
    let code = unsafe {
        sodium::sodium_unpad(
            &raw mut unpadded_len,
            buffer.as_ptr(),
            buffer.len(),
            granularity,
        )
    };
    if code != 0 {
        return Err(CryptoError::Authentication {
            what: "the padding of an authenticated plaintext",
        });
    }
    Ok(unpadded_len)
}

/// libsodium's message-length type.
#[allow(non_camel_case_types)]
type libc_ulonglong = std::os::raw::c_ulonglong;

/// Returns a pointer to `aad`, or null when it is empty.
///
/// An empty slice has a dangling non-null pointer; libsodium is documented to accept a null
/// pointer with a zero length, and passing the dangling one is a needless risk.
fn aad_ptr(aad: &[u8]) -> *const u8 {
    if aad.is_empty() {
        std::ptr::null()
    } else {
        aad.as_ptr()
    }
}

fn check(code: std::os::raw::c_int, name: &'static str) -> Result<()> {
    if code == 0 {
        return Ok(());
    }
    Err(CryptoError::Library { name, code })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The base point every X25519 public key is the agreement of a scalar with.
    const BASE_POINT: [u8; AGREEMENT_LEN] = {
        let mut point = [0u8; AGREEMENT_LEN];
        point[0] = 9;
        point
    };

    fn bytes(text: &str) -> [u8; AGREEMENT_LEN] {
        let mut out = [0u8; AGREEMENT_LEN];
        hex::decode_to_slice(text, &mut out).expect("a 32-byte hexadecimal vector");
        out
    }

    /// RFC 7748 section 6.1: the two scalars, the two public keys they derive and the one secret
    /// they agree on.
    ///
    /// The vectors are the whole point of having them: a curve implementation that is subtly wrong
    /// still round-trips with itself, so a round trip proves compatibility with nothing. These
    /// bytes are what every other X25519 implementation produces, which is what makes the value a
    /// service derives on the other side the same value.
    #[test]
    fn an_agreement_matches_the_published_x25519_vectors() {
        let alice_scalar =
            bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let alice_public =
            bytes("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let bob_scalar = bytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let bob_public = bytes("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let agreed = bytes("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        assert_eq!(
            scalarmult(&alice_scalar, &BASE_POINT).expect("a public key"),
            alice_public
        );
        assert_eq!(
            scalarmult(&bob_scalar, &BASE_POINT).expect("a public key"),
            bob_public
        );
        assert_eq!(
            scalarmult(&alice_scalar, &bob_public).expect("the shared secret"),
            agreed
        );
        assert_eq!(
            scalarmult(&bob_scalar, &alice_public).expect("the shared secret"),
            agreed
        );
    }

    /// KR-REQ-20.01: `crypto_box_easy` behind this boundary is libsodium's own: the vector
    /// libsodium publishes for it (`test/default/box_easy`, over the RFC 7748 keys above) seals to
    /// exactly its bytes, opens for the other party, and fails to open once a byte changes.
    #[test]
    fn the_box_construction_seals_and_opens_the_published_libsodium_vector() {
        let alice_secret =
            bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let alice_public =
            bytes("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let bob_secret = bytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let bob_public = bytes("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let mut nonce = [0u8; BOX_NONCE_LEN];
        hex::decode_to_slice(
            "69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37",
            &mut nonce,
        )
        .expect("a 24-byte nonce");
        let message = hex::decode(concat!(
            "be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffc",
            "e5ecbaaf33bd751a1ac728d45e6c61296cdc3c01233561f41db66cce314adb31",
            "0e3be8250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde",
            "048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f93776384864",
            "5e0705"
        ))
        .expect("the message");
        let published = hex::decode(concat!(
            "f3ffc7703f9400e52a7dfb4b3d3305d98e993b9f48681273c29650ba32fc76ce",
            "48332ea7164d96a4476fb8c531a1186ac0dfc17c98dce87b4da7f011ec48c972",
            "71d2c20f9b928fe2270d6fb863d51738b48eeee314a7cc8ab932164548e526ae",
            "90224368517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b3",
            "7973f622a43d14a6599b1f654cb45a74e355a5"
        ))
        .expect("the ciphertext");

        let sealed = box_easy(&message, &nonce, &bob_public, &alice_secret).expect("seals");
        assert_eq!(sealed, published, "the published ciphertext, MAC first");
        assert_eq!(sealed.len(), message.len() + BOX_MAC_LEN);
        assert_eq!(
            box_open_easy(&published, &nonce, &alice_public, &bob_secret).expect("opens"),
            message
        );

        let mut tampered = published;
        tampered[BOX_MAC_LEN] ^= 1;
        assert!(box_open_easy(&tampered, &nonce, &alice_public, &bob_secret).is_err());
    }

    /// KR-REQ-20.01: Ed25519 behind this boundary is libsodium's standard signature: RFC 8032
    /// section 7.1 test 1 derives its published public key from its seed and its published
    /// signature over the empty message, which verifies, and a changed signature does not.
    #[test]
    fn ed25519_reproduces_rfc_8032_test_one() {
        let seed = bytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let (public, secret) = sign_seed_keypair(&seed).expect("a keypair");
        assert_eq!(
            public,
            bytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        );
        let signature = sign_detached(b"", &secret).expect("a signature");
        assert_eq!(
            hex::encode(signature),
            concat!(
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
                "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
            )
        );
        assert!(sign_verify_detached(&signature, b"", &public).is_ok());
        let mut changed = signature;
        changed[0] ^= 1;
        assert!(sign_verify_detached(&changed, b"", &public).is_err());
    }

    #[test]
    fn a_point_that_agrees_to_nothing_is_a_failure_rather_than_a_secret() {
        let scalar = bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        for point in [
            // Three of the points libsodium blacklists, by their u coordinate: 0, 1 and p - 1.
            // Each of them sends every scalar to the same all-zero secret, so a caller given one
            // would hold a "shared" secret that the other side did not have to know anything to
            // produce.
            [0u8; AGREEMENT_LEN],
            bytes("0100000000000000000000000000000000000000000000000000000000000000"),
            bytes("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        ] {
            assert!(matches!(
                scalarmult(&scalar, &point),
                Err(CryptoError::Library {
                    name: "crypto_scalarmult",
                    ..
                })
            ));
        }
    }
}

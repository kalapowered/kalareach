//! The printable and QR recovery kit.
//!
//! One document, two ways of handing it over: printed for a person to type, and carried in a QR
//! code's byte mode for a camera to read. They are the same bytes, so what a scanner reads is what
//! a person could have typed, and there is one format to get right rather than two.
//!
//! # What it carries
//!
//! Section 20 fixes the contents: the format and cryptographic profile version, the recovery seed
//! and its checksum, each configured service origin, and the stable opaque bundle locator. *A seed
//! without a way to find the encrypted bundle is not a complete kit*, so the locator and the
//! origins are part of the document rather than something a person is expected to remember.
//!
//! # The seed's alphabet
//!
//! Crockford base32: no `I`, `L`, `O` or `U`, so the pairs that are misread when a kit is copied
//! by hand are not both in the alphabet. Reading accepts either case and maps `I` and `L` to `1`
//! and `O` to `0`, which is what a person who wrote them down anyway would mean. The four-byte
//! checksum then catches what the alphabet does not.
//!
//! # What is cleared
//!
//! The rendered document holds the seed. It is built into a buffer reserved at its exact final
//! size, inside `Zeroizing`, so no reallocation leaves a copy behind and the buffer clears when it
//! is dropped. A caller that prints it is responsible for what the printer does with it.

use kr_protocol::archive::{RECOVERY_KIT_PROFILE_VERSION, RecoveryKit};
use kr_protocol::scalars::{Bytes, SecretBytes32, U64};
use zeroize::Zeroizing;

use crate::recovery::RecoveryError;

/// The format line every recovery kit starts with.
pub const RECOVERY_KIT_FORMAT: &str = "kalareach-recovery-kit/1";

/// Bytes in the encoded seed payload: the 32-byte seed and its four-byte checksum.
const PAYLOAD_LEN: usize = 36;

/// Symbols in the base32 rendering of that payload.
const SYMBOLS: usize = PAYLOAD_LEN * 8 / 5 + 1;

/// Symbols per group in the printed seed.
const GROUP: usize = 4;

/// Crockford's base32 alphabet: the digits and the letters, without `I`, `L`, `O` and `U`.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// The most bytes a recovery kit may render to.
///
/// A QR code carries the document in byte mode. Version 26 at the medium error correction a
/// printed kit wants holds 1 059 bytes, so a kit inside this bound fits one; a kit that would not
/// is refused when it is built rather than discovered at the camera.
pub const MAX_RECOVERY_KIT_BYTES: usize = 1024;

/// Renders one kit as the printable and QR document.
///
/// # Errors
///
/// Returns [`RecoveryError::UnsupportedProfile`] for a profile this build does not write,
/// [`RecoveryError::UnprintableKit`] when an origin or the locator carries a character a
/// line-oriented document cannot hold, and [`RecoveryError::KitTooLarge`] when the document would
/// not fit a scannable QR code.
pub fn render(kit: &RecoveryKit) -> Result<Zeroizing<String>, RecoveryError> {
    if kit.profile_version.get() != RECOVERY_KIT_PROFILE_VERSION {
        return Err(RecoveryError::UnsupportedProfile {
            version: kit.profile_version.get(),
        });
    }
    check_printable("the bundle locator", &kit.bundle_locator)?;
    for origin in &kit.service_origins {
        check_printable("a service origin", origin)?;
    }
    if kit.service_origins.is_empty() {
        return Err(RecoveryError::UnprintableKit {
            what: "a kit that names no service origin, which is a seed with nowhere to look",
        });
    }
    if kit.seed_checksum.as_slice().len() != 4 {
        return Err(RecoveryError::UnprintableKit {
            what: "a seed checksum that is not four bytes",
        });
    }

    let seed = grouped_seed(kit);
    // Reserved at its exact final size, so the buffer holding the seed never moves.
    let total = RECOVERY_KIT_FORMAT.len()
        + 1
        + "seed: ".len()
        + seed.len()
        + 1
        + "locator: ".len()
        + kit.bundle_locator.len()
        + 1
        + kit
            .service_origins
            .iter()
            .map(|origin| "origin: ".len() + origin.len() + 1)
            .sum::<usize>();
    if total > MAX_RECOVERY_KIT_BYTES {
        return Err(RecoveryError::KitTooLarge {
            len: total,
            limit: MAX_RECOVERY_KIT_BYTES,
        });
    }
    let mut out = Zeroizing::new(String::with_capacity(total));
    out.push_str(RECOVERY_KIT_FORMAT);
    out.push('\n');
    out.push_str("seed: ");
    out.push_str(&seed);
    out.push('\n');
    out.push_str("locator: ");
    out.push_str(&kit.bundle_locator);
    out.push('\n');
    for origin in &kit.service_origins {
        out.push_str("origin: ");
        out.push_str(origin);
        out.push('\n');
    }
    // Compared without rendering either side: an assertion that printed what it compared would be
    // one step from printing what the buffer holds.
    debug_assert!(out.len() == total, "the reserved size is the written size");
    debug_assert!(out.capacity() == total, "the buffer never grew");
    Ok(out)
}

/// Returns the bytes a QR code carries in byte mode.
///
/// They are [`render`]'s bytes. A scanner therefore reads the document a person could have typed,
/// and a kit copied by either route is the same kit.
///
/// # Errors
///
/// See [`render`].
pub fn qr_payload(kit: &RecoveryKit) -> Result<Zeroizing<Vec<u8>>, RecoveryError> {
    Ok(Zeroizing::new(render(kit)?.as_bytes().to_vec()))
}

/// Reads a kit back from the printed or scanned document.
///
/// The profile version is checked before anything is decoded, and the checksum before the kit is
/// returned, so a mistyped kit fails here rather than at the first thing that will not decrypt.
///
/// # Errors
///
/// Returns [`RecoveryError::MalformedKit`] when the document is not this format,
/// [`RecoveryError::UnsupportedProfile`] for another profile, and
/// [`RecoveryError::MistypedKit`] when the checksum does not match the seed.
pub fn parse(document: &str) -> Result<RecoveryKit, RecoveryError> {
    if document.len() > MAX_RECOVERY_KIT_BYTES {
        return Err(RecoveryError::KitTooLarge {
            len: document.len(),
            limit: MAX_RECOVERY_KIT_BYTES,
        });
    }
    let mut lines = document.lines().filter(|line| !line.trim().is_empty());
    let format = lines.next().ok_or(RecoveryError::MalformedKit {
        what: "an empty document",
    })?;
    if format.trim() != RECOVERY_KIT_FORMAT {
        return Err(RecoveryError::MalformedKit {
            what: "a first line that is not this kit format",
        });
    }

    let mut seed: Option<Zeroizing<Vec<u8>>> = None;
    let mut locator: Option<String> = None;
    let mut origins: Vec<String> = Vec::new();
    for line in lines {
        let (key, value) = line
            .trim()
            .split_once(": ")
            .ok_or(RecoveryError::MalformedKit {
                what: "a line that is not `key: value`",
            })?;
        match key {
            "seed" => {
                if seed.is_some() {
                    return Err(RecoveryError::MalformedKit {
                        what: "a document that names the seed twice",
                    });
                }
                seed = Some(decode_seed(value)?);
            }
            "locator" => {
                if locator.is_some() {
                    return Err(RecoveryError::MalformedKit {
                        what: "a document that names the locator twice",
                    });
                }
                locator = Some(value.to_owned());
            }
            "origin" => origins.push(value.to_owned()),
            _ => {
                return Err(RecoveryError::MalformedKit {
                    what: "a line this kit format does not define",
                });
            }
        }
    }

    let payload = seed.ok_or(RecoveryError::MalformedKit {
        what: "a document with no seed",
    })?;
    let locator = locator.ok_or(RecoveryError::MalformedKit {
        what: "a document with no bundle locator",
    })?;
    if origins.is_empty() {
        return Err(RecoveryError::MalformedKit {
            what: "a document with no service origin",
        });
    }

    let Ok(bytes) = <[u8; 32]>::try_from(&payload[..32]) else {
        unreachable!("the payload is thirty-six bytes");
    };
    let kit = RecoveryKit {
        profile_version: U64::new(RECOVERY_KIT_PROFILE_VERSION),
        seed: SecretBytes32::from_bytes(bytes),
        seed_checksum: Bytes::new(payload[32..].to_vec()),
        service_origins: origins,
        bundle_locator: locator,
    };
    // The checksum is the seed's own, so a mistyped document fails before anything is derived.
    kr_crypto::kdf::RecoverySeed::from_kit(&kit).map_err(|_| RecoveryError::MistypedKit)?;
    Ok(kit)
}

/// Renders the seed and its checksum as grouped Crockford base32.
fn grouped_seed(kit: &RecoveryKit) -> Zeroizing<String> {
    let mut payload = Zeroizing::new([0u8; PAYLOAD_LEN]);
    payload[..32].copy_from_slice(kit.seed.expose().as_slice());
    payload[32..].copy_from_slice(kit.seed_checksum.as_slice());

    let groups = SYMBOLS.div_ceil(GROUP);
    let mut out = Zeroizing::new(String::with_capacity(SYMBOLS + groups - 1));
    for index in 0..SYMBOLS {
        if index > 0 && index % GROUP == 0 {
            out.push('-');
        }
        out.push(char::from(
            ALPHABET[usize::from(five_bits(&payload, index))],
        ));
    }
    out
}

/// Returns the five bits at `index` of the payload, counting from its most significant bit.
///
/// The last group is short, so the bits past the end of the payload are zero and reading rejects a
/// document whose last symbol claims otherwise.
fn five_bits(payload: &[u8; PAYLOAD_LEN], index: usize) -> u8 {
    let mut value = 0u8;
    for offset in 0..5 {
        let bit = index * 5 + offset;
        let byte = bit / 8;
        let taken = if byte < PAYLOAD_LEN {
            (payload[byte] >> (7 - bit % 8)) & 1
        } else {
            0
        };
        value = (value << 1) | taken;
    }
    value
}

/// Reads a grouped Crockford base32 seed back.
fn decode_seed(text: &str) -> Result<Zeroizing<Vec<u8>>, RecoveryError> {
    let mut symbols = Zeroizing::new(Vec::with_capacity(SYMBOLS));
    for character in text.chars() {
        if character == '-' || character == ' ' {
            continue;
        }
        symbols.push(symbol_value(character).ok_or(RecoveryError::MalformedKit {
            what: "a character the recovery alphabet does not use",
        })?);
    }
    if symbols.len() != SYMBOLS {
        return Err(RecoveryError::MalformedKit {
            what: "a seed that is not the length this format writes",
        });
    }

    let mut payload = Zeroizing::new(vec![0u8; PAYLOAD_LEN]);
    let mut accumulator = 0u16;
    let mut bits = 0u32;
    let mut written = 0usize;
    for symbol in symbols.iter() {
        accumulator = (accumulator << 5) | u16::from(*symbol);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            let Ok(byte) = u8::try_from((accumulator >> bits) & 0xff) else {
                unreachable!("eight bits");
            };
            if written < PAYLOAD_LEN {
                payload[written] = byte;
                written += 1;
            } else if byte != 0 {
                return Err(RecoveryError::MalformedKit {
                    what: "a seed with content past its own length",
                });
            }
        }
    }
    // The final symbol carries two bits the payload does not use. This build writes them as zero,
    // so a document that sets them is not one this build produced.
    if accumulator & ((1 << bits) - 1) != 0 {
        return Err(RecoveryError::MalformedKit {
            what: "a seed whose last symbol is not canonical",
        });
    }
    Ok(payload)
}

/// Returns the value of one base32 symbol, accepting either case and the three confusable letters.
fn symbol_value(character: char) -> Option<u8> {
    let upper = character.to_ascii_uppercase();
    // `I` and `L` are how a hand-written `1` is read back, and `O` is how a `0` is; the alphabet
    // leaves all three out so that reading them as digits is unambiguous rather than a guess.
    let upper = match upper {
        'I' | 'L' => '1',
        'O' => '0',
        other => other,
    };
    ALPHABET
        .iter()
        .position(|candidate| char::from(*candidate) == upper)
        .and_then(|position| u8::try_from(position).ok())
}

/// Refuses a value a line-oriented document cannot carry unambiguously.
///
/// Printable ASCII, and no leading or trailing space. Reading trims the line, so a value that ends
/// in a space would come back a different string, and a different locator or origin derives a
/// different bundle key: the kit would round-trip to something that authenticates nothing.
fn check_printable(what: &'static str, value: &str) -> Result<(), RecoveryError> {
    if value.is_empty() {
        return Err(RecoveryError::UnprintableKit { what });
    }
    if value.trim() != value {
        return Err(RecoveryError::UnprintableKit { what });
    }
    if value
        .bytes()
        .any(|byte| !(0x21..=0x7e).contains(&byte) && byte != b' ')
    {
        return Err(RecoveryError::UnprintableKit { what });
    }
    Ok(())
}

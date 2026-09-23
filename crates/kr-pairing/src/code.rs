//! The ten-character short code.
//!
//! Section 10 displays it as `XXXX-XXX-XXX`: four Base58 characters locate a temporary rendezvous
//! record and six are the PAKE secret. The locator is not secret and the six characters never
//! enter a service request, a URL, a log or an analytics event.
//!
//! Six characters from a 58-character alphabet carry about 35.15 bits. Five guesses against the
//! host therefore succeed with probability at most `5 / 58^6`, about 1.3e-10, and that bound holds
//! only because the PAKE prevents an offline guess: the locator adds no secret entropy.

use core::fmt;

use kr_crypto::secret::Secret;
use kr_protocol::pairing::{BASE58_ALPHABET, CODE_LEN, CODE_SECRET_LEN, LOCATOR_LEN, Locator};

use crate::error::{PairingError, Result};

/// The number of characters in the alphabet.
const ALPHABET_LEN: u8 = 58;

/// A generated ten-character code, before it is split into its two halves.
///
/// The type exists so a caller cannot accidentally print or log a whole code: only the locator has
/// a `Display`, and the secret half is reachable only through [`Self::secret`].
#[derive(Clone)]
pub struct GeneratedCode {
    locator: Locator,
    secret: CodeSecret,
}

impl GeneratedCode {
    /// Returns the locator half, which the client sends to the rendezvous service.
    #[must_use]
    pub const fn locator(&self) -> &Locator {
        &self.locator
    }

    /// Returns the six secret characters, which never leave the two devices.
    #[must_use]
    pub const fn secret(&self) -> &CodeSecret {
        &self.secret
    }

    /// Returns the canonical display form `XXXX-XXX-XXX`, in a buffer that clears itself.
    #[must_use]
    pub fn display_text(&self) -> zeroize::Zeroizing<String> {
        let secret = self.secret.expose_text();
        let mut text = zeroize::Zeroizing::new(String::with_capacity(CODE_LEN + 2));
        text.push_str(self.locator.as_str());
        text.push('-');
        text.push_str(&secret[..3]);
        text.push('-');
        text.push_str(&secret[3..]);
        text
    }
}

impl fmt::Debug for GeneratedCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "GeneratedCode({}-...-...)", self.locator)
    }
}

/// The six secret characters of a short code.
///
/// They are the PAKE password. The bytes clear when the value is dropped, and the type refuses to
/// print itself.
#[derive(Clone)]
pub struct CodeSecret(Secret<CODE_SECRET_LEN>);

impl CodeSecret {
    /// Wraps six characters after checking that each is in the alphabet.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::MalformedCode`] when the text is not six alphabet characters.
    pub fn new(text: &str) -> Result<Self> {
        let bytes = text.as_bytes();
        if bytes.len() != CODE_SECRET_LEN || !text.chars().all(is_base58) {
            return Err(PairingError::MalformedCode);
        }
        let mut out = [0u8; CODE_SECRET_LEN];
        out.copy_from_slice(bytes);
        let secret = Self(Secret::from_bytes(out));
        kr_crypto::zeroise(&mut out);
        Ok(secret)
    }

    /// Returns the six characters.
    ///
    /// They are the password the PAKE is run with, and nothing else reads them.
    #[must_use]
    pub fn expose(&self) -> &[u8; CODE_SECRET_LEN] {
        self.0.expose()
    }

    /// Returns the six characters as text, in a buffer that clears itself.
    #[must_use]
    pub fn expose_text(&self) -> zeroize::Zeroizing<String> {
        zeroize::Zeroizing::new(
            String::from_utf8(self.0.expose().to_vec())
                .expect("a code secret is alphabet characters"),
        )
    }
}

impl fmt::Debug for CodeSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CodeSecret(redacted)")
    }
}

/// Returns true when `character` is in the Bitcoin Base58 alphabet.
#[must_use]
pub fn is_base58(character: char) -> bool {
    BASE58_ALPHABET.contains(character)
}

/// Generates a fresh ten-character code from libsodium's random generator.
///
/// Characters are drawn with rejection sampling: a byte of 232 or more is discarded rather than
/// reduced, because reducing it would make the first 24 characters of the alphabet likelier than
/// the rest and cost the code part of the entropy the section 10 bound assumes.
///
/// # Errors
///
/// Returns an error when libsodium is unavailable.
pub fn generate_code() -> Result<GeneratedCode> {
    let mut characters = [0u8; CODE_LEN];
    for slot in &mut characters {
        *slot = sample_character()?;
    }
    let locator = Locator::new(
        core::str::from_utf8(&characters[..LOCATOR_LEN]).expect("alphabet characters are ASCII"),
    )
    .expect("generated characters are in the alphabet");
    let secret = CodeSecret::new(
        core::str::from_utf8(&characters[LOCATOR_LEN..]).expect("alphabet characters are ASCII"),
    )?;
    kr_crypto::zeroise(&mut characters);
    Ok(GeneratedCode { locator, secret })
}

/// The largest byte that can be reduced without bias: the last whole multiple of 58 below 256.
const REJECTION_BOUND: u8 = (256 / ALPHABET_LEN as u16 * ALPHABET_LEN as u16 - 1) as u8;

/// Draws one uniform alphabet character.
fn sample_character() -> Result<u8> {
    let alphabet = BASE58_ALPHABET.as_bytes();
    loop {
        let byte = kr_crypto::random_byte()?;
        if byte <= REJECTION_BOUND {
            return Ok(alphabet[usize::from(byte % ALPHABET_LEN)]);
        }
    }
}

/// One entered code, normalised and split.
///
/// Section 10 fixes the parsing rule: remove ASCII spaces and hyphens, preserve case, and require
/// exactly ten valid characters. Preserving case matters because the alphabet distinguishes `a`
/// from `A`, and folding it would throw away entropy the bound depends on.
#[derive(Clone)]
pub struct EnteredCode {
    locator: Locator,
    secret: CodeSecret,
    normalised: zeroize::Zeroizing<String>,
}

impl EnteredCode {
    /// Parses text a person typed or a QR payload carried.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::MalformedCode`] when the text does not hold exactly ten alphabet
    /// characters once spaces and hyphens are removed.
    pub fn parse(text: &str) -> Result<Self> {
        let mut normalised = zeroize::Zeroizing::new(String::with_capacity(CODE_LEN));
        for character in text.chars() {
            match character {
                ' ' | '-' => {}
                character if is_base58(character) => {
                    if normalised.chars().count() == CODE_LEN {
                        // An eleventh valid character is a different code, not a longer one.
                        return Err(PairingError::MalformedCode);
                    }
                    normalised.push(character);
                }
                _ => return Err(PairingError::MalformedCode),
            }
        }
        if normalised.chars().count() != CODE_LEN {
            return Err(PairingError::MalformedCode);
        }
        Ok(Self {
            locator: Locator::new(&normalised[..LOCATOR_LEN]).map_err(|_| {
                // Unreachable: every character passed `is_base58` above.
                PairingError::MalformedCode
            })?,
            secret: CodeSecret::new(&normalised[LOCATOR_LEN..])?,
            normalised,
        })
    }

    /// Returns the locator, which is the only part a client sends to the service.
    #[must_use]
    pub const fn locator(&self) -> &Locator {
        &self.locator
    }

    /// Returns the six secret characters.
    #[must_use]
    pub const fn secret(&self) -> &CodeSecret {
        &self.secret
    }

    /// Returns the normalised ten characters, without separators.
    ///
    /// The client-side attempt counter is keyed by an HMAC of the configured origin and this
    /// value, so two spellings of one code share a counter.
    #[must_use]
    pub fn normalised(&self) -> &str {
        &self.normalised
    }
}

impl fmt::Debug for EnteredCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "EnteredCode({}-...-...)", self.locator)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// KR-REQ-10.04, KR-REQ-10.11: a code is ten Base58 characters shown as `XXXX-XXX-XXX`.
    #[test]
    fn a_generated_code_is_ten_alphabet_characters() {
        let code = generate_code().expect("libsodium is available");
        assert_eq!(code.locator().as_str().chars().count(), LOCATOR_LEN);
        assert!(code.locator().as_str().chars().all(is_base58));
        let secret = code.secret().expose_text();
        assert_eq!(secret.chars().count(), CODE_SECRET_LEN);
        assert!(secret.chars().all(is_base58));
        let display = code.display_text();
        assert_eq!(display.len(), CODE_LEN + 2);
        assert_eq!(display.as_bytes()[LOCATOR_LEN], b'-');
        assert_eq!(display.as_bytes()[LOCATOR_LEN + 4], b'-');
    }

    #[test]
    fn two_generated_codes_differ() {
        let first = generate_code().expect("a code");
        let second = generate_code().expect("a code");
        assert_ne!(
            first.display_text().as_str(),
            second.display_text().as_str()
        );
    }

    /// KR-REQ-10.11: rejection sampling draws every character uniformly.
    #[test]
    fn generation_covers_the_whole_alphabet_without_a_bias_towards_its_start() {
        // Rejection sampling is what keeps the distribution uniform. A modulo without it would
        // make the first 256 - 232 = 24 characters appear half again as often, so this counts a
        // large sample and checks that no character is missing and none is wildly over-represented.
        let mut counts = std::collections::BTreeMap::new();
        for _ in 0..600 {
            let code = generate_code().expect("a code");
            for character in code.display_text().chars().filter(|c| *c != '-') {
                *counts.entry(character).or_insert(0usize) += 1;
            }
        }
        assert_eq!(
            counts.len(),
            BASE58_ALPHABET.chars().count(),
            "every character appears"
        );
        let total: usize = counts.values().sum();
        let expected = total / BASE58_ALPHABET.chars().count();
        for (character, count) in &counts {
            assert!(
                *count * 2 > expected && *count < expected * 2,
                "{character} appeared {count} times against an expected {expected}"
            );
        }
    }

    /// KR-REQ-10.11: generation discards the bytes a bare modulo would fold onto the start of the
    /// alphabet. Reducing every random byte modulo 58 would give each of the first 24 characters
    /// 5/256 and each of the other 34 4/256, so those 24 would make up 46.9% of a large sample
    /// rather than their fair 24/58, 41.4%. Across 30,000 characters the fair share varies by
    /// about 0.3 percentage points, so the 38.8% and 44% lines each sit more than eight standard
    /// deviations from the fair share and the 44% line more than ten from the biased one.
    #[test]
    fn the_start_of_the_alphabet_gets_its_fair_share_and_no_more() {
        let favoured: std::collections::BTreeSet<char> = BASE58_ALPHABET.chars().take(24).collect();
        let (mut hits, mut total) = (0usize, 0usize);
        for _ in 0..3_000 {
            let code = generate_code().expect("a code");
            for character in code.display_text().chars().filter(|c| *c != '-') {
                total += 1;
                if favoured.contains(&character) {
                    hits += 1;
                }
            }
        }
        assert_eq!(total, 30_000);
        assert!(
            hits * 1_000 > total * 388 && hits * 100 < total * 44,
            "the first 24 characters took {hits} of {total} draws"
        );
    }

    /// KR-REQ-10.11: the rejection bound keeps the draw unbiased.
    #[test]
    fn the_rejection_bound_is_the_last_whole_multiple_of_the_alphabet() {
        assert_eq!(REJECTION_BOUND, 231);
        assert_eq!(
            (u16::from(REJECTION_BOUND) + 1) % u16::from(ALPHABET_LEN),
            0
        );
    }

    /// KR-REQ-10.11: parsing removes spaces and hyphens and preserves case.
    #[test]
    fn parsing_removes_separators_and_preserves_case() {
        let plain = EnteredCode::parse("aB3xYz79Qw").expect("a code");
        let grouped = EnteredCode::parse("aB3x-Yz7-9Qw").expect("a code");
        let spaced = EnteredCode::parse(" aB3x Yz7 9Qw ").expect("a code");
        assert_eq!(plain.normalised(), "aB3xYz79Qw");
        assert_eq!(grouped.normalised(), plain.normalised());
        assert_eq!(spaced.normalised(), plain.normalised());
        assert_eq!(plain.locator().as_str(), "aB3x");

        // Case is part of the code: folding it would throw away entropy.
        let other = EnteredCode::parse("Ab3xYz79Qw").expect("a code");
        assert_ne!(other.normalised(), plain.normalised());
    }

    /// KR-REQ-10.11, KR-REQ-10.04: parsing needs exactly ten Base58 characters.
    #[test]
    fn parsing_requires_exactly_ten_valid_characters() {
        assert!(EnteredCode::parse("aB3xYz79Q").is_err());
        assert!(EnteredCode::parse("aB3xYz79QwX").is_err());
        assert!(EnteredCode::parse("").is_err());
        // 0, O, I and l are outside the Bitcoin alphabet.
        assert!(EnteredCode::parse("0B3xYz79Qw").is_err());
        assert!(EnteredCode::parse("aB3xYz79Q!").is_err());
        assert!(EnteredCode::parse("aB3xYz79Q\u{00e9}").is_err());
    }

    /// KR-REQ-10.12: the six secret characters never appear in a log or debug rendering.
    #[test]
    fn a_code_redacts_its_secret_half() {
        let code = EnteredCode::parse("aB3x-Yz7-9Qw").expect("a code");
        let rendered = format!("{code:?}");
        assert_eq!(rendered, "EnteredCode(aB3x-...-...)");
        assert!(!rendered.contains("Yz7"));
        assert_eq!(format!("{:?}", code.secret()), "CodeSecret(redacted)");

        let generated = generate_code().expect("a code");
        assert!(format!("{generated:?}").ends_with("-...-...)"));
    }

    /// KR-REQ-10.11: the secret half is six Base58 characters.
    #[test]
    fn a_secret_is_six_alphabet_characters() {
        assert!(CodeSecret::new("Yz79Qw").is_ok());
        assert!(CodeSecret::new("Yz79Q").is_err());
        assert!(CodeSecret::new("Yz79Qwx").is_err());
        assert!(CodeSecret::new("Yz79Q0").is_err());
    }

    /// KR-REQ-10.12: locators are drawn from the whole four-character space.
    #[test]
    fn locators_are_drawn_from_the_whole_space() {
        // A locator collision makes the host generate another one; this checks that generation
        // does not keep producing the same few.
        let locators: BTreeSet<String> = (0..64)
            .map(|_| {
                generate_code()
                    .expect("a code")
                    .locator()
                    .as_str()
                    .to_owned()
            })
            .collect();
        assert!(locators.len() > 60, "{} distinct locators", locators.len());
    }
}

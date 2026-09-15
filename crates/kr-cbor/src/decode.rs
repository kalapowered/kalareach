//! The strict decoder.
//!
//! The decoder reads the bytes directly rather than delegating to a general CBOR reader, because
//! every forbidden representation has to be rejected by its own rule and a general reader
//! discards the evidence: a value tree cannot tell you whether a length was indefinite, whether an
//! argument used a longer head than necessary, whether two keys collided or what order the keys
//! arrived in. The decoder therefore owns the byte rules and hands a validated tree to the
//! maintained serde implementation.
//!
//! As a last check it re-encodes the tree and requires the input bytes back, so a reader that
//! normalised something instead of rejecting it fails here rather than producing a signature over
//! a different value.

use core::cmp::Ordering;

use crate::error::{CborError, Result};
use crate::limits::Limits;
use crate::value::{CanonicalMap, CanonicalValue, Integer, compare_keys};

/// Decodes exactly one canonical object from `bytes`.
///
/// # Errors
///
/// Returns the first rule the input breaks, including trailing bytes after the object.
pub fn decode(bytes: &[u8], limits: &Limits) -> Result<CanonicalValue> {
    if bytes.len() > limits.max_message_len {
        return Err(CborError::InputTooLarge {
            len: bytes.len(),
            limit: limits.max_message_len,
        });
    }
    if bytes.is_empty() {
        return Err(CborError::EmptyInput);
    }
    let mut reader = Reader {
        input: bytes,
        offset: 0,
        items: 0,
        limits,
    };
    let value = reader.read_value(1)?;
    let remaining = bytes.len() - reader.offset;
    if remaining > 0 {
        return Err(CborError::TrailingBytes { count: remaining });
    }
    // Every rule is already checked above, so this should be unreachable. It is here because
    // canonicity is what signatures rest on: a reader that normalised something instead of
    // rejecting it would show up as different bytes rather than as a valid signature over the
    // wrong value.
    if crate::encode::encode(&value) != bytes {
        return Err(CborError::NonCanonical);
    }
    Ok(value)
}

/// Which rule a non-shortest head breaks.
#[derive(Debug, Clone, Copy)]
enum HeadKind {
    Integer,
    Length,
}

struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
    items: usize,
    limits: &'a Limits,
}

impl Reader<'_> {
    fn remaining(&self) -> usize {
        self.input.len() - self.offset
    }

    fn take(&mut self, count: usize) -> Result<&[u8]> {
        if self.remaining() < count {
            return Err(CborError::UnexpectedEnd {
                offset: self.input.len(),
            });
        }
        let start = self.offset;
        self.offset += count;
        Ok(&self.input[start..self.offset])
    }

    fn count_item(&mut self) -> Result<()> {
        self.items += 1;
        if self.items > self.limits.max_items {
            return Err(CborError::CountLimit {
                limit: self.limits.max_items,
            });
        }
        Ok(())
    }

    fn read_argument(&mut self, additional: u8, kind: HeadKind, head_offset: usize) -> Result<u64> {
        let non_shortest = || match kind {
            HeadKind::Integer => CborError::NonShortestInteger {
                offset: head_offset,
            },
            HeadKind::Length => CborError::NonShortestLength {
                offset: head_offset,
            },
        };
        match additional {
            0..=23 => Ok(u64::from(additional)),
            24 => {
                let value = u64::from(self.take(1)?[0]);
                if value < 24 {
                    return Err(non_shortest());
                }
                Ok(value)
            }
            25 => {
                let bytes: [u8; 2] = self.take(2)?.try_into().expect("two bytes");
                let value = u64::from(u16::from_be_bytes(bytes));
                if value <= u64::from(u8::MAX) {
                    return Err(non_shortest());
                }
                Ok(value)
            }
            26 => {
                let bytes: [u8; 4] = self.take(4)?.try_into().expect("four bytes");
                let value = u64::from(u32::from_be_bytes(bytes));
                if value <= u64::from(u16::MAX) {
                    return Err(non_shortest());
                }
                Ok(value)
            }
            27 => {
                let bytes: [u8; 8] = self.take(8)?.try_into().expect("eight bytes");
                let value = u64::from_be_bytes(bytes);
                if value <= u64::from(u32::MAX) {
                    return Err(non_shortest());
                }
                Ok(value)
            }
            _ => unreachable!("additional information 28..=31 is handled before the argument"),
        }
    }

    fn check_string_len(&self, len: u64, limit: usize) -> Result<usize> {
        if len > limit as u64 {
            return Err(CborError::LengthLimit { len, limit });
        }
        // Reject a declared length that the remaining input cannot supply before allocating.
        if len > self.remaining() as u64 {
            return Err(CborError::UnexpectedEnd {
                offset: self.input.len(),
            });
        }
        Ok(usize::try_from(len).expect("checked against a usize limit"))
    }

    fn check_collection_len(&self, len: u64, members_per_entry: u64) -> Result<usize> {
        let limit = self.limits.max_collection_len;
        if len > limit as u64 {
            return Err(CborError::CollectionLimit { len, limit });
        }
        // Every member needs at least one byte, so a declared count larger than the remaining
        // input is rejected before any capacity is reserved.
        let minimum_bytes = len.saturating_mul(members_per_entry);
        if minimum_bytes > self.remaining() as u64 {
            return Err(CborError::UnexpectedEnd {
                offset: self.input.len(),
            });
        }
        Ok(usize::try_from(len).expect("checked against a usize limit"))
    }

    /// Checks the depth and item budgets a collection is about to consume.
    ///
    /// A collection reserves capacity for its members, so the budget for those members has to be
    /// checked before the reservation rather than while reading them.
    fn reserve_items(&self, members: usize, member_depth: usize) -> Result<()> {
        // An empty collection has no children, so it does not consume the depth its members would.
        if members > 0 && member_depth > self.limits.max_depth {
            return Err(CborError::DepthLimit {
                limit: self.limits.max_depth,
            });
        }
        if self.items.saturating_add(members) > self.limits.max_items {
            return Err(CborError::CountLimit {
                limit: self.limits.max_items,
            });
        }
        Ok(())
    }

    fn read_value(&mut self, depth: usize) -> Result<CanonicalValue> {
        if depth > self.limits.max_depth {
            return Err(CborError::DepthLimit {
                limit: self.limits.max_depth,
            });
        }
        self.count_item()?;
        let head_offset = self.offset;
        let initial = self.take(1)?[0];
        let major = initial >> 5;
        let additional = initial & 0x1f;

        if additional >= 28 {
            return Err(match (major, additional) {
                (2..=5, 31) => CborError::IndefiniteLength {
                    offset: head_offset,
                },
                (7, 31) => CborError::BreakOutsideIndefinite {
                    offset: head_offset,
                },
                _ => CborError::ReservedAdditionalInfo {
                    value: additional,
                    offset: head_offset,
                },
            });
        }

        match major {
            0 => {
                let argument = self.read_argument(additional, HeadKind::Integer, head_offset)?;
                Ok(CanonicalValue::Integer(Integer::from(argument)))
            }
            1 => {
                let argument = self.read_argument(additional, HeadKind::Integer, head_offset)?;
                let value = -1 - i128::from(argument);
                Ok(CanonicalValue::Integer(Integer::new(value)?))
            }
            2 => {
                let argument = self.read_argument(additional, HeadKind::Length, head_offset)?;
                let len = self.check_string_len(argument, self.limits.max_bytes_len)?;
                Ok(CanonicalValue::Bytes(self.take(len)?.to_vec()))
            }
            3 => Ok(CanonicalValue::Text(
                self.read_text(additional, head_offset)?,
            )),
            4 => {
                let argument = self.read_argument(additional, HeadKind::Length, head_offset)?;
                let len = self.check_collection_len(argument, 1)?;
                self.reserve_items(len, depth + 1)?;
                let mut items = Vec::with_capacity(len);
                for _ in 0..len {
                    items.push(self.read_value(depth + 1)?);
                }
                Ok(CanonicalValue::Array(items))
            }
            5 => self.read_map(additional, head_offset, depth),
            6 => {
                let tag = self.read_argument(additional, HeadKind::Integer, head_offset)?;
                Err(CborError::Tag {
                    tag,
                    offset: head_offset,
                })
            }
            _ => self.read_simple(additional, head_offset),
        }
    }

    fn read_text(&mut self, additional: u8, head_offset: usize) -> Result<String> {
        let argument = self.read_argument(additional, HeadKind::Length, head_offset)?;
        let len = self.check_string_len(argument, self.limits.max_text_len)?;
        let body_offset = self.offset;
        let body = self.take(len)?;
        core::str::from_utf8(body)
            .map(str::to_owned)
            .map_err(|_| CborError::InvalidUtf8 {
                offset: body_offset,
            })
    }

    fn read_map(
        &mut self,
        additional: u8,
        head_offset: usize,
        depth: usize,
    ) -> Result<CanonicalValue> {
        let argument = self.read_argument(additional, HeadKind::Length, head_offset)?;
        let len = self.check_collection_len(argument, 2)?;
        // Two items per entry: the key and its value.
        self.reserve_items(len.saturating_mul(2), depth + 1)?;
        let mut entries: Vec<(String, CanonicalValue)> = Vec::with_capacity(len);
        for _ in 0..len {
            self.count_item()?;
            let key_offset = self.offset;
            let key_initial = *self.input.get(key_offset).ok_or(CborError::UnexpectedEnd {
                offset: self.input.len(),
            })?;
            if key_initial >> 5 != 3 {
                return Err(CborError::NonTextMapKey { offset: key_offset });
            }
            let key_additional = key_initial & 0x1f;
            // A key head carries the same reserved and indefinite rules as any other head, and it
            // has to be checked here: read_text would otherwise be handed an argument it cannot
            // read.
            if key_additional >= 28 {
                return Err(if key_additional == 31 {
                    CborError::IndefiniteLength { offset: key_offset }
                } else {
                    CborError::ReservedAdditionalInfo {
                        value: key_additional,
                        offset: key_offset,
                    }
                });
            }
            self.offset += 1;
            let key = self.read_text(key_additional, key_offset)?;
            if let Some((previous, _)) = entries.last() {
                match compare_keys(previous, &key) {
                    Ordering::Less => {}
                    Ordering::Equal => return Err(CborError::DuplicateKey { key }),
                    Ordering::Greater => {
                        return Err(CborError::UnsortedMapKeys {
                            previous: previous.clone(),
                            current: key,
                        });
                    }
                }
            }
            let value = self.read_value(depth + 1)?;
            entries.push((key, value));
        }
        Ok(CanonicalValue::Map(CanonicalMap::from_sorted_entries(
            entries,
        )?))
    }

    fn read_simple(&mut self, additional: u8, head_offset: usize) -> Result<CanonicalValue> {
        match additional {
            20 => Ok(CanonicalValue::Bool(false)),
            21 => Ok(CanonicalValue::Bool(true)),
            22 => Ok(CanonicalValue::Null),
            23 => Err(CborError::Undefined {
                offset: head_offset,
            }),
            24 => {
                let value = self.take(1)?[0];
                Err(CborError::SimpleValue {
                    value,
                    offset: head_offset,
                })
            }
            25..=27 => Err(CborError::Float {
                offset: head_offset,
            }),
            _ => Err(CborError::SimpleValue {
                value: additional,
                offset: head_offset,
            }),
        }
    }
}

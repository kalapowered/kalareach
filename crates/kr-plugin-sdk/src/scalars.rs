//! The scalars these types are built from.
//!
//! Most of them are defined in `kr-protocol` and re-exported here, so a consumer can name every
//! type in this crate's public interface without depending on the protocol crate as well.
//!
//! [`SafeInt`] is the exception. Section 4 makes JSON the managed representation and requires
//! unsigned 64-bit counters to travel as decimal strings, because a JavaScript number cannot carry
//! them exactly. A signed value a person types into a control has the same problem above
//! 2^53, and a value that changes when it crosses a language boundary is a value nobody can
//! check. `SafeInt` is bounded to the range every language represents exactly, and it says so in
//! its schema rather than leaving a consumer to find out.

use core::fmt;
use core::str::FromStr;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize};

pub use kr_protocol::scalars::{Bytes, CanonicalSet, Nullable, TimestampMs, U64, Uuid};

/// The largest magnitude every supported language represents exactly, `2^53 - 1`.
pub const SAFE_INT_MAX: i64 = 9_007_199_254_740_991;

/// The smallest such value.
pub const SAFE_INT_MIN: i64 = -SAFE_INT_MAX;

/// A signed integer both Rust and JavaScript represent exactly.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct SafeInt(i64);

/// A value outside the range every supported language represents exactly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{value} is outside the exactly representable range {SAFE_INT_MIN} to {SAFE_INT_MAX}")]
pub struct SafeIntError {
    /// The rejected value.
    pub value: i64,
}

impl SafeInt {
    /// Wraps a value inside the exactly representable range.
    ///
    /// # Errors
    ///
    /// Returns [`SafeIntError`] when the value is outside that range.
    pub const fn new(value: i64) -> Result<Self, SafeIntError> {
        if value < SAFE_INT_MIN || value > SAFE_INT_MAX {
            return Err(SafeIntError { value });
        }
        Ok(Self(value))
    }

    /// Returns the value.
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }
}

impl fmt::Display for SafeInt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, formatter)
    }
}

impl FromStr for SafeInt {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let value: i64 = text
            .parse()
            .map_err(|_| format!("{text} is not an integer"))?;
        Self::new(value).map_err(|error| error.to_string())
    }
}

impl<'de> Deserialize<'de> for SafeInt {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = i64::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for SafeInt {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "SafeInt".into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        "kalareach::SafeInt".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "integer",
            "minimum": SAFE_INT_MIN,
            "maximum": SAFE_INT_MAX,
            "description": "A signed integer inside the range every supported language represents exactly, -(2^53 - 1) to 2^53 - 1."
        })
    }
}

/// A count of things, bounded so it is exact in every supported language.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Count(u32);

impl Count {
    /// The largest count a manifest may declare.
    pub const MAX: u32 = u32::MAX;

    /// Wraps a count.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the count.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl fmt::Display for Count {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, formatter)
    }
}

impl<'de> Deserialize<'de> for Count {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        u32::deserialize(deserializer).map(Self)
    }
}

impl JsonSchema for Count {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Count".into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        "kalareach::Count".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "integer",
            "minimum": 0,
            "maximum": Count::MAX,
            "description": "A count of things, from 0 to 4294967295."
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_safe_integer_rejects_values_javascript_cannot_hold() {
        assert!(SafeInt::new(SAFE_INT_MAX).is_ok());
        assert!(SafeInt::new(SAFE_INT_MIN).is_ok());
        assert_eq!(
            SafeInt::new(SAFE_INT_MAX + 1),
            Err(SafeIntError {
                value: SAFE_INT_MAX + 1
            })
        );
        assert!(serde_json::from_str::<SafeInt>("9007199254740992").is_err());
        assert_eq!(
            serde_json::from_str::<SafeInt>("-42").expect("in range"),
            SafeInt::new(-42).expect("in range")
        );
    }

    #[test]
    fn a_count_round_trips_as_a_json_number() {
        let count = Count::new(7);
        let text = serde_json::to_string(&count).expect("serialisable");
        assert_eq!(text, "7");
        assert_eq!(
            serde_json::from_str::<Count>(&text).expect("deserialisable"),
            count
        );
        assert!(serde_json::from_str::<Count>("4294967296").is_err());
    }
}

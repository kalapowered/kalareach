//! Package identifiers.
//!
//! A package is named by a publisher identifier and a plugin identifier, both immutable for the
//! life of the package. Nodes, controls and actions carry their own stable identifiers so a
//! client can address one element across revisions.
//!
//! Every identifier here is a slug: lower-case ASCII letters, digits, and single separators
//! between them. The narrow alphabet is deliberate. These identifiers become directory names in a
//! catalogue checkout, keys in an index and segments of a content path, so an identifier that
//! looks different in two places, or that changes meaning when a filesystem folds its case, is a
//! defect rather than a style preference.

use core::fmt;
use core::str::FromStr;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize};

pub use kr_protocol::ids::{CapabilityId, CapabilityRevision, PluginId, RepositoryGeneration};

/// Maximum length in bytes of a slug identifier.
pub const MAX_SLUG_LEN: usize = 64;

/// Text that is not a valid slug identifier.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SlugError {
    /// The slug was empty.
    #[error("identifier is empty")]
    Empty,
    /// The slug was longer than [`MAX_SLUG_LEN`] bytes.
    #[error("identifier is {len} bytes, over the {MAX_SLUG_LEN} byte limit")]
    TooLong {
        /// The byte length of the supplied text.
        len: usize,
    },
    /// The slug used a character outside the permitted alphabet.
    #[error("identifier contains {character:?}; use lower-case letters, digits, '-' and '.'")]
    ForbiddenCharacter {
        /// The offending character.
        character: char,
    },
    /// The slug started or ended with a separator, or repeated one.
    #[error("identifier has a leading, trailing or repeated separator")]
    Separator,
}

/// Checks the slug alphabet and separator placement.
///
/// # Errors
///
/// Returns [`SlugError`] describing the first rule the text breaks.
pub fn validate_slug(text: &str) -> Result<(), SlugError> {
    if text.is_empty() {
        return Err(SlugError::Empty);
    }
    if text.len() > MAX_SLUG_LEN {
        return Err(SlugError::TooLong { len: text.len() });
    }
    let mut previous_was_separator = true;
    for character in text.chars() {
        let is_separator = matches!(character, '-' | '.');
        if !is_separator && !character.is_ascii_lowercase() && !character.is_ascii_digit() {
            return Err(SlugError::ForbiddenCharacter { character });
        }
        if is_separator && previous_was_separator {
            return Err(SlugError::Separator);
        }
        previous_was_separator = is_separator;
    }
    if previous_was_separator {
        return Err(SlugError::Separator);
    }
    Ok(())
}

macro_rules! slug_id {
    ($(#[$meta:meta])* $name:ident, $description:literal) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Wraps text after checking the slug rules.
            ///
            /// # Errors
            ///
            /// Returns [`SlugError`] when the text is not a valid slug.
            pub fn new(value: impl Into<String>) -> Result<Self, SlugError> {
                let value = value.into();
                validate_slug(&value)?;
                Ok(Self(value))
            }

            /// Returns the identifier text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = SlugError;

            fn from_str(text: &str) -> Result<Self, Self::Err> {
                Self::new(text)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text = String::deserialize(deserializer)?;
                Self::new(text).map_err(serde::de::Error::custom)
            }
        }

        impl JsonSchema for $name {
            fn schema_name() -> std::borrow::Cow<'static, str> {
                stringify!($name).into()
            }

            fn schema_id() -> std::borrow::Cow<'static, str> {
                concat!("kalareach::", stringify!($name)).into()
            }

            fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
                json_schema!({
                    "type": "string",
                    "minLength": 1,
                    "maxLength": MAX_SLUG_LEN,
                    "pattern": "^[a-z0-9]+([.-][a-z0-9]+)*$",
                    "description": $description
                })
            }
        }
    };
}

slug_id!(
    /// The publisher that signs and maintains a package. Immutable for the package's life.
    PublisherId,
    "The publisher that signs and maintains a package. Immutable for the package's life."
);
slug_id!(
    /// A package-local plugin identifier, unique under its publisher.
    ///
    /// The catalogue addresses a package as publisher plus name; [`PluginId`] is the same pair
    /// written as one string for the wire.
    PluginName,
    "A package-local plugin identifier, unique under its publisher."
);
slug_id!(
    /// An action registered in the package manifest and invoked by a control.
    ///
    /// A control may only name an action the manifest registers, so the effect class the broker
    /// enforces is always the one the publisher declared and a reviewer read.
    ActionName,
    "An action registered in the package manifest. A control may only name a registered action."
);
slug_id!(
    /// The stable identifier of one document node.
    NodeId,
    "The stable identifier of one document node."
);
slug_id!(
    /// The stable identifier of one control.
    ControlId,
    "The stable identifier of one control."
);
slug_id!(
    /// The name of one parameter in an action's parameter schema.
    ParameterName,
    "The name of one parameter in an action's parameter schema."
);
slug_id!(
    /// A native protocol method name as the upstream application spells it.
    ///
    /// Vendor methods are written in many styles; the slug rules keep the classification table
    /// readable and its keys unambiguous. A vendor whose wire spelling differs from its slug
    /// records the wire spelling in the route.
    MethodName,
    "A native protocol method name in the connector's classification table."
);

/// Joins a publisher and plugin name into the wire [`PluginId`].
///
/// # Panics
///
/// Panics when the joined identifier exceeds the opaque identifier bound, which cannot happen for
/// two slugs of at most [`MAX_SLUG_LEN`] bytes.
#[must_use]
pub fn plugin_id(publisher: &PublisherId, name: &PluginName) -> PluginId {
    PluginId::new(format!("{publisher}/{name}")).expect("two slugs join to a bounded identifier")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_identifiers() {
        assert!(PublisherId::new("kalareach").is_ok());
        assert!(PluginName::new("claude-code").is_ok());
        assert!(PluginName::new("example.declarative").is_ok());
    }

    #[test]
    fn rejects_case_and_separator_abuse() {
        assert_eq!(
            PublisherId::new("KalaReach"),
            Err(SlugError::ForbiddenCharacter { character: 'K' })
        );
        assert_eq!(PluginName::new("-leading"), Err(SlugError::Separator));
        assert_eq!(PluginName::new("trailing-"), Err(SlugError::Separator));
        assert_eq!(PluginName::new("double--dash"), Err(SlugError::Separator));
        assert_eq!(PluginName::new(""), Err(SlugError::Empty));
    }

    #[test]
    fn rejects_path_and_separator_characters() {
        for text in ["a/b", "a\\b", "a b", "a_b", "..", "a:b"] {
            assert!(PluginName::new(text).is_err(), "accepted {text:?}");
        }
    }

    #[test]
    fn joins_into_the_wire_identifier() {
        let publisher = PublisherId::new("kalareach").expect("valid publisher");
        let name = PluginName::new("example-declarative").expect("valid name");
        assert_eq!(
            plugin_id(&publisher, &name).as_str(),
            "kalareach/example-declarative"
        );
    }
}

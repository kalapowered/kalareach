//! Schema-directed checks on a decoded value, run before typed deserialisation.
//!
//! Section 9 refuses duplicate keys, invalid UTF-8 and unrecognised fields before ordinary
//! deserialisation. [`crate::decode`] refuses the first two, with every other byte rule, before it
//! builds a value. A byte reader cannot know which keys a message's schema declares; that takes the
//! schema. [`check`] reads the decoded value against a [`Shape`] that describes the message's
//! structure and refuses a key the schema does not declare, so a typed decoder never sees a message
//! that names a field its type does not have.
//!
//! A shape describes structure and nothing else: which values are objects and which keys they
//! declare, which are arrays, maps keyed by data, one of several variants, or opaque. Scalar types,
//! ranges and required fields stay with the typed layer, which checks them anyway. Where a value's
//! kind does not match its shape (a map where the schema has text, say) the check does not look
//! inside it and the typed layer refuses it.
//!
//! Two kinds of undeclared key are not refused outright. An object whose schema says so may carry
//! fields a receiver does not know, and the receiver ignores them: [`Undeclared::Ignore`]. And a key
//! may name an extension, which a caller-supplied [`Extensions`] policy admits or refuses. Both kinds
//! are removed from the value the typed layer reads, and an admitted extension member is returned in
//! [`Checked::members`] rather than dropped.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::error::{CborError, Result};
use crate::value::{CanonicalMap, CanonicalValue};

/// The structure a message's schema declares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shape {
    /// Any value. The check does not look inside it.
    Any,
    /// A value that is neither an array nor a map.
    Scalar,
    /// An array whose every item has this shape.
    Array(Arc<Shape>),
    /// A map whose keys are data rather than field names. Every value has this shape.
    Map(Arc<Shape>),
    /// A map whose keys are the fields an object declares.
    Object(Arc<ObjectShape>),
    /// An object that is one of several variants, told apart by the text of one field.
    ///
    /// The field's value selects the variant whose fields apply, exactly as the typed decoder
    /// selects it, so a message that names one variant is never checked against another's fields.
    Tagged(Arc<TaggedShape>),
    /// A value that has one of these shapes.
    ///
    /// They are tried in order and the first that accepts the value decides. A shape that expects
    /// a container is not tried against a scalar, or the other way round, which is what tells a
    /// variant carried by name from a variant carried with content. Alternatives are only ever
    /// objects that declare different keys, or shapes of different kinds, so no two of them accept
    /// the same value; variants that share keys are a [`Shape::Tagged`].
    OneOf(Arc<[Shape]>),
}

/// Variants of one object, selected by the text of their tag field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaggedShape {
    tag: String,
    variants: BTreeMap<String, Arc<ObjectShape>>,
    any_variant: ObjectShape,
}

impl TaggedShape {
    /// Builds the variants of an object told apart by the field `tag`.
    ///
    /// Each variant's fields include the tag itself. `name` is the schema name of the whole union.
    #[must_use]
    pub fn new(
        name: Option<String>,
        tag: String,
        variants: BTreeMap<String, Arc<ObjectShape>>,
    ) -> Self {
        let mut fields: BTreeMap<String, Vec<Shape>> = BTreeMap::new();
        for variant in variants.values() {
            for (field, shape) in &variant.fields {
                let shapes = fields.entry(field.clone()).or_default();
                if !shapes.contains(shape) {
                    shapes.push(shape.clone());
                }
            }
        }
        let undeclared = if variants
            .values()
            .all(|variant| variant.undeclared == Undeclared::Ignore)
        {
            Undeclared::Ignore
        } else {
            Undeclared::Refuse
        };
        let any_variant = ObjectShape {
            name,
            fields: fields
                .into_iter()
                .map(|(field, mut shapes)| {
                    let shape = if shapes.len() == 1 {
                        shapes.remove(0)
                    } else {
                        Shape::OneOf(shapes.into())
                    };
                    (field, shape)
                })
                .collect(),
            undeclared,
        };
        Self {
            tag,
            variants,
            any_variant,
        }
    }

    /// The field whose text selects the variant.
    #[must_use]
    pub fn tag(&self) -> &str {
        &self.tag
    }

    /// Every variant, by the text of its tag.
    #[must_use]
    pub const fn variants(&self) -> &BTreeMap<String, Arc<ObjectShape>> {
        &self.variants
    }
}

/// One object: the fields it declares and what happens to a key it does not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectShape {
    /// The object's schema name, where it has one of its own.
    pub name: Option<String>,
    /// Every declared field, with its shape.
    pub fields: BTreeMap<String, Shape>,
    /// What happens to a key the object does not declare.
    pub undeclared: Undeclared,
}

/// What the check does with an ordinary key an object does not declare.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Undeclared {
    /// The message is refused. Every closed schema is this, and so is every mutation schema.
    Refuse,
    /// The entry is removed before typed decoding and never delivered. Read-only metadata may carry
    /// optional fields a receiver does not know, and the receiver ignores them.
    Ignore,
}

/// Decides the undeclared keys that name an extension.
///
/// The check asks about every key an object does not declare, before the object's
/// [`Undeclared`] rule applies, so a policy sees an extension member even in an object that would
/// otherwise ignore an unknown field.
pub trait Extensions {
    /// Classifies `key`, which `object` does not declare.
    fn classify(&self, object: &ObjectShape, key: &str) -> Member;
}

/// What an undeclared key is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Member {
    /// An ordinary field. The object's [`Undeclared`] rule decides.
    Field,
    /// A member of an extension admitted in this object, whose value has the given shape. The
    /// value is checked against it, then removed before typed decoding and returned in
    /// [`Checked::members`].
    Admitted(Arc<Shape>),
    /// A member of an extension that is not admitted in this object. The message is refused.
    Refused,
}

/// A value that passed the check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checked<'a> {
    /// What typed decoding reads: the input less any ignored field and admitted extension member.
    /// It borrows the input when nothing was removed.
    pub value: Cow<'a, CanonicalValue>,
    /// The admitted extension members, in the order the check met them.
    pub members: Vec<AdmittedMember>,
}

/// One admitted extension member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedMember {
    /// The schema name of the object that carried it, where the object has one.
    pub object: Option<String>,
    /// Where that object is in the message, as a JSON Pointer.
    pub path: String,
    /// The member's key.
    pub key: String,
    /// The member's value.
    pub value: CanonicalValue,
}

/// Checks a decoded value against a shape.
///
/// # Errors
///
/// Returns [`CborError::UnknownField`] for an undeclared ordinary key in an object that refuses
/// one, [`CborError::UnknownVariant`] for a tag naming no variant, and
/// [`CborError::UnnegotiatedExtension`] for an extension member the policy refuses. The error
/// names the object and where it is in the message.
pub fn check<'a>(
    value: &'a CanonicalValue,
    shape: &Shape,
    extensions: &dyn Extensions,
) -> Result<Checked<'a>> {
    let mut walk = Walk {
        extensions,
        members: Vec::new(),
        path: Vec::new(),
    };
    let rewritten = walk.value(value, shape).map_err(|failure| failure.error)?;
    Ok(Checked {
        value: rewritten.map_or(Cow::Borrowed(value), Cow::Owned),
        members: walk.members,
    })
}

/// One step of the path to the value being checked.
enum Step<'v> {
    Key(&'v str),
    Index(usize),
}

/// A refusal, with how deep in the message it was found.
///
/// Where several variants refuse a value, the refusal found deepest is the one reported: it comes
/// from the variant the value was written as, and the others refuse at the top.
struct Failure {
    error: CborError,
    depth: usize,
}

struct Walk<'e, 'v> {
    extensions: &'e dyn Extensions,
    members: Vec<AdmittedMember>,
    path: Vec<Step<'v>>,
}

/// `None` when the value is kept as it is; `Some` with the value to use instead.
type Rewrite = core::result::Result<Option<CanonicalValue>, Failure>;

impl<'v> Walk<'_, 'v> {
    fn value(&mut self, value: &'v CanonicalValue, shape: &Shape) -> Rewrite {
        match (shape, value) {
            (Shape::Array(item), CanonicalValue::Array(items)) => self.array(items, item),
            (Shape::Map(member), CanonicalValue::Map(map)) => self.map(map, member),
            (Shape::Object(object), CanonicalValue::Map(map)) => self.object(map, object),
            (Shape::Tagged(tagged), CanonicalValue::Map(map)) => self.tagged(map, tagged),
            (Shape::OneOf(shapes), _) => self.one_of(value, shapes),
            // Opaque, scalar, or a value whose kind is not the one the shape describes: there is
            // nothing here the check can read, and the typed layer refuses a wrong kind.
            _ => Ok(None),
        }
    }

    fn array(&mut self, items: &'v [CanonicalValue], item: &Shape) -> Rewrite {
        let mut rewritten: Option<Vec<CanonicalValue>> = None;
        for (index, entry) in items.iter().enumerate() {
            self.path.push(Step::Index(index));
            let outcome = self.value(entry, item);
            self.path.pop();
            match outcome? {
                Some(replacement) => rewritten
                    .get_or_insert_with(|| items[..index].to_vec())
                    .push(replacement),
                None => {
                    if let Some(kept) = rewritten.as_mut() {
                        kept.push(entry.clone());
                    }
                }
            }
        }
        Ok(rewritten.map(CanonicalValue::Array))
    }

    fn map(&mut self, map: &'v CanonicalMap, member: &Shape) -> Rewrite {
        let mut rewritten: Option<Vec<(String, CanonicalValue)>> = None;
        for (index, (key, entry)) in map.entries().iter().enumerate() {
            self.path.push(Step::Key(key));
            let outcome = self.value(entry, member);
            self.path.pop();
            keep(&mut rewritten, map, index, key, entry, outcome?.map(Some));
        }
        Ok(rewritten.map(sorted_map))
    }

    fn object(&mut self, map: &'v CanonicalMap, object: &ObjectShape) -> Rewrite {
        let mut rewritten: Option<Vec<(String, CanonicalValue)>> = None;
        for (index, (key, entry)) in map.entries().iter().enumerate() {
            let change = if let Some(field) = object.fields.get(key) {
                self.path.push(Step::Key(key));
                let outcome = self.value(entry, field);
                self.path.pop();
                outcome?.map(Some)
            } else {
                match self.extensions.classify(object, key) {
                    Member::Admitted(member) => {
                        self.path.push(Step::Key(key));
                        let outcome = self.value(entry, &member);
                        self.path.pop();
                        let value = outcome?.unwrap_or_else(|| entry.clone());
                        self.members.push(AdmittedMember {
                            object: object.name.clone(),
                            path: self.pointer(),
                            key: key.clone(),
                            value,
                        });
                        Some(None)
                    }
                    Member::Refused => {
                        return Err(self.failure(CborError::UnnegotiatedExtension {
                            at: self.describe(object),
                            extension: key.clone(),
                        }));
                    }
                    Member::Field => match object.undeclared {
                        Undeclared::Ignore => Some(None),
                        Undeclared::Refuse => {
                            return Err(self.failure(CborError::UnknownField {
                                at: self.describe(object),
                                field: key.clone(),
                            }));
                        }
                    },
                }
            };
            keep(&mut rewritten, map, index, key, entry, change);
        }
        Ok(rewritten.map(sorted_map))
    }

    fn tagged(&mut self, map: &'v CanonicalMap, tagged: &TaggedShape) -> Rewrite {
        match map.get(&tagged.tag) {
            Some(CanonicalValue::Text(variant)) => match tagged.variants.get(variant) {
                Some(object) => self.object(map, object),
                None => Err(self.failure(CborError::UnknownVariant {
                    at: self.describe(&tagged.any_variant),
                    tag: tagged.tag.clone(),
                    variant: variant.clone(),
                })),
            },
            // No variant is named, so no one variant's fields apply: a key that no variant declares
            // is refused here, and the typed layer refuses the missing or malformed tag.
            _ => self.object(map, &tagged.any_variant),
        }
    }

    fn one_of(&mut self, value: &'v CanonicalValue, shapes: &[Shape]) -> Rewrite {
        let admitted = self.members.len();
        let mut deepest: Option<Failure> = None;
        for shape in shapes {
            if !kind_fits(value, shape) {
                continue;
            }
            match self.value(value, shape) {
                Ok(rewritten) => return Ok(rewritten),
                Err(failure) => {
                    // A variant that refused may have admitted members before it did.
                    self.members.truncate(admitted);
                    if deepest
                        .as_ref()
                        .is_none_or(|current| failure.depth > current.depth)
                    {
                        deepest = Some(failure);
                    }
                }
            }
        }
        // No variant takes this kind of value: the typed layer refuses it.
        deepest.map_or(Ok(None), Err)
    }

    fn failure(&self, error: CborError) -> Failure {
        Failure {
            error,
            depth: self.path.len(),
        }
    }

    fn pointer(&self) -> String {
        let mut pointer = String::new();
        for step in &self.path {
            pointer.push('/');
            match step {
                Step::Key(key) => pointer.push_str(&key.replace('~', "~0").replace('/', "~1")),
                Step::Index(index) => pointer.push_str(&index.to_string()),
            }
        }
        pointer
    }

    fn describe(&self, object: &ObjectShape) -> String {
        let pointer = self.pointer();
        match (&object.name, pointer.is_empty()) {
            (Some(name), true) => name.clone(),
            (Some(name), false) => format!("{name} at {pointer}"),
            (None, true) => "the message".to_owned(),
            (None, false) => format!("the object at {pointer}"),
        }
    }
}

/// True when `shape` could describe a value of `value`'s kind.
fn kind_fits(value: &CanonicalValue, shape: &Shape) -> bool {
    let container = matches!(value, CanonicalValue::Array(_) | CanonicalValue::Map(_));
    match shape {
        Shape::Any | Shape::OneOf(_) => true,
        Shape::Scalar => !container,
        Shape::Array(_) => matches!(value, CanonicalValue::Array(_)),
        Shape::Map(_) | Shape::Object(_) | Shape::Tagged(_) => {
            matches!(value, CanonicalValue::Map(_))
        }
    }
}

/// Records one map entry's outcome, copying the entries before it only once something changes.
///
/// `change` is `None` to keep the entry, `Some(None)` to remove it and `Some(Some(value))` to
/// replace its value.
fn keep(
    rewritten: &mut Option<Vec<(String, CanonicalValue)>>,
    map: &CanonicalMap,
    index: usize,
    key: &str,
    entry: &CanonicalValue,
    change: Option<Option<CanonicalValue>>,
) {
    match change {
        None => {
            if let Some(kept) = rewritten.as_mut() {
                kept.push((key.to_owned(), entry.clone()));
            }
        }
        Some(replacement) => {
            let kept = rewritten.get_or_insert_with(|| map.entries()[..index].to_vec());
            if let Some(replacement) = replacement {
                kept.push((key.to_owned(), replacement));
            }
        }
    }
}

/// Rebuilds a map from entries that are a subset of a canonical map's, in its order.
fn sorted_map(entries: Vec<(String, CanonicalValue)>) -> CanonicalValue {
    CanonicalValue::Map(
        CanonicalMap::from_sorted_entries(entries)
            .expect("a subset of canonical entries keeps their order"),
    )
}

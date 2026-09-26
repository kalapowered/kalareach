//! A JSON document read with the place of every member, so one member can be added or taken out
//! and every other byte kept.
//!
//! A settings document is somebody's. Parsing it into a value and writing the value back would
//! keep its settings and change its bytes: members reordered, numbers spelled again, and of two
//! members with one name only the last kept. So this reader keeps the text and records where each
//! member of each object begins and ends, and an edit splices one member into or out of that text,
//! or one member's value in place of another.
//! What it reads is strict RFC 8259 with one object at the root. A document it cannot read exactly
//! is refused rather than guessed at, and a name repeated in any object refuses the whole document:
//! a repeated member is a setting one reader sees and another does not.
//!
//! An insertion and the removal of what it inserted are exact inverses, so a document that gained
//! a member and lost it again is byte for byte the document it was.

use std::collections::BTreeSet;

/// The deepest nesting a document may have.
const MAX_DEPTH: usize = 128;

/// A document, read, with the place of every member of every object.
#[derive(Clone, Debug)]
pub(crate) struct Document {
    root: Object,
}

#[derive(Clone, Debug)]
struct Object {
    /// Where its `{` is.
    open: usize,
    members: Vec<Member>,
}

#[derive(Clone, Debug)]
struct Member {
    name: String,
    /// Just after the `{` or `,` that comes before it.
    lead: usize,
    /// Where its name's opening quote is.
    start: usize,
    /// Where its value begins.
    value_start: usize,
    /// Just after its value.
    value_end: usize,
    value: Value,
}

#[derive(Clone, Debug)]
enum Value {
    Object(Object),
    Other,
}

impl Object {
    fn member(&self, name: &str) -> Option<(usize, &Member)> {
        self.members
            .iter()
            .enumerate()
            .find(|(_, member)| member.name == name)
    }
}

impl Document {
    /// Reads a document.
    ///
    /// # Errors
    ///
    /// Returns why the text is not a JSON object this reader can edit exactly, with where.
    pub(crate) fn read(text: &str) -> Result<Self, String> {
        let mut reader = Reader { text, at: 0 };
        reader.skip_whitespace();
        if reader.peek() != Some(b'{') {
            return Err(reader.fail("the document is not a JSON object"));
        }
        let root = reader.object(0)?;
        reader.skip_whitespace();
        if reader.at != text.len() {
            return Err(reader.fail("something follows the document's object"));
        }
        Ok(Self { root })
    }

    /// Returns true when the root object has no members.
    pub(crate) fn is_empty(&self) -> bool {
        self.root.members.is_empty()
    }

    /// Returns the text of the value at `path`, or `None` when a member on the way or the member
    /// itself is absent.
    ///
    /// # Errors
    ///
    /// Returns a refusal naming the member on the way that is not an object.
    pub(crate) fn value_at<'t>(
        &self,
        text: &'t str,
        path: &[&str],
    ) -> Result<Option<&'t str>, String> {
        let Some((leaf, ancestors)) = path.split_last() else {
            return Ok(None);
        };
        let mut object = &self.root;
        for name in ancestors {
            match object.member(name) {
                None => return Ok(None),
                Some((_, member)) => match &member.value {
                    Value::Object(inner) => object = inner,
                    Value::Other => return Err(not_an_object(name)),
                },
            }
        }
        Ok(object
            .member(leaf)
            .and_then(|(_, member)| text.get(member.value_start..member.value_end)))
    }

    /// Returns the object at `path`, where every member on the way is an object.
    fn object_at(&self, path: &[&str]) -> Option<&Object> {
        let mut object = &self.root;
        for name in path {
            match object.member(name)?.1 {
                Member {
                    value: Value::Object(inner),
                    ..
                } => object = inner,
                _ => return None,
            }
        }
        Some(object)
    }
}

/// What an insertion made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Inserted {
    /// The document with the member in it.
    pub(crate) text: String,
    /// How many members on the way to it the insertion created, the leaf not counted. They are the
    /// last ones on the path before the leaf.
    pub(crate) created: usize,
}

/// Returns `text` with the member at `path` set to `value`, creating the objects on the way that
/// are absent.
///
/// `value` is JSON text, written as it is.
///
/// # Errors
///
/// Returns a refusal when the text cannot be read, a member on the way is not an object, or the
/// member is already there.
pub(crate) fn insert(text: &str, path: &[&str], value: &str) -> Result<Inserted, String> {
    let document = Document::read(text)?;
    let Some((leaf, ancestors)) = path.split_last() else {
        return Err("the key names no member".to_owned());
    };
    // The deepest object on the path that is already there.
    let mut object = &document.root;
    let mut present = 0;
    for name in ancestors {
        match object.member(name) {
            None => break,
            Some((_, member)) => match &member.value {
                Value::Object(inner) => {
                    object = inner;
                    present += 1;
                }
                Value::Other => return Err(not_an_object(name)),
            },
        }
    }
    if present == ancestors.len() && object.member(leaf).is_some() {
        return Err(format!("{} is already set", path.join(".")));
    }
    let mut member = format!("{}: {value}", quoted(leaf));
    for name in ancestors[present..].iter().rev() {
        member = format!("{}: {{{member}}}", quoted(name));
    }
    let (at, inserted) = match object.members.last() {
        // The same separation the last member has, so the document keeps its own layout.
        Some(last) => (
            last.value_end,
            format!(",{}{member}", &text[last.lead..last.start]),
        ),
        None => (object.open + 1, member),
    };
    let mut edited = String::with_capacity(text.len() + inserted.len());
    edited.push_str(&text[..at]);
    edited.push_str(&inserted);
    edited.push_str(&text[at..]);
    // Read back, so what is written is known to be a document this reader edits exactly and to
    // hold the value where it was put.
    let check = Document::read(&edited)?;
    if check.value_at(&edited, path)? != Some(value) {
        return Err(format!("{} could not be placed", path.join(".")));
    }
    Ok(Inserted {
        text: edited,
        created: ancestors.len() - present,
    })
}

/// Returns `text` without the member at `path`, and without each of the `created` members before
/// it that the removal left empty, deepest first.
///
/// # Errors
///
/// Returns a refusal when the text cannot be read or the member is not there.
pub(crate) fn remove(text: &str, path: &[&str], created: usize) -> Result<String, String> {
    let mut edited = splice_out(text, path)?;
    let ancestors = path.len().saturating_sub(1);
    for depth in (ancestors.saturating_sub(created)..ancestors).rev() {
        let owner = &path[..=depth];
        let document = Document::read(&edited)?;
        match document.object_at(owner) {
            Some(object) if object.members.is_empty() => edited = splice_out(&edited, owner)?,
            _ => break,
        }
    }
    Ok(edited)
}

/// Returns `text` without the member at `path`.
fn splice_out(text: &str, path: &[&str]) -> Result<String, String> {
    let document = Document::read(text)?;
    let Some((leaf, ancestors)) = path.split_last() else {
        return Err("the key names no member".to_owned());
    };
    let object = document
        .object_at(ancestors)
        .ok_or_else(|| format!("{} is not there", path.join(".")))?;
    let (index, member) = object
        .member(leaf)
        .ok_or_else(|| format!("{} is not there", path.join(".")))?;
    let (from, to) = if object.members.len() == 1 {
        (member.lead, member.value_end)
    } else if index == 0 {
        (member.start, object.members[1].start)
    } else {
        (object.members[index - 1].value_end, member.value_end)
    };
    let mut edited = String::with_capacity(text.len());
    edited.push_str(&text[..from]);
    edited.push_str(&text[to..]);
    Document::read(&edited)?;
    Ok(edited)
}

/// Returns `text` with the value of the member at `path` replaced by `value`, and every other byte
/// kept, the member's own place and spacing among them.
///
/// `value` is JSON text, written as it is.
///
/// # Errors
///
/// Returns a refusal when the text cannot be read or the member is not there.
pub(crate) fn replace(text: &str, path: &[&str], value: &str) -> Result<String, String> {
    let document = Document::read(text)?;
    let Some((leaf, ancestors)) = path.split_last() else {
        return Err("the key names no member".to_owned());
    };
    let (_, member) = document
        .object_at(ancestors)
        .and_then(|object| object.member(leaf))
        .ok_or_else(|| format!("{} is not there", path.join(".")))?;
    let mut edited = String::with_capacity(text.len() + value.len());
    edited.push_str(&text[..member.value_start]);
    edited.push_str(value);
    edited.push_str(&text[member.value_end..]);
    let check = Document::read(&edited)?;
    if check.value_at(&edited, path)? != Some(value) {
        return Err(format!("{} could not be placed", path.join(".")));
    }
    Ok(edited)
}

fn quoted(name: &str) -> String {
    serde_json::to_string(name).unwrap_or_else(|_| format!("\"{name}\""))
}

fn not_an_object(name: &str) -> String {
    format!("{name} holds something other than an object")
}

/// A strict reader over the document's text.
struct Reader<'a> {
    text: &'a str,
    at: usize,
}

impl Reader<'_> {
    fn fail(&self, reason: &str) -> String {
        format!("{reason} (at byte {})", self.at)
    }

    fn peek(&self) -> Option<u8> {
        self.text.as_bytes().get(self.at).copied()
    }

    fn skip_whitespace(&mut self) {
        while let Some(b' ' | b'\t' | b'\n' | b'\r') = self.peek() {
            self.at += 1;
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, String> {
        if depth > MAX_DEPTH {
            return Err(self.fail("the document is nested too deeply"));
        }
        match self.peek() {
            Some(b'{') => self.object(depth).map(Value::Object),
            Some(b'[') => self.array(depth).map(|()| Value::Other),
            Some(b'"') => self.string().map(|_| Value::Other),
            Some(b't') => self.literal("true").map(|()| Value::Other),
            Some(b'f') => self.literal("false").map(|()| Value::Other),
            Some(b'n') => self.literal("null").map(|()| Value::Other),
            Some(b'-' | b'0'..=b'9') => self.number().map(|()| Value::Other),
            _ => Err(self.fail("a value was expected")),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Object, String> {
        let open = self.at;
        self.at += 1;
        let mut members = Vec::new();
        let mut names = BTreeSet::new();
        let mut lead = self.at;
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.at += 1;
            return Ok(Object { open, members });
        }
        loop {
            if self.peek() != Some(b'"') {
                return Err(self.fail("a member name was expected"));
            }
            let start = self.at;
            let name = self.string()?;
            if !names.insert(name.clone()) {
                return Err(format!(
                    "the member {name:?} appears more than once in one object (at byte {start})"
                ));
            }
            self.skip_whitespace();
            if self.peek() != Some(b':') {
                return Err(self.fail("a ':' was expected"));
            }
            self.at += 1;
            self.skip_whitespace();
            let value_start = self.at;
            let value = self.value(depth + 1)?;
            members.push(Member {
                name,
                lead,
                start,
                value_start,
                value_end: self.at,
                value,
            });
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => {
                    self.at += 1;
                    lead = self.at;
                    self.skip_whitespace();
                }
                Some(b'}') => {
                    self.at += 1;
                    return Ok(Object { open, members });
                }
                _ => return Err(self.fail("a ',' or '}' was expected")),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<(), String> {
        self.at += 1;
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.at += 1;
            return Ok(());
        }
        loop {
            self.value(depth + 1)?;
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => {
                    self.at += 1;
                    self.skip_whitespace();
                }
                Some(b']') => {
                    self.at += 1;
                    return Ok(());
                }
                _ => return Err(self.fail("a ',' or ']' was expected")),
            }
        }
    }

    /// Reads a string and returns what it says, its escapes decoded.
    fn string(&mut self) -> Result<String, String> {
        self.at += 1;
        let mut decoded = String::new();
        loop {
            let Some(byte) = self.peek() else {
                return Err(self.fail("a string is not closed"));
            };
            match byte {
                b'"' => {
                    self.at += 1;
                    return Ok(decoded);
                }
                b'\\' => {
                    self.at += 1;
                    let character = match self.peek() {
                        Some(b'"') => '"',
                        Some(b'\\') => '\\',
                        Some(b'/') => '/',
                        Some(b'b') => '\u{8}',
                        Some(b'f') => '\u{c}',
                        Some(b'n') => '\n',
                        Some(b'r') => '\r',
                        Some(b't') => '\t',
                        Some(b'u') => {
                            self.at += 1;
                            decoded.push(self.unicode_escape()?);
                            continue;
                        }
                        _ => return Err(self.fail("an escape is not one JSON has")),
                    };
                    decoded.push(character);
                    self.at += 1;
                }
                0x00..=0x1f => return Err(self.fail("a control character is not escaped")),
                _ => {
                    let character = self.text[self.at..]
                        .chars()
                        .next()
                        .ok_or_else(|| self.fail("a string is not closed"))?;
                    decoded.push(character);
                    self.at += character.len_utf8();
                }
            }
        }
    }

    /// Reads the four digits after `\u`, and a second escape after a high surrogate.
    fn unicode_escape(&mut self) -> Result<char, String> {
        let unit = self.hex4()?;
        let code = match unit {
            0xD800..=0xDBFF => {
                if self.text.as_bytes().get(self.at..self.at + 2) != Some(b"\\u") {
                    return Err(self.fail("a surrogate is not paired"));
                }
                self.at += 2;
                let low = self.hex4()?;
                if !(0xDC00..=0xDFFF).contains(&low) {
                    return Err(self.fail("a surrogate is not paired"));
                }
                0x1_0000 + ((unit - 0xD800) << 10) + (low - 0xDC00)
            }
            0xDC00..=0xDFFF => return Err(self.fail("a surrogate is not paired")),
            other => other,
        };
        char::from_u32(code).ok_or_else(|| self.fail("an escape names no character"))
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let digits = self
            .text
            .get(self.at..self.at + 4)
            .filter(|digits| digits.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .ok_or_else(|| self.fail("a \\u escape needs four hexadecimal digits"))?;
        let unit = u32::from_str_radix(digits, 16)
            .map_err(|_| self.fail("a \\u escape is not hexadecimal"))?;
        self.at += 4;
        Ok(unit)
    }

    fn literal(&mut self, word: &str) -> Result<(), String> {
        if self.text[self.at..].starts_with(word) {
            self.at += word.len();
            Ok(())
        } else {
            Err(self.fail("a value was expected"))
        }
    }

    fn number(&mut self) -> Result<(), String> {
        if self.peek() == Some(b'-') {
            self.at += 1;
        }
        match self.peek() {
            Some(b'0') => self.at += 1,
            Some(b'1'..=b'9') => self.digits(),
            _ => return Err(self.fail("a number has no digits")),
        }
        if self.peek() == Some(b'.') {
            self.at += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.fail("a fraction has no digits"));
            }
            self.digits();
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.at += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.at += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.fail("an exponent has no digits"));
            }
            self.digits();
        }
        Ok(())
    }

    fn digits(&mut self) {
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.at += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [&str; 2] = ["enabledPlugins", "kalareach-channels@skills-dir"];

    #[test]
    fn a_member_is_added_and_taken_out_leaving_every_other_byte() {
        let documents = [
            "{}",
            "{ }",
            "{\n}\n",
            "{\n  \"model\": \"opus\",\n  \"cleanupPeriodDays\": 1e3,\n  \"n\": -0.10\n}\n",
            "{\"enabledPlugins\":{},\"z\":[1,{\"a\":null}]}",
            "{\n  \"enabledPlugins\": {\n    \"other@market\": false\n  }\n}\n",
            "{\"a\": \"\\u00e9\\ud83d\\ude00\", \"enabledPlugins\": {\"x\": true}, \"b\": 12345678901234567890}",
        ];
        for original in documents {
            let inserted = insert(original, &KEY, "true").expect("inserts");
            let document = Document::read(&inserted.text).expect("reads back");
            assert_eq!(
                document.value_at(&inserted.text, &KEY).expect("an object"),
                Some("true"),
                "{original}"
            );
            let restored = remove(&inserted.text, &KEY, inserted.created).expect("removes");
            assert_eq!(restored, original, "the document is the one it was");
        }
    }

    #[test]
    fn the_members_on_the_way_are_created_and_taken_out_only_when_empty() {
        let inserted = insert("{\"a\": 1}", &KEY, "true").expect("inserts");
        assert_eq!(inserted.created, 1);
        // The separation the last member has, which here is none.
        assert_eq!(
            inserted.text,
            "{\"a\": 1,\"enabledPlugins\": {\"kalareach-channels@skills-dir\": true}}"
        );
        // Somebody enables another plugin under the object this host created: that object stays.
        let theirs =
            insert(&inserted.text, &["enabledPlugins", "theirs@market"], "true").expect("inserts");
        let removed = remove(&theirs.text, &KEY, inserted.created).expect("removes");
        assert_eq!(
            removed,
            "{\"a\": 1,\"enabledPlugins\": {\"theirs@market\": true}}"
        );
    }

    #[test]
    fn a_member_somebody_added_after_this_one_survives_its_removal() {
        let inserted = insert("{\n  \"enabledPlugins\": {}\n}", &KEY, "true").expect("inserts");
        let theirs =
            insert(&inserted.text, &["enabledPlugins", "later"], "false").expect("inserts");
        let removed = remove(&theirs.text, &KEY, inserted.created).expect("removes");
        assert_eq!(removed, "{\n  \"enabledPlugins\": {\"later\": false}\n}");
    }

    #[test]
    fn what_cannot_be_read_exactly_is_refused() {
        for (text, why) in [
            ("{\"a\": 1, \"a\": 2}", "appears more than once"),
            ("{\"x\": {\"b\": 1, \"b\": 1}}", "appears more than once"),
            ("{\"x\": [{\"b\": 1, \"b\": 1}]}", "appears more than once"),
            ("[]", "not a JSON object"),
            ("", "not a JSON object"),
            ("{\"a\": 1} {}", "follows"),
            ("{\"a\": 01}", "was expected"),
            ("{\"a\": 1.}", "fraction"),
            ("{\"a\": NaN}", "value was expected"),
            ("{\"a\": \"\\ud800\"}", "surrogate"),
            ("{\"a\": \"tab\there\"}", "control character"),
            ("{// comment\n}", "member name"),
            ("{\"a\": 1,}", "member name"),
            ("\u{feff}{}", "not a JSON object"),
        ] {
            let refused = Document::read(text).expect_err(text);
            assert!(refused.contains(why), "{text}: {refused}");
        }
        let deep = format!("{{\"a\": {}{}}}", "[".repeat(200), "]".repeat(200));
        assert!(
            Document::read(&deep)
                .expect_err("too deep")
                .contains("nested")
        );
    }

    #[test]
    fn a_value_is_replaced_in_its_place_leaving_every_other_byte() {
        let original = "{\n\t\"z\": 1,\n\t\"enabledPlugins\": {\"kalareach-channels@skills-dir\": false, \
                        \"theirs\": true}\n}\n";
        let replaced = replace(original, &KEY, "{\"a\": [1, 2]}").expect("replaces");
        assert_eq!(
            replaced,
            "{\n\t\"z\": 1,\n\t\"enabledPlugins\": {\"kalareach-channels@skills-dir\": {\"a\": [1, 2]}, \
             \"theirs\": true}\n}\n"
        );
        let refused = replace("{\"enabledPlugins\": {}}", &KEY, "true").expect_err("refuses");
        assert!(refused.contains("is not there"), "{refused}");
    }

    #[test]
    fn a_path_through_something_that_is_not_an_object_is_refused() {
        let refused = insert("{\"enabledPlugins\": []}", &KEY, "true").expect_err("refuses");
        assert!(refused.contains("enabledPlugins"), "{refused}");
        let refused = insert(
            "{\"enabledPlugins\": {\"kalareach-channels@skills-dir\": false}}",
            &KEY,
            "true",
        )
        .expect_err("refuses");
        assert!(refused.contains("already set"), "{refused}");
    }
}

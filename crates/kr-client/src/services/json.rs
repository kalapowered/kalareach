//! The one reader of what a managed service answers.
//!
//! A JSON text that names one member twice in one object says two things at once. `serde_json`'s
//! value tree keeps the last of the two, a derived shape refuses a member it names twice and never
//! looks at one it does not name, and another reader, the service's own among them, may keep the
//! first. A client that read such an answer would be acting on one of two answers the service did
//! not give once. So [`read`] refuses the text before anything reads a member of it, whichever
//! object repeats a name, at whatever depth, and whatever the member is. Names are compared as the
//! strings they decode to, so `"a"` and `"\u0061"` are one name. The service holds the requests it
//! receives to the same rule.
//!
//! Every service client in this crate reads an answer through [`read`], and so does the host where
//! it reads the gateway's answers itself. A test in this module walks the service modules and fails
//! when one of them decodes JSON text any other way.
//!
//! What a failure says is [`Unreadable`]: which rule the text broke and where, and nothing that was
//! in it. An answer carries whatever answered, and a message that quoted it would print it.

use std::cell::Cell;
use std::collections::BTreeSet;
use std::fmt;

use serde::de::{self, DeserializeOwned, DeserializeSeed, MapAccess, SeqAccess, Visitor};

/// Reads one JSON text as `T`, once no object in it names a member twice.
///
/// The whole text is walked first, so a repeat anywhere refuses it, in a member `T` never reads as
/// much as in one it does: the text is what the service said, and a text that says two things is
/// not one answer. Only a text that passes is read as `T`.
///
/// # Errors
///
/// Returns [`Unreadable`] when the text is not JSON, when an object in it names one member twice,
/// or when it is not the shape `T` gives it.
pub fn read<T: DeserializeOwned>(text: &[u8]) -> Result<T, Unreadable> {
    let named_twice = Cell::new(false);
    let mut walk = serde_json::Deserializer::from_slice(text);
    Distinct {
        named_twice: &named_twice,
    }
    .deserialize(&mut walk)
    .and_then(|()| walk.end())
    .map_err(|error| {
        let fault = Unreadable::from(&error);
        if named_twice.get() {
            Unreadable {
                fault: Fault::NamedTwice,
                ..fault
            }
        } else {
            fault
        }
    })?;
    serde_json::from_slice(text).map_err(|error| Unreadable::from(&error))
}

/// Why a JSON text was not read, in words that carry none of it.
///
/// Which rule the text broke, and the line and column it was found at. Both help somebody
/// diagnosing a mismatch, and neither is anything that travelled. It is also what this crate says
/// about any other JSON failure, through [`super::json_fault`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unreadable {
    fault: Fault,
    line: usize,
    column: usize,
}

/// Which rule a text broke.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    /// The bytes could not be read at all.
    Unread,
    /// The text is not JSON.
    NotJson,
    /// The text ended before its value did.
    EndedEarly,
    /// An object in the text names one member twice.
    NamedTwice,
    /// The text is JSON, and not the shape the caller reads.
    NotTheShape,
}

impl Unreadable {
    /// Whether the text was refused because an object in it names one member twice.
    #[must_use]
    pub fn names_a_member_twice(&self) -> bool {
        self.fault == Fault::NamedTwice
    }
}

impl From<&serde_json::Error> for Unreadable {
    /// The class `serde_json` gives a failure, and its position. Never its message, which quotes
    /// the value it rejected.
    fn from(error: &serde_json::Error) -> Self {
        let fault = match error.classify() {
            serde_json::error::Category::Io => Fault::Unread,
            serde_json::error::Category::Syntax => Fault::NotJson,
            serde_json::error::Category::Data => Fault::NotTheShape,
            serde_json::error::Category::Eof => Fault::EndedEarly,
        };
        Self {
            fault,
            line: error.line(),
            column: error.column(),
        }
    }
}

impl fmt::Display for Unreadable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match self.fault {
            Fault::Unread => "could not be read",
            Fault::NotJson => "is not JSON",
            Fault::EndedEarly => "ended early",
            Fault::NamedTwice => "names one member of an object twice",
            Fault::NotTheShape => "is not the shape this client reads",
        };
        write!(
            formatter,
            "it {what} at line {} column {}",
            self.line, self.column
        )
    }
}

impl std::error::Error for Unreadable {}

/// One JSON value of any kind, walked for an object that names a member twice.
///
/// The walk keeps the names of the objects it is inside and nothing else. What it finds is set in
/// `named_twice` as well as returned as an error, because the error `serde_json` hands back is one
/// of its own and says nothing of which rule it was.
#[derive(Clone, Copy)]
struct Distinct<'a> {
    named_twice: &'a Cell<bool>,
}

impl<'de> DeserializeSeed<'de> for Distinct<'_> {
    type Value = ();

    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Distinct<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }

    fn visit_i64<E: de::Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }

    fn visit_u64<E: de::Error>(self, _: u64) -> Result<(), E> {
        Ok(())
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<(), E> {
        Ok(())
    }

    fn visit_str<E: de::Error>(self, _: &str) -> Result<(), E> {
        Ok(())
    }

    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut items: A) -> Result<(), A::Error> {
        while items.next_element_seed(self)?.is_some() {}
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut members: A) -> Result<(), A::Error> {
        // A name is read as the string it decodes to, so two spellings of one name are one name.
        let mut names = BTreeSet::new();
        while let Some(name) = members.next_key::<String>()? {
            if !names.insert(name) {
                self.named_twice.set(true);
                return Err(de::Error::custom("an object names one member twice"));
            }
            members.next_value_seed(self)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::services::rendering::NEVER_RENDERED;

    /// Decodes of JSON text under `services/` that read no answer, each named by the file it is in
    /// and the code that makes it. Each must still be there, once, so an exception cannot outlive
    /// the code it excused.
    const NOT_AN_ANSWER: [(&str, &str); 4] = [
        // A header value this client sends, which is not JSON at all.
        ("http.rs", "reqwest::header::HeaderValue::from_str(value)"),
        // The sign-in this device stored.
        (
            "account.rs",
            "let document: GrantDocument = serde_json::from_slice(bytes)",
        ),
        // The revocations this device keeps until the service acknowledges them.
        (
            "account.rs",
            "let document: PendingDocument = serde_json::from_slice(bytes.expose())",
        ),
        // The account token this device stored.
        (
            "voice.rs",
            "let document: TokenDocument = serde_json::from_slice(bytes)",
        ),
    ];

    /// The names a decode of JSON text is reached by: `serde_json`'s three decoders, the
    /// deserializers they are built on, and a value parsed out of text.
    const DECODERS: [&str; 6] = [
        "from_slice",
        "from_str",
        "from_reader",
        "Deserializer::new",
        "StreamDeserializer",
        "parse::<serde_json::Value>",
    ];

    /// Every name in [`DECODERS`] that `code` uses, where it starts a name rather than ends one.
    fn decoders_named_in(code: &str) -> Vec<&'static str> {
        DECODERS
            .into_iter()
            .filter(|name| {
                code.match_indices(name).any(|(at, _)| {
                    !code[..at]
                        .chars()
                        .next_back()
                        .is_some_and(|before| before.is_alphanumeric() || before == '_')
                })
            })
            .collect()
    }

    /// What a source holds outside its tests, without its comments and with its layout taken out.
    ///
    /// A file's tests are its last item, `#[cfg(test)] mod tests`, which clippy's
    /// `items_after_test_module` holds every file to, so everything from there on is left out. A
    /// comment line names things rather than calling them, and the rest is read with every run of
    /// white space as one space, so a call split across lines reads as one.
    fn product_code(source: &str) -> String {
        source
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .unwrap_or(source)
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .flat_map(str::split_whitespace)
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// The file that declares the test module `relative` is part of, when it is part of one: a
    /// `tests.rs`, or a file under a `tests` directory, belongs to the module its parent declares.
    fn declared_by_test_module(relative: &Path) -> Option<PathBuf> {
        let parts: Vec<_> = relative.components().collect();
        let at = parts
            .iter()
            .position(|part| part.as_os_str() == "tests" || part.as_os_str() == "tests.rs")?;
        Some(match at {
            0 => PathBuf::from("mod.rs"),
            _ => {
                let parent: PathBuf = parts[..at].iter().collect();
                parent.with_extension("rs")
            }
        })
    }

    /// Every Rust source in one directory and the directories under it, read whole.
    fn rust_sources(directory: &Path) -> Vec<(PathBuf, String)> {
        let mut sources = Vec::new();
        let mut pending = vec![directory.to_path_buf()];
        while let Some(directory) = pending.pop() {
            for entry in std::fs::read_dir(&directory).expect("a directory of the module") {
                let path = entry.expect("an entry of the module").path();
                if path.is_dir() {
                    pending.push(path);
                } else if path.extension().is_some_and(|extension| extension == "rs") {
                    let source = std::fs::read_to_string(&path).expect("a source of the module");
                    sources.push((path, source));
                }
            }
        }
        sources
    }

    /// Every service module reads an answer through [`read`], and this is what keeps that true.
    ///
    /// Decoding JSON text takes one of `serde_json`'s decoders, and each is reached by a name in
    /// [`DECODERS`]. So every file under `services/` but this one is read for those names, and one
    /// found there fails this test whatever it decodes. The exceptions read this device's own
    /// stored files, or no JSON at all, and each is named by its code in [`NOT_AN_ANSWER`].
    ///
    /// Tests are left out: a file's own tests are its last item, and a module declared under
    /// `#[cfg(test)]` is test code whole, which is checked where it is declared. The directory is
    /// walked rather than listed, so a file added to the module is read the day it arrives.
    #[test]
    fn nothing_but_this_reader_decodes_the_text_of_an_answer() {
        let services = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/services");
        let reader = services.join("json.rs");
        let sources = rust_sources(&services);
        assert!(
            sources.iter().any(|(path, _)| path == &reader),
            "the reader is where this expects it: {}",
            reader.display()
        );
        assert!(
            sources.len() >= 10,
            "the service modules are there to be read: {}",
            services.display()
        );

        let mut excused = [0; NOT_AN_ANSWER.len()];
        for (path, source) in &sources {
            if path == &reader {
                continue;
            }
            let relative = path.strip_prefix(&services).expect("a file of the module");
            if let Some(declaring) = declared_by_test_module(relative) {
                let parent = std::fs::read_to_string(services.join(&declaring))
                    .expect("the file that declares a test module");
                assert!(
                    parent.contains("#[cfg(test)]\nmod tests;"),
                    "{} is read as test code, so {} declares it under #[cfg(test)]",
                    relative.display(),
                    declaring.display()
                );
                continue;
            }
            let mut code = product_code(source);
            for (index, (file, excuse)) in NOT_AN_ANSWER.into_iter().enumerate() {
                if relative == Path::new(file) {
                    assert_eq!(
                        code.matches(excuse).count(),
                        1,
                        "{file} still holds, once, the decode it is excused for: {excuse}"
                    );
                    code = code.replacen(excuse, "", 1);
                    excused[index] += 1;
                }
            }
            let named = decoders_named_in(&code);
            assert!(
                named.is_empty(),
                "{} decodes JSON text round the one reader of an answer: {named:?}",
                relative.display()
            );
        }
        assert_eq!(
            excused,
            [1; NOT_AN_ANSWER.len()],
            "every exception names a file that is still there"
        );
    }

    #[test]
    fn the_walk_finds_a_decode_however_it_is_written() {
        // The control for the test above: each way of decoding text is seen, and a name that only
        // ends in one of them, or a comment that mentions one, is not.
        for written in [
            "let envelope: Envelope = serde_json::from_slice(&answer.body)?;",
            "let envelope = serde_json::from_str::<Envelope>(\n    text,\n)?;",
            "use serde_json::{from_slice as decode, Value};",
            "serde_json::from_reader(std::io::Cursor::new(bytes))",
            "let mut walk = serde_json::Deserializer::new(serde_json::de::SliceRead::new(bytes));",
            "let pages = serde_json::StreamDeserializer::<_, Page>::new(read);",
            "let value = text.parse::<serde_json::Value>()?;",
        ] {
            assert!(
                !decoders_named_in(&product_code(written)).is_empty(),
                "{written}"
            );
        }
        for innocent in [
            "buffer.extend_from_slice(&chunk);",
            "/// Reads it with `serde_json::from_slice`.",
            "    // serde_json::from_str would quote the text",
            "let value = serde_json::from_value(data)?;",
            "fn product() {}\n#[cfg(test)]\nmod tests {\n    let _ = serde_json::from_slice(b\"{}\");\n}",
        ] {
            assert!(
                decoders_named_in(&product_code(innocent)).is_empty(),
                "{innocent}"
            );
        }
    }

    fn refused(text: &str) -> Unreadable {
        read::<serde_json::Value>(text.as_bytes()).expect_err(text)
    }

    #[test]
    fn a_text_that_names_a_member_twice_is_refused_at_any_depth() {
        for text in [
            r#"{"a":1,"a":1}"#,
            r#"{"a":1,"b":2,"a":3}"#,
            r#"{"data":{"recovery_id":null,"recovery_id":"x"}}"#,
            r#"[{"ok":true},{"ok":true,"ok":false}]"#,
            r#"{"outer":[[{"inner":{"deep":1,"deep":2}}]]}"#,
            // Two spellings of one name are one name, whichever way round.
            r#"{"a":1,"\u0061":2}"#,
            r#"{"\u0061":1,"a":2}"#,
            r#"{"A":2,"\u0041":{}}"#,
            r#"{"\ud834\udd1e":1,"𝄞":2}"#,
            r#"{"a\nb":1,"a\u000ab":2}"#,
        ] {
            let fault = refused(text);
            assert!(fault.names_a_member_twice(), "{text}: {fault}");
        }
    }

    #[test]
    fn names_that_are_not_one_name_or_are_in_two_objects_are_read() {
        // The controls: a name is one only within one object, and only as the string it decodes to.
        for text in [
            r#"{"a":1,"\u0041":2}"#,
            r#"{"a":{"a":1},"b":{"a":2}}"#,
            r#"[{"a":1},{"a":2}]"#,
            r#"{"a ":1,"a":2}"#,
            r#"{"a":"a","b":"a"}"#,
            "{}",
            "[]",
            "null",
            r#"{"n":-1,"f":1.5e3,"t":true,"s":"\"quoted\""}"#,
        ] {
            read::<serde_json::Value>(text.as_bytes()).expect(text);
        }
    }

    #[test]
    fn a_repeat_in_a_member_the_shape_never_reads_still_refuses_the_text() {
        #[derive(Debug, serde::Deserialize)]
        struct Shape {
            #[allow(dead_code, reason = "read only to give the text a shape")]
            read: u8,
        }
        // A derived shape ignores a member it does not name, so on its own it would read this.
        assert!(serde_json::from_str::<Shape>(r#"{"read":1,"other":2,"other":3}"#).is_ok());
        let fault = read::<Shape>(br#"{"read":1,"other":2,"other":3}"#).expect_err("repeated");
        assert!(fault.names_a_member_twice(), "{fault}");
        // And one the text names once is read.
        assert_eq!(
            read::<Shape>(br#"{"read":1,"other":2}"#)
                .expect("a shape")
                .read,
            1
        );
    }

    #[test]
    fn a_failure_names_the_rule_and_the_place_and_nothing_of_the_text() {
        let text =
            format!(r#"{{"note":"{NEVER_RENDERED}","{NEVER_RENDERED}":1,"{NEVER_RENDERED}":2}}"#);
        let fault = read::<serde_json::Value>(text.as_bytes()).expect_err("repeated");
        let said = fault.to_string();
        assert!(!said.contains(NEVER_RENDERED), "{said}");
        assert!(!format!("{fault:?}").contains(NEVER_RENDERED));
        assert!(
            said.starts_with("it names one member of an object twice at line 1 column "),
            "{said}"
        );

        #[derive(Debug, serde::Deserialize)]
        struct Shape {
            #[allow(dead_code, reason = "the failure to read it is the subject")]
            member: u8,
        }
        let text = format!(r#"{{"member":"{NEVER_RENDERED}"}}"#);
        let fault = read::<Shape>(text.as_bytes()).expect_err("not the shape");
        assert!(!fault.to_string().contains(NEVER_RENDERED), "{fault}");
        assert!(
            fault
                .to_string()
                .contains("is not the shape this client reads")
        );
        assert!(!fault.names_a_member_twice());

        for (text, what) in [
            ("{", "ended early"),
            (r#"{"a":1} {"a":1}"#, "is not JSON"),
            (r#"{"a":1,}"#, "is not JSON"),
        ] {
            let fault = refused(text);
            assert!(fault.to_string().contains(what), "{text}: {fault}");
            assert!(!fault.names_a_member_twice(), "{text}");
        }
    }
}

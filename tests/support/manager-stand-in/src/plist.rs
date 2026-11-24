//! The property list `kr host startup` writes, read as launchd reads it: every key it holds is one
//! the stand-in applies, and any other is refused.

use quick_xml::XmlVersion;
use quick_xml::events::Event;
use quick_xml::reader::Reader;

/// How deep a property list may nest: the one `kr` writes nests two.
const MAX_DEPTH: usize = 8;

/// One value of a property list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// `<string>`.
    String(String),
    /// `<integer>`.
    Integer(i64),
    /// `<true/>` and `<false/>`.
    Bool(bool),
    /// `<array>`.
    Array(Vec<Value>),
    /// `<dict>`, in the order written.
    Dict(Vec<(String, Value)>),
}

/// What a definition of `kr` makes launchd do, as the keys of its property list say.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Definition {
    /// The job's label.
    pub label: String,
    /// The program and its arguments, as written.
    pub arguments: Vec<String>,
    /// Whether launchd starts it when it is loaded.
    pub run_at_load: bool,
    /// Whether launchd starts it again when it ends.
    pub keep_alive: bool,
    /// The session type the job loads into.
    pub session_type: String,
    /// The working directory.
    pub working_directory: String,
    /// The file mode mask.
    pub umask: u32,
    /// Where standard output goes.
    pub standard_out: String,
    /// Where standard error goes.
    pub standard_error: String,
    /// The environment the definition adds, in the order written.
    pub environment: Vec<(String, String)>,
}

/// The elements open while a list is read, and what they have collected.
#[derive(Default)]
struct Builder {
    /// Each open container or scalar, with the items an array has collected.
    open: Vec<(String, Vec<Value>)>,
    /// The entries of each open dictionary.
    dicts: Vec<Vec<(String, Value)>>,
    /// The key waiting for its value in each open dictionary.
    keys: Vec<Option<String>>,
    /// The whole list, once its outer element has closed.
    result: Option<Value>,
}

impl Builder {
    /// Opens the element `name`. A boolean is a complete value at once.
    fn start(&mut self, name: &str) -> Result<(), String> {
        if self.open.len() >= MAX_DEPTH {
            return Err("the property list nests deeper than a definition does".to_owned());
        }
        match name {
            "dict" => {
                self.dicts.push(Vec::new());
                self.keys.push(None);
                self.open.push((name.to_owned(), Vec::new()));
            }
            "array" | "key" | "string" | "integer" => self.open.push((name.to_owned(), Vec::new())),
            "true" | "false" => self.place(Value::Bool(name == "true"))?,
            other => return Err(format!("the element {other} is not one a definition holds")),
        }
        Ok(())
    }

    /// Closes the element `name`, whose text was `held`, and places its value.
    fn end(&mut self, name: &str, held: &str) -> Result<(), String> {
        if matches!(name, "true" | "false") {
            return Ok(());
        }
        let (opened, items) = self
            .open
            .pop()
            .ok_or_else(|| format!("</{name}> closes nothing"))?;
        if opened != name {
            return Err(format!("</{name}> closes <{opened}>"));
        }
        let value = match name {
            "key" => {
                let slot = self
                    .keys
                    .last_mut()
                    .ok_or("a key stands outside a dictionary")?;
                if slot.is_some() {
                    return Err("a key follows a key".to_owned());
                }
                *slot = Some(held.to_owned());
                return Ok(());
            }
            "string" => Value::String(held.to_owned()),
            "integer" => Value::Integer(
                held.trim()
                    .parse()
                    .map_err(|_| format!("{held:?} is not an integer"))?,
            ),
            "array" => Value::Array(items),
            _ => {
                self.keys.pop();
                Value::Dict(
                    self.dicts
                        .pop()
                        .ok_or("a dictionary closes that never opened")?,
                )
            }
        };
        self.place(value)
    }

    /// Puts `value` where the open elements say it goes: under the key before it in the open
    /// dictionary, as an item of the open array, or as the whole of the list.
    fn place(&mut self, value: Value) -> Result<(), String> {
        match self.open.last_mut() {
            Some((container, items)) if container == "array" => items.push(value),
            Some((container, _)) if container == "dict" => {
                let key = self
                    .keys
                    .last_mut()
                    .and_then(Option::take)
                    .ok_or("a value stands in a dictionary with no key before it")?;
                self.dicts
                    .last_mut()
                    .ok_or("a dictionary is open and holds no entries")?
                    .push((key, value));
            }
            None => self.result = Some(value),
            Some((container, _)) => return Err(format!("a value stands inside <{container}>")),
        }
        Ok(())
    }
}

/// Reads a property list into the dictionary of its top level.
///
/// # Errors
///
/// Says what is wrong: markup that is not a property list of `kr`'s kind, or a value it does not
/// hold.
pub fn parse(text: &str) -> Result<Vec<(String, Value)>, String> {
    let mut reader = Reader::from_str(text);
    let mut builder = Builder::default();
    let mut held = String::new();
    let mut in_plist = false;
    loop {
        let event = reader
            .read_event()
            .map_err(|error| format!("the property list is not well formed: {error}"))?;
        match event {
            Event::Eof => break,
            Event::Decl(_) | Event::DocType(_) | Event::Comment(_) | Event::PI(_) => {}
            Event::Text(text) => held.push_str(&text.xml_content(XmlVersion::Implicit1_0)),
            Event::GeneralRef(reference) => {
                if let Some(character) = reference
                    .resolve_char_ref()
                    .map_err(|error| format!("a character reference is not valid: {error}"))?
                {
                    held.push(character);
                } else {
                    held.push(match &*reference.xml_content(XmlVersion::Implicit1_0) {
                        "amp" => '&',
                        "lt" => '<',
                        "gt" => '>',
                        "quot" => '"',
                        "apos" => '\'',
                        other => return Err(format!("the entity {other} is not one of XML's own")),
                    });
                }
            }
            Event::CData(_) => return Err("a CDATA section is no part of a definition".to_owned()),
            Event::Start(element) => {
                held.clear();
                let name = element.name().as_ref().to_owned();
                if name == "plist" {
                    in_plist = true;
                } else {
                    builder.start(&name)?;
                }
            }
            Event::Empty(element) => {
                held.clear();
                let name = element.name().as_ref().to_owned();
                builder.start(&name)?;
                builder.end(&name, "")?;
            }
            Event::End(element) => {
                let name = element.name().as_ref().to_owned();
                if name != "plist" {
                    builder.end(&name, &std::mem::take(&mut held))?;
                }
            }
        }
    }
    if !in_plist {
        return Err("the file is not a property list".to_owned());
    }
    match builder.result {
        Some(Value::Dict(top)) => Ok(top),
        _ => Err("the property list holds no dictionary".to_owned()),
    }
}

impl Definition {
    /// Reads the definition `kr` writes: the keys of its `render`, and none other.
    ///
    /// # Errors
    ///
    /// Says what is wrong: a key that the stand-in does not apply, a key twice, a value of another
    /// kind, or a key that is missing.
    pub fn read(text: &str) -> Result<Self, String> {
        let mut definition = Self {
            label: String::new(),
            arguments: Vec::new(),
            run_at_load: true,
            keep_alive: true,
            session_type: String::new(),
            working_directory: String::new(),
            umask: u32::MAX,
            standard_out: String::new(),
            standard_error: String::new(),
            environment: Vec::new(),
        };
        let mut seen: Vec<String> = Vec::new();
        for (key, value) in parse(text)? {
            if seen.contains(&key) {
                return Err(format!("the key {key} is there twice"));
            }
            match (key.as_str(), value) {
                ("Label", Value::String(label)) => definition.label = label,
                ("ProgramArguments", Value::Array(items)) => {
                    definition.arguments = items
                        .into_iter()
                        .map(|item| match item {
                            Value::String(argument) => Ok(argument),
                            _ => Err("an argument is not a string".to_owned()),
                        })
                        .collect::<Result<_, _>>()?;
                }
                ("RunAtLoad", Value::Bool(value)) => definition.run_at_load = value,
                ("KeepAlive", Value::Bool(value)) => definition.keep_alive = value,
                ("LimitLoadToSessionType", Value::String(value)) => definition.session_type = value,
                ("ProcessType", Value::String(_)) => {}
                ("WorkingDirectory", Value::String(value)) => definition.working_directory = value,
                ("Umask", Value::Integer(value)) => {
                    definition.umask = u32::try_from(value)
                        .ok()
                        .filter(|mask| *mask <= 0o777)
                        .ok_or_else(|| format!("{value} is not a file mode mask"))?;
                }
                ("StandardOutPath", Value::String(value)) => definition.standard_out = value,
                ("StandardErrorPath", Value::String(value)) => definition.standard_error = value,
                ("EnvironmentVariables", Value::Dict(entries)) => {
                    for (name, entry) in entries {
                        let Value::String(entry) = entry else {
                            return Err(format!("the variable {name} is not a string"));
                        };
                        definition.environment.push((name, entry));
                    }
                }
                (other, _) => {
                    return Err(format!(
                        "the key {other} is one the stand-in does not apply, or its value is not \
                         of the kind launchd reads for it"
                    ));
                }
            }
            seen.push(key);
        }
        for required in [
            "Label",
            "ProgramArguments",
            "RunAtLoad",
            "KeepAlive",
            "LimitLoadToSessionType",
            "WorkingDirectory",
            "Umask",
            "StandardOutPath",
            "StandardErrorPath",
        ] {
            if !seen.iter().any(|key| key == required) {
                return Err(format!("the key {required} is missing"));
            }
        }
        if definition.arguments.is_empty() {
            return Err("the definition names no program".to_owned());
        }
        Ok(definition)
    }
}

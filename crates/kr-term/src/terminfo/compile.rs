//! The compiled form of the pinned database, and the directory a terminfo library reads it from.
//!
//! The database exists twice: as Rust data, which the XTGETTCAP responder answers from, and as the
//! binary file every terminfo library loads. Both come from one description, so an application that
//! reads a capability and one that asks the terminal for it get the same value.
//!
//! The file is the legacy binary format: a header, the terminal names, the boolean, number and
//! string tables of the predefined capabilities, and after them an extended section for every
//! capability the library does not predefine (`Tc`, `RGB`, `BE`, `BD`, `PS`, `PE`, the modified-key
//! strings and others). A library that predates the extended section stops reading at the size the
//! header gives and never sees it. Numbers are 16 bits wide, so the format holds none above 32767;
//! a larger value needs a different magic number and 32-bit numbers, and is refused here.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use super::names;

/// The names line of the pinned entry: the terminal name, then a description.
///
/// A description cannot hold a comma, because the source form of an entry ends each field with one.
pub const TERMINAL_NAMES: &str = "xterm-256color|xterm with 256 colors (KalaReach kr-vt/1)";

/// The first two bytes of a compiled entry, little-endian: octal 0432.
const MAGIC: u16 = 0o432;

/// The most bytes the names line may hold, its NUL included.
const MAX_NAMES_BYTES: usize = 128;

/// The most bytes a compiled entry may hold: the limit of the format this writes, which a library
/// older than the one that added the larger format reads as the end of the entry.
const MAX_ENTRY_BYTES: usize = 4_096;

/// Why a description cannot be compiled.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CompileError {
    /// A number is negative or does not fit 16 bits.
    #[error("capability {name} has the value {value}, which the 16-bit format cannot hold")]
    NumberOutOfRange {
        /// The capability.
        name: String,
        /// Its value.
        value: i32,
    },
    /// A string value holds a NUL byte, which ends a string in the file.
    #[error("capability {name} holds a NUL byte")]
    EmbeddedNul {
        /// The capability.
        name: String,
    },
    /// A capability name is empty, or holds a byte the file cannot carry in a name.
    #[error("{name:?} is not a capability name")]
    BadName {
        /// The name.
        name: String,
    },
    /// The names line is empty or holds a NUL byte.
    #[error("the terminal names line {names:?} is not usable")]
    BadNames {
        /// The names line.
        names: String,
    },
    /// A table or the entry as a whole is larger than the format allows.
    #[error("the entry is larger than the format allows ({what})")]
    TooLarge {
        /// Which limit was crossed.
        what: &'static str,
    },
}

/// One terminal description, ready to compile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Description {
    /// The names line: the terminal name, then any aliases, then a description, separated by `|`.
    pub names: String,
    /// The boolean capabilities the terminal has.
    pub booleans: BTreeSet<String>,
    /// The numeric capabilities and their values.
    pub numbers: BTreeMap<String, i32>,
    /// The string capabilities and their values, padding directives already removed.
    pub strings: BTreeMap<String, String>,
}

impl Description {
    /// The pinned database, taken from the same data the responder answers from.
    #[must_use]
    pub fn pinned() -> Self {
        Self {
            names: TERMINAL_NAMES.to_owned(),
            booleans: super::booleans()
                .iter()
                .map(|name| (*name).to_owned())
                .collect(),
            numbers: super::numbers()
                .iter()
                .map(|(name, value)| ((*name).to_owned(), *value))
                .collect(),
            strings: super::strings()
                .iter()
                .map(|cap| (cap.name.to_owned(), cap.value.to_owned()))
                .collect(),
        }
    }

    /// The terminal name a library looks the entry up by: the first name on the names line.
    #[must_use]
    pub fn terminal_name(&self) -> &str {
        self.names.split('|').next().unwrap_or_default()
    }

    /// The directories of a database the entry is stored in, one for each lookup convention.
    ///
    /// A library names the directory after the terminal name's first character or, when it was
    /// built for a case-insensitive file system, after that character's code in two hexadecimal
    /// digits so that `A` and `a` cannot collide. The choice is made when the library is built,
    /// and macOS's own library keeps its entries under the hexadecimal name. A database that any
    /// host may read holds the entry under both.
    #[must_use]
    pub fn leaf_directories(&self) -> [String; 2] {
        let first = self.terminal_name().chars().next().unwrap_or_default();
        [first.to_string(), format!("{:02x}", u32::from(first))]
    }

    /// Where the entry lives inside the database at `root`, one path for each lookup convention.
    #[must_use]
    pub fn entry_paths(&self, root: &Path) -> [PathBuf; 2] {
        self.leaf_directories()
            .map(|leaf| root.join(leaf).join(self.terminal_name()))
    }

    /// Writes the compiled entry into the database at `root`, under every lookup convention.
    ///
    /// A file that already holds the current bytes is left alone, so a host that materialises the
    /// database at every start does not rewrite it. A file that differs, or is missing, is replaced
    /// by a complete new one: a library reading the entry sees the old file or the new one, never a
    /// partial one.
    ///
    /// # Errors
    ///
    /// Fails when the description cannot be compiled or a file cannot be written.
    pub fn install(&self, root: &Path) -> std::io::Result<()> {
        let bytes = self
            .compile()
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        for target in self.entry_paths(root) {
            if std::fs::read(&target).is_ok_and(|current| current == bytes) {
                continue;
            }
            let directory = target.parent().unwrap_or(root);
            std::fs::create_dir_all(directory)?;
            replace_file(directory, &target, &bytes)?;
        }
        Ok(())
    }

    /// Compiles the description into the file a terminfo library reads.
    ///
    /// # Errors
    ///
    /// Fails when a name or value cannot be stored, or when the entry outgrows the format.
    pub fn compile(&self) -> Result<Vec<u8>, CompileError> {
        if self.names.is_empty() || self.names.contains('\0') {
            return Err(CompileError::BadNames {
                names: self.names.clone(),
            });
        }
        for name in self
            .booleans
            .iter()
            .chain(self.numbers.keys())
            .chain(self.strings.keys())
        {
            if name.is_empty()
                || name
                    .bytes()
                    .any(|byte| byte == 0 || !byte.is_ascii_graphic())
            {
                return Err(CompileError::BadName { name: name.clone() });
            }
        }

        let standard = Standard::of(self)?;
        let extended = Extended::of(self)?;
        let mut names = self.names.clone().into_bytes();
        names.push(0);
        if names.len() > MAX_NAMES_BYTES {
            return Err(CompileError::TooLarge {
                what: "a names line over 128 bytes",
            });
        }

        let mut out = Vec::new();
        push_short(&mut out, MAGIC.cast_signed());
        push_count(&mut out, names.len(), "the names line")?;
        push_count(&mut out, standard.booleans.len(), "the boolean table")?;
        push_count(&mut out, standard.numbers.len(), "the number table")?;
        push_count(&mut out, standard.offsets.len(), "the string table")?;
        push_count(&mut out, standard.strings.len(), "the string data")?;
        out.extend_from_slice(&names);
        out.extend_from_slice(&standard.booleans);
        pad_to_even(&mut out);
        for number in &standard.numbers {
            push_short(&mut out, *number);
        }
        for offset in &standard.offsets {
            push_short(&mut out, *offset);
        }
        out.extend_from_slice(&standard.strings);

        if !extended.is_empty() {
            pad_to_even(&mut out);
            extended.write(&mut out)?;
        }
        if out.len() > MAX_ENTRY_BYTES {
            return Err(CompileError::TooLarge {
                what: "more than 4096 bytes",
            });
        }
        Ok(out)
    }
}

/// The compiled pinned database.
///
/// # Errors
///
/// Fails only if the pinned data cannot be compiled, which the crate's tests rule out.
pub fn compiled() -> Result<Vec<u8>, CompileError> {
    Description::pinned().compile()
}

/// Writes the pinned database into `root`, under each directory a library may look in.
///
/// See [`Description::install`].
///
/// # Errors
///
/// Fails when the pinned data cannot be compiled or a file cannot be written.
pub fn write_database(root: &Path) -> std::io::Result<()> {
    Description::pinned().install(root)
}

fn replace_file(directory: &Path, target: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let name = target
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    // Unique within this process as well as across processes, so two threads installing at once
    // never write one staging file.
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let staging = directory.join(format!(
        ".{name}.{}.{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let mut file = std::fs::File::create(&staging)?;
    let written = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    written
        .and_then(|()| std::fs::rename(&staging, target))
        .inspect_err(|_| {
            let _ = std::fs::remove_file(&staging);
        })
}

/// The predefined capabilities of one entry, in the layout the file stores them in.
struct Standard {
    booleans: Vec<u8>,
    numbers: Vec<i16>,
    offsets: Vec<i16>,
    strings: Vec<u8>,
}

impl Standard {
    fn of(description: &Description) -> Result<Self, CompileError> {
        let mut booleans = Vec::new();
        for name in &description.booleans {
            if let Some(index) = position(&names::BOOLEANS, name) {
                if booleans.len() <= index {
                    booleans.resize(index + 1, 0);
                }
                booleans[index] = 1;
            }
        }

        let mut numbers = Vec::new();
        for (name, value) in &description.numbers {
            if let Some(index) = position(&names::NUMBERS, name) {
                if numbers.len() <= index {
                    numbers.resize(index + 1, ABSENT);
                }
                numbers[index] = number(name, *value)?;
            }
        }

        let mut placed: BTreeMap<usize, &str> = BTreeMap::new();
        for (name, value) in &description.strings {
            if let Some(index) = position(&names::STRINGS, name) {
                if value.contains('\0') {
                    return Err(CompileError::EmbeddedNul { name: name.clone() });
                }
                placed.insert(index, value);
            }
        }
        let mut offsets = Vec::new();
        let mut strings = Vec::new();
        if let Some(last) = placed.keys().next_back() {
            offsets.resize(last + 1, ABSENT);
        }
        for (index, value) in placed {
            offsets[index] = offset(strings.len(), "the string data")?;
            strings.extend_from_slice(value.as_bytes());
            strings.push(0);
        }
        Ok(Self {
            booleans,
            numbers,
            offsets,
            strings,
        })
    }
}

/// The user-defined capabilities of one entry, which the file stores after the predefined ones.
///
/// Each kind is sorted by name, the order the reference compiler writes them in. The string table
/// holds the values of the string capabilities first and then every name, booleans, numbers and
/// strings in turn; a name's offset counts from the start of the names, not of the table.
struct Extended<'a> {
    booleans: Vec<&'a str>,
    numbers: Vec<(&'a str, i16)>,
    strings: Vec<(&'a str, &'a str)>,
}

impl<'a> Extended<'a> {
    fn of(description: &'a Description) -> Result<Self, CompileError> {
        let booleans = description
            .booleans
            .iter()
            .filter(|name| position(&names::BOOLEANS, name).is_none())
            .map(String::as_str)
            .collect();
        let mut numbers = Vec::new();
        for (name, value) in &description.numbers {
            if position(&names::NUMBERS, name).is_none() {
                numbers.push((name.as_str(), number(name, *value)?));
            }
        }
        let mut strings = Vec::new();
        for (name, value) in &description.strings {
            if position(&names::STRINGS, name).is_none() {
                if value.contains('\0') {
                    return Err(CompileError::EmbeddedNul { name: name.clone() });
                }
                strings.push((name.as_str(), value.as_str()));
            }
        }
        Ok(Self {
            booleans,
            numbers,
            strings,
        })
    }

    fn is_empty(&self) -> bool {
        self.booleans.is_empty() && self.numbers.is_empty() && self.strings.is_empty()
    }

    fn write(&self, out: &mut Vec<u8>) -> Result<(), CompileError> {
        let mut values = Vec::new();
        let mut value_offsets = Vec::new();
        for (_, value) in &self.strings {
            value_offsets.push(offset(values.len(), "the extended string data")?);
            values.extend_from_slice(value.as_bytes());
            values.push(0);
        }
        let mut names = Vec::new();
        let mut name_offsets = Vec::new();
        let all_names = self
            .booleans
            .iter()
            .copied()
            .chain(self.numbers.iter().map(|(name, _)| *name))
            .chain(self.strings.iter().map(|(name, _)| *name));
        for name in all_names {
            name_offsets.push(offset(names.len(), "the extended names")?);
            names.extend_from_slice(name.as_bytes());
            names.push(0);
        }

        push_count(out, self.booleans.len(), "the extended boolean table")?;
        push_count(out, self.numbers.len(), "the extended number table")?;
        push_count(out, self.strings.len(), "the extended string table")?;
        push_count(
            out,
            value_offsets.len() + name_offsets.len(),
            "the extended offsets",
        )?;
        push_count(out, values.len() + names.len(), "the extended string data")?;
        out.extend(std::iter::repeat_n(1, self.booleans.len()));
        pad_to_even(out);
        for (_, value) in &self.numbers {
            push_short(out, *value);
        }
        for offset in value_offsets.iter().chain(&name_offsets) {
            push_short(out, *offset);
        }
        out.extend_from_slice(&values);
        out.extend_from_slice(&names);
        Ok(())
    }
}

/// The value a table holds for a capability the entry does not have.
const ABSENT: i16 = -1;

fn position(table: &[&str], name: &str) -> Option<usize> {
    table.iter().position(|candidate| *candidate == name)
}

fn number(name: &str, value: i32) -> Result<i16, CompileError> {
    i16::try_from(value)
        .ok()
        .filter(|number| *number >= 0)
        .ok_or_else(|| CompileError::NumberOutOfRange {
            name: name.to_owned(),
            value,
        })
}

fn offset(position: usize, what: &'static str) -> Result<i16, CompileError> {
    i16::try_from(position).map_err(|_| CompileError::TooLarge { what })
}

fn push_short(out: &mut Vec<u8>, value: i16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_count(out: &mut Vec<u8>, count: usize, what: &'static str) -> Result<(), CompileError> {
    push_short(out, offset(count, what)?);
    Ok(())
}

fn pad_to_even(out: &mut Vec<u8>) {
    if out.len() % 2 == 1 {
        out.push(0);
    }
}

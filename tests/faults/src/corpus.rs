//! An application's output, kept as a fixture.
//!
//! A corpus is what one application wrote, in the writes it made them in, and nothing else: no
//! expectation is stored with it, because the expectation is the session's own screen at the same
//! point. A write is text where the bytes are text, so a person reading a failure reads what the
//! application drew, and hexadecimal where they are not.
//!
//! ```json
//! {
//!   "format": "kalareach.restore-corpus/1",
//!   "name": "alternate-1049",
//!   "about": "a full-screen application entered and left through mode 1049",
//!   "columns": 24,
//!   "rows": 6,
//!   "writes": [{ "text": "shell$ vi\r\n" }, { "hex": "1b5b3f3130343968" }]
//! }
//! ```

use std::path::{Path, PathBuf};

use serde::Deserialize;

/// The format every corpus names, so a file of another shape is refused rather than misread.
pub const FORMAT: &str = "kalareach.restore-corpus/1";

/// Where the corpora are kept, from this crate's own directory.
#[must_use]
pub fn directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/faults/restore")
}

/// One application's output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Corpus {
    /// Its name, which is its file's name.
    pub name: String,
    /// What it exercises, for a person reading a failure.
    pub about: String,
    /// The session's columns.
    pub columns: u16,
    /// The session's rows.
    pub rows: u16,
    /// The writes, in order.
    pub writes: Vec<Vec<u8>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    format: String,
    name: String,
    about: String,
    columns: u16,
    rows: u16,
    writes: Vec<StoredWrite>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
enum StoredWrite {
    Text(String),
    Hex(String),
}

impl Corpus {
    /// Reads one corpus.
    ///
    /// # Errors
    ///
    /// Returns what is wrong with the file: unreadable, another format, a name that is not its
    /// file's, a write that is empty or not hexadecimal, or a screen with no cells.
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|error| format!("{} could not be read: {error}", path.display()))?;
        Self::parse(path, &text)
    }

    /// Reads one corpus from the text of the file at `path`.
    ///
    /// # Errors
    ///
    /// As [`Corpus::load`], apart from reading.
    pub fn parse(path: &Path, text: &str) -> Result<Self, String> {
        let stored: Stored = serde_json::from_str(text)
            .map_err(|error| format!("{} is not a corpus: {error}", path.display()))?;
        if stored.format != FORMAT {
            return Err(format!(
                "{} is {:?}, and a corpus is {FORMAT:?}",
                path.display(),
                stored.format
            ));
        }
        let stem = path.file_stem().and_then(|stem| stem.to_str());
        if stem != Some(stored.name.as_str()) {
            return Err(format!(
                "{} names itself {:?}; a corpus is named by its file",
                path.display(),
                stored.name
            ));
        }
        if stored.columns == 0 || stored.rows == 0 {
            return Err(format!("{} has a screen with no cells", path.display()));
        }
        let mut writes = Vec::with_capacity(stored.writes.len());
        for (index, write) in stored.writes.into_iter().enumerate() {
            let bytes = match write {
                StoredWrite::Text(text) => text.into_bytes(),
                StoredWrite::Hex(digits) => hex::decode(&digits).map_err(|error| {
                    format!(
                        "{} write {index} is not hexadecimal: {error}",
                        path.display()
                    )
                })?,
            };
            if bytes.is_empty() {
                return Err(format!("{} write {index} writes nothing", path.display()));
            }
            writes.push(bytes);
        }
        if writes.is_empty() {
            return Err(format!("{} writes nothing", path.display()));
        }
        Ok(Self {
            name: stored.name,
            about: stored.about,
            columns: stored.columns,
            rows: stored.rows,
            writes,
        })
    }

    /// Every corpus kept with this crate, in name order.
    ///
    /// # Errors
    ///
    /// Returns what is wrong with the first file that cannot be read as a corpus, or with the
    /// directory.
    pub fn all() -> Result<Vec<Self>, String> {
        let directory = directory();
        let mut paths: Vec<PathBuf> = std::fs::read_dir(&directory)
            .map_err(|error| format!("{} could not be listed: {error}", directory.display()))?
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "json")
            })
            .collect();
        paths.sort();
        paths.iter().map(|path| Self::load(path)).collect()
    }

    /// The whole output, as one run of bytes.
    #[must_use]
    pub fn bytes(&self) -> Vec<u8> {
        self.writes.concat()
    }

    /// The offset each write ends at.
    #[must_use]
    pub fn write_ends(&self) -> Vec<usize> {
        self.writes
            .iter()
            .scan(0, |end, write| {
                *end += write.len();
                Some(*end)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<Corpus, String> {
        Corpus::parse(Path::new("/corpora/sample.json"), text)
    }

    #[test]
    fn text_and_hexadecimal_writes_are_read_as_the_bytes_they_spell() {
        let corpus = parse(
            r#"{"format":"kalareach.restore-corpus/1","name":"sample","about":"a sample",
               "columns":4,"rows":2,"writes":[{"text":"a\u001b[1m"},{"hex":"ff41"}]}"#,
        )
        .expect("a corpus");
        assert_eq!(corpus.writes, vec![b"a\x1b[1m".to_vec(), vec![0xff, 0x41]]);
        assert_eq!(corpus.bytes(), b"a\x1b[1m\xffA".to_vec());
        assert_eq!(corpus.write_ends(), vec![5, 7]);
    }

    #[test]
    fn a_file_of_another_format_or_another_name_or_an_empty_write_is_refused() {
        let other = parse(
            r#"{"format":"x/1","name":"sample","about":"","columns":4,"rows":2,"writes":[{"text":"a"}]}"#,
        );
        assert!(other.is_err_and(|error| error.contains("x/1")));
        let renamed = parse(
            r#"{"format":"kalareach.restore-corpus/1","name":"other","about":"","columns":4,"rows":2,"writes":[{"text":"a"}]}"#,
        );
        assert!(renamed.is_err_and(|error| error.contains("named by its file")));
        let empty = parse(
            r#"{"format":"kalareach.restore-corpus/1","name":"sample","about":"","columns":4,"rows":2,"writes":[{"text":""}]}"#,
        );
        assert!(empty.is_err_and(|error| error.contains("writes nothing")));
    }
}

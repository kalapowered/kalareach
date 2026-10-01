//! The committed records of physical terminals, held to the corpus and to the grid as it is now.
//!
//! A record says what a terminal answered and what the canonical grid answered at the time. If the
//! corpus or the grid changes, a record that still passes would be a claim about something that no
//! longer exists, so these tests fail until the terminal is measured again.

use std::path::{Path, PathBuf};

use kr_term_probe::corpus;
use kr_term_probe::run;
use serde_json::Value;

fn records() -> Vec<(PathBuf, Value)> {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("terminal")
        .join("physical");
    let mut found: Vec<_> = std::fs::read_dir(&directory)
        .unwrap_or_else(|error| panic!("{}: {error}", directory.display()))
        .map(|entry| entry.expect("an entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .map(|path| {
            let text = std::fs::read_to_string(&path).expect("a record");
            let value = serde_json::from_str(&text)
                .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
            (path, value)
        })
        .collect();
    found.sort_by(|left, right| left.0.cmp(&right.0));
    found
}

fn window(record: &Value) -> (u32, u32) {
    let size = record["window"].as_array().expect("a window");
    (
        u32::try_from(size[0].as_u64().expect("columns")).expect("columns fit"),
        u32::try_from(size[1].as_u64().expect("rows")).expect("rows fit"),
    )
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|at| u8::from_str_radix(&text[at * 2..at * 2 + 2], 16).expect("hexadecimal"))
        .collect()
}

#[test]
fn every_record_measures_the_current_corpus() {
    let records = records();
    assert!(records.len() >= 2, "records of at least two terminals");
    for (path, record) in &records {
        let (cols, rows) = window(record);
        let expected = corpus::steps(cols, rows);
        let steps = record["steps"].as_array().expect("steps");
        assert_eq!(steps.len(), expected.len(), "{}", path.display());
        for (step, expected) in steps.iter().zip(&expected) {
            assert_eq!(step["id"], expected.id.as_str(), "{}", path.display());
            assert_eq!(hex(step["bytes"].as_str().expect("bytes")), expected.bytes);
        }
    }
}

#[test]
fn every_record_holds_the_grids_answer_as_it_is_now() {
    for (path, record) in records() {
        let (cols, rows) = window(&record);
        for step in record["steps"].as_array().expect("steps") {
            let (position, pending) =
                run::canonical(cols, rows, &hex(step["bytes"].as_str().expect("bytes")));
            assert_eq!(
                step["canonical"],
                serde_json::json!({ "row": position.row, "col": position.col }),
                "{}: {} has a new canonical position; measure the terminal again",
                path.display(),
                step["id"]
            );
            assert_eq!(step["canonical_pending_wrap"], pending, "{}", step["id"]);
        }
    }
}

#[test]
fn every_summary_counts_its_steps_and_every_answer_is_one_terminal_reported() {
    for (path, record) in records() {
        let steps = record["steps"].as_array().expect("steps");
        let agree = steps.iter().filter(|step| step["agrees"] == true).count();
        let silent = steps
            .iter()
            .filter(|step| step["terminal"].is_null())
            .count();
        let summary = &record["summary"];
        assert_eq!(summary["steps"], steps.len(), "{}", path.display());
        assert_eq!(summary["agree"], agree, "{}", path.display());
        assert_eq!(summary["unanswered"], silent, "{}", path.display());
        assert_eq!(
            summary["differ"],
            steps.len() - agree - silent,
            "{}",
            path.display()
        );
        for step in steps {
            assert_eq!(
                step["agrees"] == true,
                step["terminal"] == step["canonical"],
                "{}: {}",
                path.display(),
                step["id"]
            );
        }
        assert_eq!(
            record["canonical_library"],
            kr_term::unicode::LIBRARY.revision,
            "{} was measured against another revision of the grid's library",
            path.display()
        );
        assert!(
            record["launcher"]["application"].is_string()
                && record["launcher"]["version"].is_string(),
            "{} names the application and its version",
            path.display()
        );
        assert_eq!(
            record["launcher"]["wrapped_in_a_multiplexer"],
            false,
            "{} was measured inside a multiplexer",
            path.display()
        );
    }
}

/// A step either terminal differs on is written up in the terminal reference with its bytes.
#[test]
fn every_difference_is_written_up() {
    let reference = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("docs")
            .join("terminal")
            .join("README.md"),
    )
    .expect("the terminal reference");
    for (path, record) in records() {
        for step in record["steps"].as_array().expect("steps") {
            if step["agrees"] == false {
                let id = step["id"].as_str().expect("an id");
                assert!(
                    reference.contains(&format!("`{id}`")),
                    "{}: {id} is a difference the terminal reference does not list",
                    path.display()
                );
            }
        }
    }
}

/// A record is kept in a repository: it names programs and application bundles, never a home
/// directory, a user, a session or the directory of a program outside an application.
#[test]
fn no_record_names_a_home_directory_a_user_or_a_program_directory() {
    fn strings<'a>(value: &'a Value, found: &mut Vec<&'a str>) {
        match value {
            Value::String(text) => found.push(text),
            Value::Array(items) => items.iter().for_each(|item| strings(item, found)),
            Value::Object(fields) => fields.values().for_each(|field| strings(field, found)),
            _ => {}
        }
    }
    for (path, record) in records() {
        let mut found = Vec::new();
        strings(&record["launcher"], &mut found);
        for text in found {
            for private in ["/Users/", "/home/", "C:\\Users", "~/"] {
                assert!(
                    !text.contains(private),
                    "{} writes {text:?}, which holds {private:?}",
                    path.display()
                );
            }
        }
        for ancestor in record["launcher"]["ancestors"]
            .as_array()
            .expect("ancestors")
        {
            let name = ancestor.as_str().expect("a program name");
            assert!(
                !name.contains('/') && !name.contains('\\'),
                "{}: {name:?} is a path, and a record keeps the program's name",
                path.display()
            );
        }
    }
}

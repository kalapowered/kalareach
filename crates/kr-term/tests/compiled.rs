//! The compiled form of the pinned database, read back by the terminfo tools of the host.
//!
//! The Rust data, the XTGETTCAP responder and the binary file a terminfo library loads must say the
//! same thing. Reading the file back with the host's own `infocmp` and `tput` is what proves it: a
//! writer that agrees only with its own reader proves nothing about the libraries a shell, `vim` or
//! `tmux` will load it with.

use std::path::{Path, PathBuf};

use kr_term::terminfo::{self, CompileError, Description};

/// A scratch directory that removes itself.
struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "kr-term-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).expect("a scratch directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ------------------------------------------------------------------------------- the header

fn short(bytes: &[u8], at: usize) -> i16 {
    i16::from_le_bytes([bytes[at], bytes[at + 1]])
}

/// The file starts with the legacy magic number and sizes that add up to the bytes that follow.
#[test]
fn the_header_names_what_the_file_holds() {
    let bytes = terminfo::compiled().expect("the pinned database compiles");
    assert_eq!(short(&bytes, 0), 0o432, "the legacy magic number");
    let names = usize::try_from(short(&bytes, 2)).expect("a size");
    let booleans = usize::try_from(short(&bytes, 4)).expect("a count");
    let numbers = usize::try_from(short(&bytes, 6)).expect("a count");
    let offsets = usize::try_from(short(&bytes, 8)).expect("a count");
    let table = usize::try_from(short(&bytes, 10)).expect("a size");
    let text = &bytes[12..12 + names];
    assert_eq!(text.last(), Some(&0), "the names line ends in NUL");
    assert_eq!(
        &text[..text.len() - 1],
        terminfo::TERMINAL_NAMES.as_bytes(),
        "the names line"
    );
    let unpadded =
        12 + names + booleans + (names + booleans) % 2 + numbers * 2 + offsets * 2 + table;
    // What follows the string table is the extended header, at an even offset.
    let standard = unpadded + unpadded % 2;
    let extended = usize::try_from(short(&bytes, standard)).expect("a count")
        + usize::try_from(short(&bytes, standard + 2)).expect("a count")
        + usize::try_from(short(&bytes, standard + 4)).expect("a count");
    let expected_extended = ["AX", "RGB", "Tc", "XT"].len()
        + terminfo::strings()
            .iter()
            .filter(|cap| {
                ["BD", "BE", "Cr", "Cs", "E3", "Ms", "PE", "PS", "Se", "Ss"].contains(&cap.name)
            })
            .count();
    assert!(
        extended >= expected_extended,
        "the extended section carries the user-defined capabilities ({extended})"
    );
    let string_bytes = usize::try_from(short(&bytes, standard + 8)).expect("a size");
    let extended_offsets = usize::try_from(short(&bytes, standard + 6)).expect("a count");
    let ext_booleans = usize::try_from(short(&bytes, standard)).expect("a count");
    let ext_numbers = usize::try_from(short(&bytes, standard + 2)).expect("a count");
    let end = standard
        + 10
        + ext_booleans
        + ext_booleans % 2
        + ext_numbers * 2
        + extended_offsets * 2
        + string_bytes;
    assert_eq!(
        end,
        bytes.len(),
        "the header accounts for every byte of the file"
    );
}

/// A value the 16-bit format cannot hold, or a byte a string cannot carry, is refused rather than
/// stored wrongly.
#[test]
fn a_value_the_format_cannot_hold_is_refused() {
    let mut description = Description::pinned();
    description.numbers.insert("pairs".to_owned(), 65_536);
    assert!(matches!(
        description.compile(),
        Err(CompileError::NumberOutOfRange { .. })
    ));

    let mut description = Description::pinned();
    description.numbers.insert("cols".to_owned(), -1);
    assert!(matches!(
        description.compile(),
        Err(CompileError::NumberOutOfRange { .. })
    ));

    let mut description = Description::pinned();
    description
        .strings
        .insert("bel".to_owned(), "a\0b".to_owned());
    assert!(matches!(
        description.compile(),
        Err(CompileError::EmbeddedNul { .. })
    ));
    let mut description = Description::pinned();
    description
        .strings
        .insert("Zz".to_owned(), "a\0b".to_owned());
    assert!(matches!(
        description.compile(),
        Err(CompileError::EmbeddedNul { .. })
    ));

    let mut description = Description::pinned();
    description.booleans.insert("has space".to_owned());
    assert!(matches!(
        description.compile(),
        Err(CompileError::BadName { .. })
    ));

    let mut description = Description::pinned();
    description.names = "x".repeat(200);
    assert!(matches!(
        description.compile(),
        Err(CompileError::TooLarge { .. })
    ));
}

/// The same description compiles to the same bytes, whatever order its capabilities were added in.
#[test]
fn the_file_does_not_depend_on_how_the_description_was_built() {
    let first = terminfo::compiled().expect("compiles");
    let second = Description::pinned().compile().expect("compiles");
    assert_eq!(first, second);
    let mut shuffled = Description::pinned();
    let strings: Vec<_> = shuffled.strings.clone().into_iter().rev().collect();
    shuffled.strings = strings.into_iter().collect();
    assert_eq!(first, shuffled.compile().expect("compiles"));
}

/// The database directory holds the entry under both lookup conventions, and writing it again
/// changes nothing and leaves no staging file behind.
#[test]
fn the_database_directory_holds_the_entry_under_every_convention() {
    let scratch = Scratch::new("database");
    let pinned = Description::pinned();
    assert_eq!(pinned.leaf_directories(), ["x", "78"]);
    terminfo::write_database(scratch.path()).expect("the database is written");
    let expected = terminfo::compiled().expect("compiles");
    let paths = pinned.entry_paths(scratch.path());
    for path in &paths {
        assert_eq!(std::fs::read(path).expect("the entry"), expected);
    }

    // An entry that is current is left alone: it is still the file that was written first.
    let identity = |path: &Path| {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            std::fs::metadata(path)
                .map(|meta| meta.ino())
                .expect("a file")
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            0_u64
        }
    };
    let before: Vec<_> = paths.iter().map(|path| identity(path)).collect();
    terminfo::write_database(scratch.path()).expect("the database is written again");
    let after: Vec<_> = paths.iter().map(|path| identity(path)).collect();
    assert_eq!(before, after, "an entry that is current is not rewritten");

    // A stale or partial file is replaced whole, and no staging file stays behind.
    std::fs::write(&paths[0], b"stale").expect("a stale entry");
    std::fs::remove_file(&paths[1]).expect("a missing entry");
    terminfo::write_database(scratch.path()).expect("the database is repaired");
    for path in &paths {
        assert_eq!(std::fs::read(path).expect("the entry"), expected);
        let names: Vec<_> = std::fs::read_dir(path.parent().expect("a leaf directory"))
            .expect("a leaf directory")
            .map(|entry| entry.expect("an entry").file_name())
            .collect();
        assert_eq!(names, [std::ffi::OsString::from("xterm-256color")]);
    }
}

// ------------------------------------------------------------------- the host's own tools

#[cfg(unix)]
mod tools {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use std::process::Command;

    /// Writes `description` into a database directory the way the host does, under every leaf.
    fn database_of(description: &Description, root: &Path) {
        description.install(root).expect("the database is written");
    }

    /// The `infocmp` programs a host may have: the system's, and one from a package manager.
    fn infocmps() -> Vec<PathBuf> {
        let mut found = Vec::new();
        for candidate in [
            "/usr/bin/infocmp",
            "/opt/homebrew/opt/ncurses/bin/infocmp",
            "/usr/local/opt/ncurses/bin/infocmp",
        ] {
            if Path::new(candidate).is_file() {
                found.push(PathBuf::from(candidate));
            }
        }
        assert!(
            !found.is_empty(),
            "a Unix host has an infocmp to read the database back with"
        );
        found
    }

    fn version(program: &Path) -> String {
        let output = Command::new(program).arg("-V").output().expect("a version");
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }

    /// What `infocmp` reads out of an entry.
    #[derive(Debug, Default, PartialEq, Eq)]
    pub struct Read {
        pub file: String,
        pub names: String,
        pub booleans: BTreeSet<String>,
        pub numbers: BTreeMap<String, i32>,
        pub strings: BTreeMap<String, Vec<u8>>,
    }

    fn scrub(command: &mut Command, home: &Path) {
        command
            .env_remove("TERMINFO")
            .env_remove("TERMINFO_DIRS")
            .env_remove("COLUMNS")
            .env_remove("LINES")
            .env("HOME", home);
    }

    /// Reads `xterm-256color` from `root` with `infocmp -x -A`, one capability to a line.
    pub fn read_with(infocmp: &Path, root: &Path) -> Read {
        let home = Scratch::new("home");
        let mut command = Command::new(infocmp);
        scrub(&mut command, home.path());
        let output = command
            .args(["-x", "-1", "-A"])
            .arg(root)
            .arg("xterm-256color")
            .output()
            .expect("infocmp runs");
        assert!(
            output.status.success(),
            "{} could not read the entry: {}",
            infocmp.display(),
            String::from_utf8_lossy(&output.stderr)
        );
        parse(&String::from_utf8(output.stdout).expect("infocmp prints text"))
    }

    /// Reads the host's own `xterm-256color`: what an unmanaged shell on this host, reached over
    /// SSH or started outside KalaReach, has for the same name.
    fn read_stock(infocmp: &Path) -> Read {
        let home = Scratch::new("home");
        let mut command = Command::new(infocmp);
        scrub(&mut command, home.path());
        let output = command
            .args(["-x", "-1", "xterm-256color"])
            .output()
            .expect("infocmp runs");
        assert!(
            output.status.success(),
            "{} has no xterm-256color: {}",
            infocmp.display(),
            String::from_utf8_lossy(&output.stderr)
        );
        parse(&String::from_utf8(output.stdout).expect("infocmp prints text"))
    }

    fn parse(text: &str) -> Read {
        let mut read = Read::default();
        for line in text.lines() {
            if let Some(file) = line.strip_prefix("#\tReconstructed via infocmp from file: ") {
                read.file = file.to_owned();
            } else if line.starts_with('#') {
                continue;
            } else if let Some(field) = line.strip_prefix('\t') {
                let field = field.strip_suffix(',').expect("a field ends in a comma");
                match field.find(['=', '#']) {
                    None => {
                        read.booleans.insert(field.to_owned());
                    }
                    Some(at) if field.as_bytes()[at] == b'#' => {
                        let value = &field[at + 1..];
                        let number = value.strip_prefix("0x").map_or_else(
                            || value.parse::<i32>(),
                            |hex| i32::from_str_radix(hex, 16),
                        );
                        read.numbers
                            .insert(field[..at].to_owned(), number.expect("a number"));
                    }
                    Some(at) => {
                        read.strings
                            .insert(field[..at].to_owned(), unescape(&field[at + 1..]));
                    }
                }
            } else if !line.is_empty() {
                read.names = line.strip_suffix(',').unwrap_or(line).to_owned();
            }
        }
        read
    }

    /// Decodes the escapes terminfo source uses in a string value.
    fn unescape(text: &str) -> Vec<u8> {
        let bytes = text.as_bytes();
        let mut out = Vec::new();
        let mut at = 0;
        while at < bytes.len() {
            let byte = bytes[at];
            at += 1;
            match byte {
                b'\\' => {
                    let escaped = bytes[at];
                    at += 1;
                    match escaped {
                        b'E' | b'e' => out.push(0x1b),
                        b'n' | b'l' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0c),
                        b'a' => out.push(0x07),
                        b'v' => out.push(0x0b),
                        b's' => out.push(b' '),
                        b'0'..=b'7' => {
                            let mut value = u32::from(escaped - b'0');
                            for _ in 0..2 {
                                match bytes.get(at) {
                                    Some(digit @ b'0'..=b'7') => {
                                        value = value * 8 + u32::from(digit - b'0');
                                        at += 1;
                                    }
                                    _ => break,
                                }
                            }
                            out.push(u8::try_from(value).expect("an octal byte"));
                        }
                        other => out.push(other),
                    }
                }
                b'^' => {
                    let control = bytes[at];
                    at += 1;
                    out.push(if control == b'?' {
                        0x7f
                    } else {
                        control & 0x1f
                    });
                }
                b'$' if bytes.get(at) == Some(&b'<') => {
                    // Padding is a delay a library performs, not a byte it writes.
                    while bytes.get(at).is_some_and(|byte| *byte != b'>') {
                        at += 1;
                    }
                    at += 1;
                }
                other => out.push(other),
            }
        }
        out
    }

    /// Every way `read` differs from `description`, and from the responder's answers.
    fn differences(read: &Read, description: &Description) -> Vec<String> {
        let mut found = Vec::new();
        let names = &description.names;
        if &read.names != names {
            found.push(format!("names: {:?} against {names:?}", read.names));
        }
        for name in description.booleans.symmetric_difference(&read.booleans) {
            found.push(format!("boolean {name}"));
        }
        let expected_numbers = &description.numbers;
        for name in expected_numbers.keys().chain(read.numbers.keys()) {
            if expected_numbers.get(name) != read.numbers.get(name) {
                found.push(format!(
                    "number {name}: {:?} against {:?}",
                    read.numbers.get(name),
                    expected_numbers.get(name)
                ));
            }
        }
        for name in description.strings.keys().chain(read.strings.keys()) {
            let expected = description
                .strings
                .get(name)
                .map(|value| value.as_bytes().to_vec());
            if expected.as_ref() != read.strings.get(name) {
                found.push(format!(
                    "string {name}: {:?} against {expected:?}",
                    read.strings.get(name)
                ));
            }
        }
        found.sort();
        found.dedup();
        found
    }

    /// The Rust data a description is compared against: the pinned database itself.
    fn pinned_differences(read: &Read) -> Vec<String> {
        differences(read, &Description::pinned())
    }

    /// The value an XTGETTCAP reply carries for `name`, decoded from its reply bytes.
    fn responder_value(name: &str) -> Option<Vec<u8>> {
        let replies = terminfo::xtgettcap_replies(terminfo::to_hex(name.as_bytes()).as_bytes());
        let reply = &replies.first()?.bytes;
        let body = reply.strip_prefix(b"\x1bP1+r")?.strip_suffix(b"\x1b\\")?;
        let (_, value) = std::str::from_utf8(body).ok()?.split_once('=')?;
        terminfo::from_hex(value.as_bytes())
    }

    /// Every string capability the file holds equals what the responder answers for it.
    fn responder_differences(read: &Read) -> Vec<String> {
        let mut found = Vec::new();
        for (name, value) in &read.strings {
            match responder_value(name) {
                Some(answer) if &answer == value => {}
                answer => found.push(format!("responder {name}: {answer:?} against {value:?}")),
            }
        }
        found
    }

    /// `tput -T xterm-256color` against a database directory.
    fn tput(root: &Path, arguments: &[&str]) -> std::process::Output {
        let home = Scratch::new("home");
        let mut command = Command::new("/usr/bin/tput");
        scrub(&mut command, home.path());
        command
            .env("TERMINFO", root)
            .args(["-T", "xterm-256color"])
            .args(arguments)
            .output()
            .expect("tput runs")
    }

    /// What `tput` reads for every capability the description has, against the description.
    fn tput_differences(root: &Path, description: &Description) -> Vec<String> {
        let mut found = Vec::new();
        for (name, value) in &description.numbers {
            let output = tput(root, &[name]);
            // `cols` and `lines` come from the window when there is one, which a test has not.
            let printed = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            if printed != value.to_string() {
                found.push(format!("tput number {name}: {printed:?} against {value}"));
            }
        }
        for name in &description.booleans {
            let output = tput(root, &[name]);
            if !output.status.success() {
                found.push(format!(
                    "tput boolean {name}: exit {:?}",
                    output.status.code()
                ));
            }
        }
        for cap in terminfo::strings() {
            if !description.strings.contains_key(cap.name) {
                continue;
            }
            // Given no arguments `tput` prints a value as it is; given some it expands the value,
            // which is how the representative arguments the class check uses are read back.
            let expected = if cap.arguments.is_empty() {
                cap.value.as_bytes().to_vec()
            } else {
                terminfo::expand(cap.value, cap.arguments)
            };
            let mut arguments = vec![cap.name.to_owned()];
            for argument in cap.arguments {
                arguments.push(match argument {
                    terminfo::Param::Number(value) => value.to_string(),
                    terminfo::Param::Text(text) => (*text).to_owned(),
                });
            }
            let refs: Vec<&str> = arguments.iter().map(String::as_str).collect();
            let output = tput(root, &refs);
            // Newer `tput` follows `clear` with the capability that erases the scrollback, when the
            // entry has one, unless it is told not to. That is `tput`'s own addition to the value.
            let scrollback = description
                .strings
                .get("E3")
                .map(|value| [expected.clone(), value.as_bytes().to_vec()].concat());
            let read_as_expected = output.stdout == expected
                || (cap.name == "clear" && scrollback.is_some_and(|both| output.stdout == both));
            if !read_as_expected {
                found.push(format!(
                    "tput string {}: {:?} against {:?}",
                    cap.name, output.stdout, expected
                ));
            }
        }
        found
    }

    /// Every comparison the brief names, for one reader and one database directory.
    fn compare(infocmp: &Path, root: &Path, description: &Description) -> Comparison {
        let read = read_with(infocmp, root);
        Comparison {
            file: read.file.clone(),
            infocmp: differences(&read, description),
            pinned: pinned_differences(&read),
            responder: responder_differences(&read),
            tput: tput_differences(root, description),
        }
    }

    struct Comparison {
        file: String,
        infocmp: Vec<String>,
        pinned: Vec<String>,
        responder: Vec<String>,
        tput: Vec<String>,
    }

    /// The system's own tools read every capability of the compiled file back equal to the Rust
    /// data, and every string capability equal to the responder's reply.
    #[test]
    fn the_systems_tools_read_back_what_the_data_says() {
        let root = Scratch::new("readback");
        database_of(&Description::pinned(), root.path());
        for infocmp in infocmps() {
            let comparison = compare(&infocmp, root.path(), &Description::pinned());
            let label = format!("{} ({})", infocmp.display(), version(&infocmp));
            eprintln!("read back with {label}: {}", comparison.file);
            assert!(
                comparison
                    .file
                    .starts_with(root.path().to_str().expect("a path")),
                "{label} read the entry from the directory it was given: {}",
                comparison.file
            );
            assert!(
                comparison.infocmp.is_empty(),
                "{label}: {:#?}",
                comparison.infocmp
            );
            assert!(
                comparison.pinned.is_empty(),
                "{label}: {:#?}",
                comparison.pinned
            );
            assert!(
                comparison.responder.is_empty(),
                "{label}: {:#?}",
                comparison.responder
            );
            assert!(
                comparison.tput.is_empty(),
                "{label}: {:#?}",
                comparison.tput
            );
        }
    }

    /// Control: a capability edited in one place makes both comparisons fail, and only that
    /// capability shows in them.
    #[test]
    fn an_edited_capability_fails_both_comparisons() {
        let mut edited = Description::pinned();
        edited
            .strings
            .insert("cup".to_owned(), "\x1b[%i%p2%d;%p1%dH".to_owned());
        edited
            .strings
            .insert("Ms".to_owned(), "\x1b]52;%p1%s;x\x07".to_owned());
        let root = Scratch::new("edited");
        database_of(&edited, root.path());
        let infocmp = infocmps().remove(0);
        let read = read_with(&infocmp, root.path());
        // The file agrees with what it was compiled from and disagrees with the pinned data.
        assert!(differences(&read, &edited).is_empty());
        let against_data = pinned_differences(&read);
        assert!(
            against_data
                .iter()
                .any(|line| line.starts_with("string cup:")),
            "{against_data:?}"
        );
        assert!(
            against_data
                .iter()
                .any(|line| line.starts_with("string Ms:")),
            "{against_data:?}"
        );
        assert_eq!(
            against_data.len(),
            2,
            "nothing else moved: {against_data:?}"
        );
        // And it disagrees with what the responder says.
        let against_responder = responder_differences(&read);
        assert_eq!(against_responder.len(), 2, "{against_responder:?}");
        assert!(
            tput_differences(root.path(), &Description::pinned())
                .iter()
                .any(|line| line.starts_with("tput string cup:"))
        );
    }

    /// A capability that is added or removed is seen as such by the reader.
    #[test]
    fn an_added_or_removed_capability_is_seen_by_the_reader() {
        let mut edited = Description::pinned();
        edited.booleans.remove("Tc");
        edited.booleans.insert("hs".to_owned());
        edited.numbers.insert("Zn".to_owned(), 7);
        edited.strings.remove("kf1");
        let root = Scratch::new("shape");
        database_of(&edited, root.path());
        for infocmp in infocmps() {
            let read = read_with(&infocmp, root.path());
            assert!(
                differences(&read, &edited).is_empty(),
                "{}",
                infocmp.display()
            );
            let against_data = pinned_differences(&read);
            for expected in ["boolean Tc", "boolean hs", "number Zn:", "string kf1:"] {
                assert!(
                    against_data.iter().any(|line| line.starts_with(expected)),
                    "{expected} in {against_data:?}"
                );
            }
        }
    }

    /// The reference compiler, given the source `infocmp` prints for the entry, writes the same
    /// bytes: the file is what `tic -x` would have made, not merely something a reader accepts.
    #[test]
    fn the_reference_compiler_writes_the_same_bytes() {
        for description in [Description::pinned(), odd_sized()] {
            let root = Scratch::new("reference");
            database_of(&description, root.path());
            for infocmp in infocmps() {
                let tic = infocmp.with_file_name("tic");
                let home = Scratch::new("home");
                let mut print = Command::new(&infocmp);
                scrub(&mut print, home.path());
                let source = print
                    .args(["-x", "-I", "-A"])
                    .arg(root.path())
                    .arg(description.terminal_name())
                    .output()
                    .expect("infocmp runs");
                assert!(
                    source.status.success(),
                    "{} could not print the entry: {}",
                    infocmp.display(),
                    String::from_utf8_lossy(&source.stderr)
                );
                let work = Scratch::new("source");
                let source_file = work.path().join("entry.ti");
                std::fs::write(&source_file, &source.stdout).expect("a source file");
                let compiled = work.path().join("compiled");
                let mut compile = Command::new(&tic);
                scrub(&mut compile, home.path());
                let made = compile
                    .args(["-x", "-o"])
                    .arg(&compiled)
                    .arg(&source_file)
                    .output()
                    .expect("tic runs");
                assert!(
                    made.status.success(),
                    "{} failed: {}",
                    tic.display(),
                    String::from_utf8_lossy(&made.stderr)
                );
                let written = description
                    .entry_paths(&compiled)
                    .into_iter()
                    .find(|path| path.is_file())
                    .expect("the reference compiler wrote an entry");
                assert_eq!(
                    std::fs::read(&written).expect("the reference entry"),
                    description.compile().expect("compiles"),
                    "{} ({}) writes other bytes for {}",
                    tic.display(),
                    version(&tic),
                    description.terminal_name()
                );
            }
        }
    }

    /// A small entry whose predefined part ends on an odd byte, which is where the extended
    /// section's alignment shows.
    fn odd_sized() -> Description {
        Description {
            names: "tt|test term".to_owned(),
            booleans: ["am".to_owned(), "Xa".to_owned(), "Xb".to_owned()].into(),
            numbers: [
                ("cols".to_owned(), 80),
                ("Xn".to_owned(), 5),
                ("Xm".to_owned(), 7),
            ]
            .into(),
            strings: [
                ("bel".to_owned(), "\x07".to_owned()),
                ("Xs".to_owned(), "\x1b[x".to_owned()),
                ("Xt".to_owned(), "\x1b[y%p1%d".to_owned()),
            ]
            .into(),
        }
    }

    /// Capabilities the private database has and a stock one may lack: what the profile declares
    /// beyond it. `Tc` and `RGB` are its truecolour flags, `BE` and `BD` its bracketed paste
    /// toggles, and the rest are the extended colour forms and the strike-through and
    /// styled-underline sequences that stock entries gained over the releases.
    const ADDED: [&str; 7] = ["BD", "BE", "Smulx", "rmxx", "setrgbb", "setrgbf", "smxx"];

    /// Output capabilities whose value differs from a stock one, and the reason. The reset strings
    /// no longer touch DEC modes 3 and 4, which the profile does not track. The cursor-style
    /// reset, the alternate-screen pair and the full reset are what earlier stock releases had,
    /// before the title stack and the palette reset were added to them.
    const REWRITTEN: [&str; 6] = ["is2", "rs2", "Se", "smcup", "rmcup", "rs1"];

    /// Every output sequence `pinned` names that a stock database neither names too nor is listed
    /// as an addition or a rewrite.
    fn unexplained_differences(stock: &Read, pinned: &Description) -> Vec<String> {
        let mut found = Vec::new();
        for (name, value) in &pinned.strings {
            let output = terminfo::strings()
                .iter()
                .find(|capability| capability.name == name)
                .is_none_or(|capability| capability.direction == terminfo::Direction::Output);
            if !output {
                continue;
            }
            match stock.strings.get(name) {
                Some(stock_value) if stock_value == value.as_bytes() => {}
                Some(_) if REWRITTEN.contains(&name.as_str()) => {}
                Some(stock_value) => found.push(format!(
                    "{name} is {:?} in the stock database and {value:?} here",
                    String::from_utf8_lossy(stock_value)
                )),
                None if ADDED.contains(&name.as_str()) => {}
                None => found.push(format!(
                    "the stock database has no {name}, which the private one names as {value:?}"
                )),
            }
        }
        found
    }

    /// The private database names the sequences a stock `xterm-256color` names.
    ///
    /// An application in a KalaReach session writes what its terminfo entry says, and one that
    /// reaches a remote host over SSH writes what that host's stock entry says. The two agree,
    /// capability by capability, apart from what is listed above and why. A stock database on
    /// another release, or a change here, that adds a difference fails this and has to be
    /// answered in the list and in the terminal reference.
    #[test]
    fn the_private_database_names_the_sequences_a_stock_database_names() {
        for infocmp in infocmps() {
            let stock = read_stock(&infocmp);
            let differences = unexplained_differences(&stock, &Description::pinned());
            assert!(
                differences.is_empty(),
                "{} ({}) reading {}: {differences:#?}",
                infocmp.display(),
                version(&infocmp),
                stock.file
            );
        }
    }

    /// Control: a sequence only the private database names, and one it changed, are found.
    #[test]
    fn a_private_sequence_is_found_by_the_stock_comparison() {
        let mut edited = Description::pinned();
        edited
            .strings
            .insert("cup".to_owned(), "\x1b[%p1%d;%p2%dH".to_owned());
        edited
            .strings
            .insert("kr-private".to_owned(), "\x1b[?9999h".to_owned());
        let stock = read_stock(&infocmps().remove(0));
        let differences = unexplained_differences(&stock, &edited);
        assert_eq!(differences.len(), 2, "{differences:#?}");
        assert!(differences.iter().any(|line| line.starts_with("cup is")));
        assert!(
            differences
                .iter()
                .any(|line| line.contains("no kr-private"))
        );
    }

    /// Whether `tput` reads the private entry from `root`: `Tc` is a capability the private entry
    /// has and a stock `xterm-256color` lacks, so `colors` alone would succeed from the host's own
    /// database whether or not the private one was found.
    fn reads_the_private_entry(root: &Path) -> bool {
        tput(root, &["Tc"]).status.success()
    }

    /// Whichever leaf directory a reading library uses, it finds the entry: the system's `tput`
    /// reads it from a directory that holds only one of the two, when that is the one it looks in.
    #[test]
    fn the_hosts_library_finds_the_entry_in_the_leaf_it_looks_in() {
        let root = Scratch::new("leaf");
        let pinned = Description::pinned();
        pinned
            .install(root.path())
            .expect("the database is written");
        let mut found = 0;
        for source in pinned.entry_paths(root.path()) {
            // A directory with the entry under this lookup convention alone.
            let only = Scratch::new("only");
            let leaf = source
                .parent()
                .and_then(Path::file_name)
                .expect("a leaf directory");
            let target = only.path().join(leaf);
            std::fs::create_dir_all(&target).expect("a leaf");
            std::fs::copy(&source, target.join("xterm-256color")).expect("a copy");
            if reads_the_private_entry(only.path()) {
                eprintln!(
                    "this host's library reads the entry from the {} directory",
                    leaf.to_string_lossy()
                );
                found += 1;
            }
        }
        assert!(
            found >= 1,
            "the host's library looks in one of the two leaf directories"
        );
    }

    /// Control: an empty database directory is not read as the private entry, even though the
    /// host's own `xterm-256color` answers `colors` from wherever the library falls back to.
    #[test]
    fn an_empty_directory_does_not_read_as_the_private_entry() {
        let empty = Scratch::new("empty");
        assert!(!reads_the_private_entry(empty.path()));
        assert!(
            tput(empty.path(), &["colors"]).status.success(),
            "the host's own database still answers the ordinary capabilities"
        );
    }
}

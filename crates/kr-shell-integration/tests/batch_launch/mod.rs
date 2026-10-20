//! A launch of a batch program: which vectors the PowerShell module builds a line for, and what the
//! program is given.
//!
//! Windows runs a `.cmd` or `.bat` file through cmd.exe. PowerShell gives such a file the legacy
//! rules for its arguments, so the words of a launch go out as the text of one line that cmd.exe
//! reads again: an empty word is dropped, a double quote is not escaped, and `&`, `|`, `<`, `>`,
//! `^` and the rest are cmd.exe's own. The module builds the line a launch installs, so each case
//! asks it for one, through a helper script that loads the module's files, and runs what it built
//! as an accepted line is run. The editor is absent: the line and what the program makes of it are
//! what is under test.
//!
//! Every program writes what it received to the file `KR_CASE_OUT` names, one `n=[word]` line per
//! argument, so a launch that was refused leaves no file behind. On Windows the programs are batch
//! files; on a platform with no batch files the helper is told to treat the programs as if they
//! were, which runs the same decision about the words and carries the vectors it accepts to a
//! program that reads them as they were named.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// How long the helper is given to build and run every case of one launch.
const WITHIN: Duration = Duration::from_secs(180);

/// The program a launch is made to, found four ways.
pub struct Programs {
    /// By its full path.
    pub each: String,
    /// By its name alone, from the directory the helper puts first on the search path.
    pub by_name: &'static str,
    /// By a full path through a directory whose name holds a `%`.
    pub in_percent_directory: String,
    /// By a full path through a directory whose name holds a `!`.
    pub in_bang_directory: String,
    /// By a full path through a directory whose name holds white space and the characters
    /// cmd.exe reads as syntax only outside a quoted word.
    pub in_syntax_directory: String,
}

/// Vectors with a word that cmd.exe would read as more than that word, or not at all, and what
/// each word does. The `ver` and the file names are what a second command or a redirection would
/// run and make, and the file is what shows it.
pub const REFUSED: &[(&str, &[&str])] = &[
    ("an empty word and a double quote", &["", "a\"b", "c"]),
    ("an empty word alone", &[""]),
    ("a double quote", &["a\"b"]),
    ("a second command", &["a&ver>kr-injected.txt", "c"]),
    ("a pipe", &["a|b"]),
    ("an input redirection", &["a<b"]),
    ("an output redirection", &["a>kr-injected-out.txt"]),
    ("a caret", &["a^b"]),
    ("an opening parenthesis", &["a(b"]),
    ("a closing parenthesis", &["a)b"]),
    ("a percent sign", &["a%b"]),
    ("an exclamation mark", &["a!b"]),
    ("a line feed", &["a\nb"]),
    ("a carriage return", &["a\rb"]),
    ("a tab", &["a\tb"]),
    ("white space and a final backslash", &["a b\\"]),
];

/// Vectors of words that cmd.exe reads as themselves: white space, a path, a dash, the characters
/// PowerShell and the batch file's own parser leave alone, and a final backslash with no white
/// space in the word. Each arrives as one argument, as named.
pub const CARRIED: &[&[&str]] = &[
    &["plain"],
    &["two words", "C:\\Program Files\\x y", "tail"],
    &[
        "--flag", "-x", "/c", "/?", "a.b", "c:d", "e/f", "g+h", "i~j",
    ],
    &[
        "k'l", "m$n", "o{p}", "q[r]", "s#t", "u@v", "w*x", "y?z", "a`b",
    ],
    &["trailing\\", " padded "],
];

/// Words that are only separators between a batch file's `%1` to `%9`. They inject nothing, so a
/// launch carries them; a program that reads the whole argument text gets them whole.
pub const SEPARATORS: &[&str] = &["--model=x", "a,b", "c;d"];

/// What one launch did.
pub struct Launched {
    /// The module built no line, so nothing was run.
    pub refused: bool,
    /// The line the module built, or nothing when it built none.
    line: String,
    /// What the program wrote, or nothing when it wrote no file.
    wrote: Option<String>,
}

impl Launched {
    /// The arguments the program wrote, in order, with the unused ones at the end left off.
    pub fn received(&self) -> Vec<String> {
        let mut words: Vec<String> = self
            .wrote
            .as_deref()
            .unwrap_or_default()
            .lines()
            .map(|line| {
                let (_, rest) = line.split_once("=[").unwrap_or_default();
                rest.strip_suffix(']').unwrap_or(rest).to_owned()
            })
            .collect();
        while words.last().is_some_and(String::is_empty) {
            words.pop();
        }
        words
    }

    /// What this launch did, for a failure to say.
    pub fn describe(&self) -> String {
        if self.refused {
            "refused, nothing ran".to_owned()
        } else {
            format!("ran `{}` and the program wrote {:?}", self.line, self.wrote)
        }
    }

    /// Whether the program was started.
    pub fn started(&self) -> bool {
        self.wrote.is_some()
    }
}

/// Returns the helper script that builds a launch's line and runs it.
fn helper() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("batch_launch")
        .join("launch.ps1")
}

/// Returns the module files this checkout ships.
fn module_directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("shells")
        .join("psreadline")
        .join("module")
}

/// Launches each `(program, words)` through the module's own line, all in one PowerShell started
/// in `directory` (which also holds what the programs write), and returns what each did.
///
/// A program named without a path is looked for in `directory` first. PowerShell 7 is the root
/// shell this package is qualified against, so a host without it cannot run the shell under test;
/// the failure says so rather than passing quietly.
pub fn launch_all(
    directory: &Path,
    cases: &[(String, Vec<&str>)],
    as_batch: bool,
) -> Vec<Launched> {
    let list: Vec<serde_json::Value> = cases
        .iter()
        .map(|(program, words)| serde_json::json!({ "program": program, "words": words }))
        .collect();
    let cases_file = directory.join("cases.json");
    std::fs::write(&cases_file, serde_json::to_vec(&list).expect("cases")).expect("cases file");
    let errors = directory.join("helper-errors.txt");
    let mut command = Command::new(if cfg!(windows) { "pwsh.exe" } else { "pwsh" });
    command
        .arg("-NoLogo")
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-File")
        .arg(helper())
        .arg("-ModuleDirectory")
        .arg(module_directory())
        .arg("-Cases")
        .arg(&cases_file)
        .arg("-Directory")
        .arg(directory)
        .arg("-SearchDirectory")
        .arg(directory);
    if as_batch {
        command.arg("-AsBatch");
    }
    let mut child = command
        .current_dir(directory)
        .stdin(Stdio::null())
        .stdout(Stdio::from(
            std::fs::File::create(directory.join("helper-output.txt")).expect("an output file"),
        ))
        .stderr(Stdio::from(
            std::fs::File::create(&errors).expect("an error file"),
        ))
        .spawn()
        .unwrap_or_else(|error| panic!("PowerShell 7 did not start: {error}"));
    let deadline = Instant::now() + WITHIN;
    let status = loop {
        if let Some(status) = child.try_wait().expect("the helper's state") {
            break status;
        }
        if Instant::now() >= deadline {
            // Only this test's own child, started above.
            let _ = child.kill();
            let _ = child.wait();
            panic!("the helper did not finish within {WITHIN:?}");
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let report = std::fs::read_to_string(directory.join("report.txt")).unwrap_or_default();
    assert!(
        status.success() && report.ends_with("done\n"),
        "the helper ended {status}:\n{report}\n{}",
        std::fs::read_to_string(&errors).unwrap_or_default()
    );
    (1..=cases.len())
        .map(|number| Launched {
            refused: report.contains(&format!("case {number} refused\n")),
            line: report
                .lines()
                .find_map(|line| line.strip_prefix(&format!("case {number} line ")))
                .unwrap_or_default()
                .to_owned(),
            wrote: std::fs::read_to_string(directory.join(format!("case-{number}.txt"))).ok(),
        })
        .collect()
}

/// Launches every vector that [`REFUSED`] lists, two more at a program found by its name, and a
/// plain word at each program in a directory whose name holds a character cmd.exe expands, and
/// fails with what was started when any of them was. It is made once for each directory.
pub fn assert_nothing_is_started_that_cmd_exe_would_change(
    directory: &Path,
    programs: &Programs,
    as_batch: bool,
) {
    let mut labels: Vec<String> = Vec::new();
    let mut cases: Vec<(String, Vec<&str>)> = Vec::new();
    for (label, words) in REFUSED {
        labels.push((*label).to_owned());
        cases.push((programs.each.clone(), words.to_vec()));
    }
    labels.push("an empty word and a double quote, to a program found by its name".to_owned());
    cases.push((programs.by_name.to_owned(), vec!["", "a\"b"]));
    labels.push("a second command, to a program found by its name".to_owned());
    cases.push((
        programs.by_name.to_owned(),
        vec!["a&ver>kr-injected-name.txt"],
    ));
    labels.push("a percent sign in the program's path".to_owned());
    cases.push((programs.in_percent_directory.clone(), vec!["x"]));
    labels.push("an exclamation mark in the program's path".to_owned());
    cases.push((programs.in_bang_directory.clone(), vec!["x"]));

    let launched = launch_all(directory, &cases, as_batch);
    let wrong: Vec<String> = labels
        .iter()
        .zip(&launched)
        .filter(|(_, launch)| !launch.refused || launch.started())
        .map(|(label, launch)| format!("{label}: {}", launch.describe()))
        .collect();
    let injected: Vec<String> = std::fs::read_dir(directory)
        .expect("the directory")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("kr-injected"))
        .collect();
    assert!(
        wrong.is_empty() && injected.is_empty(),
        "a vector was started that cmd.exe would read as more than the words named:\n{}\nfiles a \
         second command or a redirection made: {injected:?}",
        wrong.join("\n")
    );
}

/// Launches every vector that [`CARRIED`] lists, one at a program found by its name and one at a
/// program in a directory whose name holds syntax, and fails with what happened when any was refused or reached the program as other than named.
pub fn assert_every_word_cmd_exe_reads_as_itself_arrives_as_named(
    directory: &Path,
    programs: &Programs,
    as_batch: bool,
) {
    let mut cases: Vec<(String, Vec<&str>)> = CARRIED
        .iter()
        .map(|words| (programs.each.clone(), words.to_vec()))
        .collect();
    cases.push((programs.by_name.to_owned(), vec!["found by its name", "b"]));
    cases.push((programs.in_syntax_directory.clone(), vec!["two words", "b"]));
    let launched = launch_all(directory, &cases, as_batch);
    let wrong: Vec<String> = cases
        .iter()
        .zip(&launched)
        .filter_map(|((_, words), launch)| {
            let expected: Vec<String> = words.iter().map(|word| (*word).to_owned()).collect();
            (launch.refused || launch.received() != expected).then(|| {
                format!(
                    "{expected:?}: {} and the program received {:?}",
                    launch.describe(),
                    launch.received()
                )
            })
        })
        .collect();
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

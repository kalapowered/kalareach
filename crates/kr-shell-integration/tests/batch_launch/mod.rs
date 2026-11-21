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

/// The program a launch is made to, and the places it is found in.
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
    ("a control character above the ASCII range", &["a\u{85}b"]),
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

/// Vectors with a separator at the edge of a word: the start of the first word, a word that is only
/// a separator, the start of a later word, the end of a word, and the end of the line.
pub const EDGE_SEPARATORS: &[&[&str]] = &[
    &[",a", "b"],
    &["=", "b"],
    &[";x"],
    &["a", ",b", "=c"],
    &["--flag=", "b,"],
    &["a;"],
];

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
    launch_all_after(directory, "", cases, as_batch)
}

/// As [`launch_all`], with `setup` run first in the helper's own scope: an alias or a function a
/// case needs, or a changed home directory.
pub fn launch_all_after(
    directory: &Path,
    setup: &str,
    cases: &[(String, Vec<&str>)],
    as_batch: bool,
) -> Vec<Launched> {
    let list: Vec<serde_json::Value> = cases
        .iter()
        .map(|(program, words)| serde_json::json!({ "program": program, "words": words }))
        .collect();
    // What an earlier launch in this directory left would be read as this one's.
    let _ = std::fs::remove_file(directory.join("report.txt"));
    for number in 1..=cases.len() {
        let _ = std::fs::remove_file(directory.join(format!("case-{number}.txt")));
    }
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
    if !setup.is_empty() {
        let setup_file = directory.join("setup.ps1");
        std::fs::write(&setup_file, setup).expect("setup file");
        command.arg("-Setup").arg(&setup_file);
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

/// Launches every vector that [`REFUSED`] lists, two more at a program found by its name, two at a
/// program written with a trailing dot or a trailing space, and a plain word at each program in a
/// directory whose name holds a character cmd.exe expands, and fails with what was started when any
/// of them was. It is made once for each directory.
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
    labels.push("a second command, to a program named with a trailing dot".to_owned());
    cases.push((
        format!("{}.", programs.each),
        vec!["a&ver>kr-injected-dot.txt"],
    ));
    labels.push("a second command, to a program named with a trailing space".to_owned());
    cases.push((
        format!("{} ", programs.each),
        vec!["a&ver>kr-injected-space.txt"],
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

/// The program word of a line the module built: what follows the call operator, in quotes.
fn program_word(launch: &Launched) -> Option<&str> {
    launch
        .line
        .strip_prefix("& '")?
        .split_once('\'')
        .map(|(word, _)| word)
}

/// KR-REQ-13.11: a function or an alias of the program's name, which the shell would find before
/// the program, does not stand in its place: the line holds the program's full path, and the
/// program runs. Where nothing is in front of the program the line holds the name as it was given.
pub fn assert_a_shadowing_function_or_alias_is_bypassed_and_the_full_path_is_typed(
    directory: &Path,
    programs: &Programs,
    as_batch: bool,
) {
    let name = programs.by_name;
    let case = || vec![(name.to_owned(), vec!["x"])];
    let plain = &launch_all(directory, &case(), as_batch)[0];
    assert!(
        !plain.refused && plain.received() == vec!["x"],
        "{}",
        plain.describe()
    );
    assert_eq!(
        program_word(plain),
        Some(name),
        "nothing stood in front of the program, so the name is typed as it was given: {}",
        plain.describe()
    );
    let write_out =
        |text: &str| format!("[System.IO.File]::WriteAllText($env:KR_CASE_OUT, \"1=[{text}]`n\")");
    for (what, setup) in [
        (
            "a function",
            format!("function {name} {{ {} }}\n", write_out("function-ran")),
        ),
        (
            "an alias",
            format!(
                "function kr-alias-target {{ {} }}\nSet-Alias -Name {name} -Value kr-alias-target\n",
                write_out("alias-ran")
            ),
        ),
    ] {
        let launch = &launch_all_after(directory, &setup, &case(), as_batch)[0];
        assert!(
            !launch.refused && launch.received() == vec!["x"],
            "{what} of the program's name stood in front of it, and the program did not run: {}",
            launch.describe()
        );
        let word = program_word(launch).unwrap_or_default();
        assert!(
            Path::new(word).is_absolute()
                && Path::new(word).file_stem().is_some_and(|stem| stem == name),
            "{what} of the program's name stood in front of it, and the line does not hold the \
             program's full path: {}",
            launch.describe()
        );
    }
}

/// KR-REQ-13.11: a batch program runs with plain arguments, and is refused an empty argument, an
/// argument with white space and a final backslash, an argument that holds one of the characters
/// `"`, `%`, `!`, `^`, `&`, `|`, `<`, `>`, `(` and `)`, and a program whose path holds `%` or `!`.
pub fn assert_a_batch_program_runs_with_plain_arguments_and_is_refused_what_cmd_exe_would_change(
    directory: &Path,
    programs: &Programs,
    as_batch: bool,
) {
    let mut cases: Vec<(String, Vec<&str>)> =
        vec![(programs.each.clone(), vec!["plain", "two words"])];
    for word in [
        "", "a b\\", "a\"b", "a%b", "a!b", "a^b", "a&b", "a|b", "a<b", "a>b", "a(b", "a)b",
    ] {
        cases.push((programs.each.clone(), vec![word]));
    }
    cases.push((programs.in_percent_directory.clone(), vec!["plain"]));
    cases.push((programs.in_bang_directory.clone(), vec!["plain"]));
    let launched = launch_all(directory, &cases, as_batch);
    assert!(
        !launched[0].refused && launched[0].received() == vec!["plain", "two words"],
        "{}",
        launched[0].describe()
    );
    for ((program, words), launch) in cases.iter().zip(&launched).skip(1) {
        assert!(
            launch.refused && !launch.started(),
            "{program} was given {words:?} and was started: {}",
            launch.describe()
        );
    }
}

/// KR-REQ-13.11: a program written as a path is typed as it was written; a program word with a
/// leading `~` is found under the provider's home directory, in both spellings of the separator,
/// as PowerShell does; and an argument that begins with `~` reaches the program as written.
///
/// The home directory the shell is given is `directory`, which holds the program, so a program
/// word of `~/<its name>` runs only because PowerShell expands the `~` in a program word even when
/// it is quoted. An argument is a quoted word of the line and is not expanded. bash, zsh and fish
/// are given the program word quoted and do not expand it: the words about a leading `~` have a
/// PowerShell form. Both results are printed (`kr-tilde-result`, read with `--nocapture`).
pub fn assert_a_tilde_program_word_is_found_under_the_home_and_a_tilde_argument_is_not_expanded(
    directory: &Path,
    programs: &Programs,
    as_batch: bool,
) {
    let name = Path::new(&programs.each)
        .file_name()
        .and_then(|name| name.to_str())
        .expect("the program's file name")
        .to_owned();
    let setup = format!(
        "(Get-PSProvider FileSystem).Home = '{}'\n",
        directory.display()
    );
    let forms = [format!("~/{name}"), format!("~\\{name}")];
    let mut cases: Vec<(String, Vec<&str>)> =
        vec![(programs.in_syntax_directory.clone(), vec!["a b"])];
    for form in &forms {
        cases.push((form.clone(), vec!["x"]));
    }
    cases.push((programs.each.clone(), vec!["~/y", "~", "a~"]));
    let launched = launch_all_after(directory, &setup, &cases, as_batch);
    assert!(
        !launched[0].refused && launched[0].received() == vec!["a b"],
        "a path to a program does not run: {}",
        launched[0].describe()
    );
    assert_eq!(
        program_word(&launched[0]),
        Some(programs.in_syntax_directory.as_str()),
        "the path is typed as it was written: {}",
        launched[0].describe()
    );
    let details: Vec<String> = forms
        .iter()
        .zip(&launched[1..])
        .map(|(form, launch)| format!("{form}: {}", launch.describe()))
        .collect();
    println!(
        "kr-tilde-result: the program word {}\nkr-tilde-result: the arguments {}",
        details.join("\n"),
        launched[3].describe()
    );
    for ((form, launch), detail) in forms.iter().zip(&launched[1..]).zip(&details) {
        assert!(
            !launch.refused && launch.received() == vec!["x"],
            "the program word {form} is not found under the provider's home: {detail}"
        );
        assert_eq!(
            program_word(launch),
            Some(form.as_str()),
            "the program word is typed as it was written: {detail}"
        );
    }
    assert!(
        !launched[3].refused && launched[3].received() == vec!["~/y", "~", "a~"],
        "an argument that begins with ~ does not reach the program as written: {}",
        launched[3].describe()
    );
}

/// KR-REQ-13.11: a program that names no application or script has no line in PowerShell, whether
/// no such name exists, a function of the name is all there is, or the path does not exist; and the
/// refusal the reader gives for a command it has no line for is a draft conflict.
pub fn assert_a_program_that_names_no_application_has_no_line_and_the_refusal_is_a_draft_conflict(
    directory: &Path,
    as_batch: bool,
) {
    let setup = "function kr-only-function { }\n";
    let cases: Vec<(String, Vec<&str>)> = vec![
        ("kr-no-such-program".to_owned(), vec!["x"]),
        ("kr-only-function".to_owned(), vec!["x"]),
        ("C:\\tools\\kr-no-such-agent.exe".to_owned(), vec!["x"]),
    ];
    let launched = launch_all_after(directory, setup, &cases, as_batch);
    for ((program, _), launch) in cases.iter().zip(&launched) {
        assert!(
            launch.refused && !launch.started(),
            "{program} names no application, and it was given a line: {}",
            launch.describe()
        );
    }
    assert_eq!(
        kr_shell_integration::contract::requests::LaunchRejectionReason::BufferNotEmpty.code(),
        kr_protocol::error::ErrorCode::DraftConflict,
        "the reason the reader gives for a command it has no line for"
    );
}

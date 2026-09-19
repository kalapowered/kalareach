//! The marked, guarded entry each shell's startup configuration gets.
//!
//! Section 7 is exact about what setup may and may not do. It locates the *actual* startup files,
//! including a configured `ZDOTDIR`, rather than assuming the home directory. It adds one marked
//! entry per shell and never replaces `.bashrc`, never points the shell at an alternate `ZDOTDIR`,
//! never substitutes a `--rcfile` and never disables an existing profile. Removal deletes the
//! marked entry and nothing else.
//!
//! The entry itself is inert in an ordinary shell. It runs in every interactive shell of that user,
//! including one a session's own commands start, and the first thing it does is
//! [`decide_activation`](crate::contract::transport::decide_activation): without both bootstrap
//! values in the exported environment there is nothing to attempt, and after the root handshake
//! there are none to inherit.

use std::path::{Path, PathBuf};

use crate::contract::qualification::ShellKind;

/// The line that opens a KalaReach entry.
pub const MARKER_BEGIN: &str = "# >>> KalaReach shell integration >>>";

/// The line that closes it.
pub const MARKER_END: &str = "# <<< KalaReach shell integration <<<";

/// The PowerShell form of the opening marker.
pub const MARKER_BEGIN_POWERSHELL: &str = "# >>> KalaReach shell integration >>>";

/// The variable a known auto-wrapper reads to stay out of a shell's way.
pub const NSH_BYPASS_VARIABLE: &str = "NSH_NO_WRAP";

/// Where one shell's guarded entry goes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StartupTarget {
    /// The shell this file belongs to.
    pub kind: ShellKind,
    /// The file the entry is added to.
    pub path: PathBuf,
    /// Why this file rather than another, for the diagnostics setup prints.
    pub reason: &'static str,
}

/// What a home directory looks like to setup.
///
/// Passed in rather than read from the process, because setup runs for the user it is configuring
/// and a test has to be able to describe a home directory that is not this process's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HomeLayout {
    /// The user's home directory.
    pub home: PathBuf,
    /// The value of `ZDOTDIR`, when the user has one.
    pub zdotdir: Option<PathBuf>,
    /// The value of `XDG_CONFIG_HOME`, when the user has one.
    pub xdg_config_home: Option<PathBuf>,
    /// The PowerShell this host would launch, when one is installed.
    ///
    /// Asked where its own profile is, rather than having a path derived for it: PowerShell keeps
    /// that file where the platform puts the user's documents, and on Windows a redirection can
    /// move it anywhere. Two editions answer differently, so this has to be the executable a
    /// session would actually start: [`Self::launching`] is how a caller that has resolved a
    /// package says which.
    pub powershell: Option<PathBuf>,
}

impl HomeLayout {
    /// Reads the layout from this process's own environment.
    #[must_use]
    pub fn from_environment() -> Self {
        Self {
            home: std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_default(),
            zdotdir: std::env::var_os("ZDOTDIR").map(PathBuf::from),
            xdg_config_home: std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from),
            powershell: powershell_on_path(),
        }
    }

    /// Returns this layout with the PowerShell a session would launch.
    ///
    /// A qualified package's own executable rather than whichever PowerShell is on the path: the
    /// two can be different editions, and on Windows they keep their profiles in different
    /// directories, so an entry written for one is never read by the other.
    #[must_use]
    pub fn launching(mut self, powershell: PathBuf) -> Self {
        self.powershell = Some(powershell);
        self
    }

    /// Returns where this shell's guarded entry goes.
    ///
    /// Zsh uses `.zshrc` inside the configured `ZDOTDIR` when there is one, because that is the
    /// file the shell actually reads. Bash uses `.bashrc`, plus a marked entry in the first login
    /// file it reads when that file does not already source `.bashrc`. Fish uses a guarded
    /// `conf.d` entry, which runs after the user's own configuration. PowerShell uses the user's
    /// profile.
    #[must_use]
    pub fn targets(&self, kind: ShellKind) -> Vec<StartupTarget> {
        match kind {
            ShellKind::Zsh => vec![StartupTarget {
                kind,
                path: self
                    .zdotdir
                    .clone()
                    .unwrap_or_else(|| self.home.clone())
                    .join(".zshrc"),
                reason: "the interactive file this shell actually reads, inside ZDOTDIR when one is set",
            }],
            ShellKind::Bash => {
                let mut targets = vec![StartupTarget {
                    kind,
                    path: self.home.join(".bashrc"),
                    reason: "the file a non-login interactive Bash reads",
                }];
                if let Some(login) = self.bash_login_file() {
                    targets.push(StartupTarget {
                        kind,
                        path: login,
                        reason: "the first login file this user has, which does not source .bashrc",
                    });
                }
                targets
            }
            ShellKind::Fish => vec![StartupTarget {
                kind,
                path: self
                    .xdg_config_home
                    .clone()
                    .unwrap_or_else(|| self.home.join(".config"))
                    .join("fish/conf.d/kalareach.fish"),
                reason: "a guarded conf.d entry; it loads before config.fish and defers its own activation until after it",
            }],
            // PowerShell is the one shell whose profile path this host does not derive: where it
            // keeps a per-user profile depends on where the platform puts that user's documents,
            // and on Windows that is a known folder a redirection can move. So the shell is asked,
            // and a shell that cannot be asked gets no target rather than an entry written where
            // it will never be read.
            ShellKind::PowerShell => self
                .powershell_profile()
                .map(|path| StartupTarget {
                    kind,
                    path,
                    reason: "the profile this shell itself names, which this entry adds to rather \
                             than replaces",
                })
                .into_iter()
                .collect(),
        }
    }

    /// Returns the profile PowerShell reads on this host.
    ///
    /// It is asked for rather than worked out. PowerShell keeps its per-user profile in a
    /// different place on each platform, in a different place for each edition, and on Windows
    /// under whatever directory the user's documents have been redirected to; a path this host
    /// derived could be a file PowerShell never reads, and an entry in a file nothing reads is an
    /// installation that reports success and integrates nothing.
    fn powershell_profile(&self) -> Option<PathBuf> {
        let shell = self.powershell.as_ref()?;
        // The shell's own answer, read from a shell started with no profile of its own so that
        // nothing a user wrote decides where their profile is. `CurrentUserCurrentHost` is the one
        // `kr shell install` adds to: the per-user file this host's PowerShell reads.
        //
        // Bounded, and written to a file rather than a pipe: `kr shell status` runs this, and a
        // shell that will not start must not hold that command open.
        let said = ask(
            shell,
            &[
                "-NoProfile",
                "-NonInteractive",
                "-NoLogo",
                "-Command",
                "$PROFILE.CurrentUserCurrentHost",
            ],
        )?;
        let said = said.trim();
        (!said.is_empty()).then(|| PathBuf::from(said))
    }

    /// Returns the first login file this user has, when it does not already source `.bashrc`.
    ///
    /// Bash reads exactly one of these for a login shell, in this order, and a file that already
    /// sources `.bashrc` needs no entry of its own: the entry in `.bashrc` will run.
    ///
    /// What counts as sourcing it is a `source` or `.` of a path whose last component is
    /// `.bashrc`, on a line that is not a comment. A file that merely mentions the name, in a
    /// comment, in a message or in a variable that is never read, is not a file that runs it, and
    /// treating it as one would leave a login shell with no entry at all.
    fn bash_login_file(&self) -> Option<PathBuf> {
        for name in [".bash_profile", ".bash_login", ".profile"] {
            let path = self.home.join(name);
            let Ok(contents) = std::fs::read_to_string(&path) else {
                continue;
            };
            if runs_bashrc(&contents) {
                return None;
            }
            return Some(path);
        }
        None
    }
}

/// How long a shell is given to answer a question about itself.
const ASK_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

/// Asks one program a question and returns what it printed, or nothing.
///
/// The answer goes to a file rather than a pipe, so nothing has to read while the program runs and
/// a descendant that inherited the handle holds nothing of this host's open. The wait is bounded,
/// and a program that outlasts it is terminated and reaped: a shell that will not start must not
/// hold `kr shell` open.
fn ask(program: &Path, arguments: &[&str]) -> Option<String> {
    // A directory of this call's own, created rather than opened and owner-only where the platform
    // has modes. `/tmp` is shared: a name another account can guess is a name it can pre-create,
    // and a file opened through it is a file this host writes on somebody else's behalf.
    let directory = std::env::temp_dir().join(format!("kr-shell-ask-{}", kr_ipc::new_uuid()));
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;

        builder.mode(0o700);
    }
    builder.create(&directory).ok()?;
    let said = directory.join("said");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options.mode(0o600);
    }
    let Ok(to) = options.open(&said) else {
        let _ = std::fs::remove_dir_all(&directory);
        return None;
    };
    let started = std::process::Command::new(program)
        .args(arguments)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(to))
        .stderr(std::process::Stdio::null())
        .spawn();
    let mut child = match started {
        Ok(child) => child,
        Err(_) => {
            let _ = std::fs::remove_dir_all(&directory);
            return None;
        }
    };
    let deadline = std::time::Instant::now() + ASK_DEADLINE;
    let mut ended = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                ended = true;
                break Some(status);
            }
            Ok(None) => {}
            Err(_) => break None,
        }
        if std::time::Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    };
    if !ended {
        let _ = child.kill();
        let _ = child.wait();
    }
    // A program that did not finish answered nothing, so nothing is read: a descendant can still
    // be writing, and half an answer is worse than none. A successful one is read up to a bound.
    let answer = status
        .filter(std::process::ExitStatus::success)
        .and_then(|_| read_answer(&said));
    let _ = std::fs::remove_dir_all(&directory);
    answer
}

/// The most one answer this host reads from a shell it asked a question of.
const ANSWER_LIMIT: u64 = 64 * 1024;

/// Reads what a shell answered, up to [`ANSWER_LIMIT`].
fn read_answer(path: &Path) -> Option<String> {
    use std::io::Read as _;

    let mut read = String::new();
    std::fs::File::open(path)
        .ok()?
        .take(ANSWER_LIMIT)
        .read_to_string(&mut read)
        .ok()?;
    Some(read)
}

/// Returns the PowerShell this host would launch, when one is on the path.
///
/// The name differs by platform: `pwsh` is PowerShell 6 and later everywhere, and Windows also
/// ships `powershell.exe`, the edition that came with it.
fn powershell_on_path() -> Option<PathBuf> {
    let names: &[&str] = if cfg!(windows) {
        &["pwsh.exe", "powershell.exe"]
    } else {
        &["pwsh"]
    };
    let path = std::env::var_os("PATH")?;
    names.iter().find_map(|name| {
        std::env::split_paths(&path)
            .map(|directory| directory.join(name))
            .find(|candidate| candidate.is_file())
    })
}

/// Returns whether a login file runs `.bashrc`.
///
/// Reading shell text without a shell is a judgement, so the rule is which way to be wrong. A file
/// this host wrongly thinks sources `.bashrc` gets no entry of its own, and a login shell then has
/// no integration at all; a file it wrongly thinks does not gets one more marked entry, which is
/// guarded, idempotent and removed by `kr shell remove`. The second is the harmless direction, so
/// anything this cannot establish reads as "it does not".
///
/// The file is read as commands rather than as lines: a quoted newline and a backslash before one
/// both carry a command on, and a here-document's body is text the shell passes on rather than
/// commands it runs, so `cat <<EOF` … `source ~/.bashrc` … `EOF` is skipped. Everything a command
/// could still hide the call behind, a substitution or an expansion this does not evaluate, reads
/// as "it does not" and costs one guarded entry.
///
/// A call the shell reaches is a call in this shell: `. ~/.bashrc`, and the same behind a `;`, a
/// `&&` or a `then`. What a login file writes the call behind is whether `.bashrc` is there,
/// which an installation has already made true, so that one condition is read through. Any other
/// condition is one this host cannot answer, and so are a `||`, a loop body that can run no times,
/// a function body nothing here calls, a pipeline, a background `&` and a subshell: each of them
/// either may not be reached or reaches a shell this host is not integrating, and each reads as
/// "it does not".
fn runs_bashrc(contents: &str) -> bool {
    let mut rest = contents;
    while !rest.is_empty() {
        let command = read_command(rest);
        rest = command.rest;
        // The bodies follow the whole command, however many lines it took to write.
        for document in &command.documents {
            rest = skip_body(rest, document);
        }
        if sources(&command.words) {
            return true;
        }
    }
    false
}

/// One word of a command, and what the scanner knows about it.
struct Word {
    text: String,
    /// Whether any of it was quoted, which makes it an argument rather than a verb.
    quoted: bool,
    /// Whether any of it was taken literally, by single quotes or a backslash.
    ///
    /// A path this host reads has to be the path the shell reads. `'$HOME/.bashrc'` names a
    /// directory called `$HOME`, not the person's home, and nothing here expands anything, so a
    /// word the shell takes literally is not read as a path at all.
    literal: bool,
    /// Whether it stands where a command name stands.
    command_position: bool,
    /// Whether a condition this host does not evaluate stands between the file and this command.
    ///
    /// `if` and `&&` both lead to a command that runs only when something else said so. The one
    /// condition a login file is written with is whether `.bashrc` is there, and after an
    /// installation it is; any other condition is one this host cannot answer, and a call it
    /// cannot see made is a call it reads as not made.
    conditional: bool,
    /// Whether this host can see the command it belongs to being run by the shell it integrates.
    ///
    /// `&&`, `;` and a new line all lead to one. `||` leads to one only when what came before it
    /// failed, a pipe and a background `&` lead to a shell of their own, and what is inside `( )`,
    /// `$( )`, backticks or a group is either another shell or not a command at all.
    plainly_run: bool,
}

/// One here-document a command opened, and how its body ends.
struct HereDocument {
    marker: String,
    /// `<<-` strips leading tabs from the delimiter line, and nothing else does.
    strip_tabs: bool,
    /// Whether the delimiter was written without quoting, which is what leaves the body expanded
    /// and a backslash at the end of a body line carrying on to the next.
    expands: bool,
}

/// One command, the here-documents it opened and what follows it.
struct Command<'a> {
    words: Vec<Word>,
    documents: Vec<HereDocument>,
    rest: &'a str,
}

/// Reads one command from the front of a login file.
fn read_command(text: &str) -> Command<'_> {
    let characters: Vec<(usize, char)> = text.char_indices().collect();
    let mut reading = Reading {
        words: Vec::new(),
        word: String::new(),
        quoted: false,
        literal: false,
        started: false,
    };
    let mut documents = Vec::new();
    // A command begins at the front and after every separator; everything else is an argument.
    let mut command_position = true;
    let mut next_command_position = true;
    let mut plainly_run = true;
    let mut conditional = false;
    // Where the command being read began, because what follows it can change what this host can
    // see of it: `. ~/.bashrc &` is read before the `&` that backgrounds it.
    let mut began = 0usize;
    let mut index = 0;
    while index < characters.len() {
        let character = characters[index].1;
        match character {
            // A backslash quotes whatever follows it. Before a newline it joins the two lines with
            // nothing in between, which is how `source\` and `~/.bashrc` make one word.
            '\\' => match characters.get(index + 1) {
                Some((_, '\n')) => index += 2,
                Some((_, following)) => {
                    reading.word.push(*following);
                    reading.quoted = true;
                    reading.literal = true;
                    reading.started = true;
                    next_command_position = false;
                    index += 2;
                }
                None => index += 1,
            },
            '\'' | '"' => {
                let quote = character;
                // `$'…'` takes backslash escapes, so the apostrophe in `$'it\'s'` does not end it.
                let escapes = quote == '"' || reading.word.ends_with('$');
                reading.quoted = true;
                reading.literal |= quote == '\'';
                reading.started = true;
                // A word has begun, so the next one is an argument: `"echo" source ~/.bashrc`
                // passes `source` to `echo`.
                next_command_position = false;
                index += 1;
                while let Some((_, inside)) = characters.get(index) {
                    if *inside == quote {
                        index += 1;
                        break;
                    }
                    if *inside == '\\' && escapes {
                        match characters.get(index + 1) {
                            Some((_, '\n')) => index += 2,
                            Some((_, following)) => {
                                reading.word.push(*following);
                                reading.literal = true;
                                index += 2;
                            }
                            None => index += 1,
                        }
                        continue;
                    }
                    reading.word.push(*inside);
                    index += 1;
                }
            }
            // A comment begins at a `#` that begins a word and runs to the end of its line.
            '#' if !reading.started => {
                while matches!(characters.get(index), Some((_, character)) if *character != '\n') {
                    index += 1;
                }
            }
            '\n' => {
                index += 1;
                break;
            }
            // A subshell, a substitution, arithmetic or array data. Whatever is inside is either
            // not a command or a command another shell runs, and either way it is not a call this
            // host can see the shell it integrates make, so all of it is taken as this word's.
            '(' => {
                index = skip_nested(&characters, index);
                reading.started = true;
                next_command_position = false;
            }
            '`' => {
                index = skip_backticks(&characters, index);
                reading.started = true;
                next_command_position = false;
            }
            ';' | '&' | '|' => {
                finish(&mut reading, command_position, plainly_run, conditional);
                let pair = characters.get(index + 1).map(|(_, character)| *character);
                // A single `&` backgrounds the command in front of it and a pipe puts it in a
                // shell of its own, so what this host can see of that command changes here,
                // after it has been read.
                let elsewhere = match (character, pair) {
                    ('&', Some('&')) => false,
                    ('&' | '|', _) => true,
                    _ => false,
                };
                if elsewhere {
                    for word in &mut reading.words[began..] {
                        word.plainly_run = false;
                    }
                }
                // `&&` and `;` lead to a command this shell runs next. `||` leads to one only
                // when what came before it failed, `|` and `|&` to one in a shell of their own,
                // `&` to one in the background, and `;;` out of a `case` arm.
                plainly_run = matches!((character, pair), (';', _) | ('&', Some('&')))
                    && !matches!((character, pair), (';', Some(';')));
                // `&&` and `||` both put a condition in front of what comes next.
                conditional |= matches!((character, pair), ('&' | '|', Some('&' | '|')));
                if matches!(
                    (character, pair),
                    (';', Some(';')) | ('&', Some('&')) | ('|', Some('|' | '&'))
                ) {
                    index += 1;
                }
                began = reading.words.len();
                command_position = true;
                next_command_position = true;
                index += 1;
            }
            // A here-document. Its delimiter follows the redirection and its body follows the
            // whole command, so only the delimiter is read here.
            '<' if matches!(characters.get(index + 1), Some((_, '<'))) => {
                finish(&mut reading, command_position, plainly_run, conditional);
                index += 2;
                // `<<<` is a here-string: its word is the input, and no body follows.
                if matches!(characters.get(index), Some((_, '<'))) {
                    index += 1;
                    continue;
                }
                let strip_tabs = matches!(characters.get(index), Some((_, '-')));
                if strip_tabs {
                    index += 1;
                }
                while matches!(characters.get(index), Some((_, ' ' | '\t'))) {
                    index += 1;
                }
                let (marker, expands, after) = marker_word(&characters, index);
                index = after;
                documents.push(HereDocument {
                    marker,
                    strip_tabs,
                    expands,
                });
            }
            character if character.is_whitespace() => {
                finish(&mut reading, command_position, plainly_run, conditional);
                command_position = next_command_position;
                index += 1;
            }
            character => {
                reading.word.push(character);
                reading.started = true;
                // A word this host reads as opening a condition puts everything after it behind
                // one, whether or not the shell takes that branch.
                if command_position
                    && !reading.quoted
                    && matches!(reading.word.as_str(), "if" | "elif")
                {
                    conditional = true;
                }
                next_command_position = false;
                index += 1;
            }
        }
    }
    finish(&mut reading, command_position, plainly_run, conditional);
    Command {
        words: reading.words,
        documents,
        rest: characters.get(index).map_or("", |(at, _)| &text[*at..]),
    }
}

/// Returns where the text a `(` opens ends, counting the ones inside it.
fn skip_nested(characters: &[(usize, char)], from: usize) -> usize {
    let mut index = from + 1;
    let mut depth = 1usize;
    while let Some((_, character)) = characters.get(index) {
        match character {
            '\\' => index += 2,
            '\'' | '"' => {
                let quote = *character;
                index += 1;
                while let Some((_, inside)) = characters.get(index) {
                    if *inside == quote {
                        index += 1;
                        break;
                    }
                    index += if *inside == '\\' && quote == '"' {
                        2
                    } else {
                        1
                    };
                }
            }
            '(' => {
                depth += 1;
                index += 1;
            }
            ')' => {
                depth -= 1;
                index += 1;
                if depth == 0 {
                    return index;
                }
            }
            _ => index += 1,
        }
    }
    index
}

/// Returns where the text a backtick opens ends.
fn skip_backticks(characters: &[(usize, char)], from: usize) -> usize {
    let mut index = from + 1;
    while let Some((_, character)) = characters.get(index) {
        match character {
            '\\' => index += 2,
            '`' => return index + 1,
            _ => index += 1,
        }
    }
    index
}

/// Ends the word being read, where one has begun.
fn finish(reading: &mut Reading, command_position: bool, plainly_run: bool, conditional: bool) {
    if !reading.started {
        return;
    }
    reading.words.push(Word {
        text: std::mem::take(&mut reading.word),
        quoted: std::mem::take(&mut reading.quoted),
        literal: std::mem::take(&mut reading.literal),
        conditional,
        command_position,
        plainly_run,
    });
    reading.started = false;
}

/// The word being read and the words read so far.
struct Reading {
    words: Vec<Word>,
    word: String,
    quoted: bool,
    literal: bool,
    started: bool,
}

/// Reads one here-document's delimiter, which may be quoted, may hold spaces and may be empty.
///
/// Returns the delimiter, whether it was written without any quoting, and where it ends.
fn marker_word(characters: &[(usize, char)], from: usize) -> (String, bool, usize) {
    let mut marker = String::new();
    let mut expands = true;
    let mut index = from;
    while let Some((_, character)) = characters.get(index) {
        match character {
            '\\' => {
                expands = false;
                match characters.get(index + 1) {
                    Some((_, following)) => {
                        marker.push(*following);
                        index += 2;
                    }
                    None => index += 1,
                }
            }
            '\'' | '"' => {
                let quote = *character;
                expands = false;
                index += 1;
                while let Some((_, inside)) = characters.get(index) {
                    if *inside == quote {
                        index += 1;
                        break;
                    }
                    // Inside double quotes a backslash goes before the four characters it can
                    // quote and stays anywhere else, so `<<"\$EOF"` ends at `$EOF`.
                    if *inside == '\\' && quote == '"' {
                        match characters.get(index + 1) {
                            Some((_, following @ ('$' | '`' | '"' | '\\'))) => {
                                marker.push(*following);
                                index += 2;
                            }
                            Some((_, following)) => {
                                marker.push('\\');
                                marker.push(*following);
                                index += 2;
                            }
                            None => index += 1,
                        }
                        continue;
                    }
                    marker.push(*inside);
                    index += 1;
                }
            }
            ';' | '&' | '|' | '<' | '>' | '(' | ')' => break,
            character if character.is_whitespace() => break,
            character => {
                marker.push(*character);
                index += 1;
            }
        }
    }
    (marker, expands, index)
}

/// Returns what follows one here-document's body.
fn skip_body<'a>(text: &'a str, document: &HereDocument) -> &'a str {
    let mut rest = text;
    while !rest.is_empty() {
        let (line, after) = match rest.find('\n') {
            Some(at) => (rest[..at].to_owned(), &rest[at + 1..]),
            None => (rest.to_owned(), ""),
        };
        let mut line = line;
        let mut after = after;
        // An unquoted delimiter leaves the body expanded, and there a backslash before the newline
        // joins the two lines before the delimiter is looked for at all.
        while document.expands && continues(&line) {
            line.pop();
            match after.find('\n') {
                Some(at) => {
                    line.push_str(&after[..at]);
                    after = &after[at + 1..];
                }
                None => {
                    line.push_str(after);
                    after = "";
                    break;
                }
            }
        }
        let ends = if document.strip_tabs {
            line.trim_start_matches('\t') == document.marker
        } else {
            line == document.marker
        };
        rest = after;
        if ends {
            return rest;
        }
    }
    ""
}

/// Returns whether a line carries on to the next one.
fn continues(line: &str) -> bool {
    // An odd number of trailing backslashes is a continuation; an even number is that many
    // backslashes, each quoting the one before it.
    line.chars().rev().take_while(|byte| *byte == '\\').count() % 2 == 1
}

/// Returns whether a word assigns a variable in front of a command, such as `LANG=C`.
fn assigns(word: &str) -> bool {
    let Some((name, _)) = word.split_once('=') else {
        return false;
    };
    // `NAME+=value` appends, and is an assignment like any other.
    let name = name.strip_suffix('+').unwrap_or(name);
    let mut characters = name.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && characters.all(|character| character.is_ascii_alphanumeric() || character == '_')
}

/// Returns whether one command runs `.bashrc`.
///
/// The shape is a `source` or `.` command whose next word is a path ending in `.bashrc`, wherever
/// in the command it stands: a login file writes it inside a test, after a `then`, behind a `&&`.
/// A word that merely contains the name, in a message or in a variable nothing reads, is not a
/// command that runs it, and treating it as one would leave a login shell with no entry.
fn sources(words: &[Word]) -> bool {
    // A word that stands where a command stands and introduces one leaves the next word standing
    // there too: `if [ -f ~/.bashrc ]; then . ~/.bashrc; fi` sources it.
    let mut at_command = true;
    let mut verbs: Vec<usize> = Vec::new();
    for (index, word) in words.iter().enumerate() {
        let here = at_command || word.command_position;
        // A keyword is only a keyword where a command stands and only unquoted: `echo if source
        // ~/.bashrc` passes `if` to `echo`, and `"if"` is the word rather than the keyword.
        //
        // These five leave the next word standing where a command stands and lead to one this
        // shell runs. `while`, `until`, `do` and a group's `{` lead to a body that may run no
        // times, and a body is not what this reads.
        let introduces = here
            && !word.quoted
            && matches!(word.text.as_str(), "if" | "then" | "else" | "elif" | "!");
        // An assignment in front of a command is that command's environment rather than a command
        // of its own: `LANG=C source ~/.bashrc` runs `source`.
        let assignment = here && !word.quoted && assigns(&word.text);
        if here && !word.quoted && !introduces && !assignment {
            verbs.push(index);
        }
        at_command = introduces || assignment;
    }
    verbs.iter().any(|index| {
        let verb = &words[*index];
        if !verb.plainly_run || (verb.text != "source" && verb.text != ".") {
            return false;
        }
        // A condition this host does not evaluate stands in front of it only where the condition
        // is about `.bashrc` itself, which is the one a login file is written with and the one an
        // installation has already made true.
        if verb.conditional && !words[..*index].iter().any(names_bashrc) {
            return false;
        }
        words.get(index + 1).is_some_and(|argument| {
            // The word after it in this same command: `source; /missing/.bashrc` names no file to
            // `source`, because the `;` ended that command before the path began.
            !argument.command_position && names_bashrc(argument)
        })
    })
}

/// Returns whether a word names a path ending in `.bashrc`.
fn names_bashrc(word: &Word) -> bool {
    // Quoting that leaves `$HOME` or `~` standing leaves a path that names neither the home
    // directory nor anything under it, and nothing here expands either one.
    if word.literal || (word.quoted && word.text.starts_with('~')) {
        return false;
    }
    std::path::Path::new(&word.text)
        .file_name()
        .is_some_and(|name| name == ".bashrc")
}

/// What one guarded entry contains.
///
/// The body is the package's own file, sourced by one line. Nothing of the integration's logic is
/// copied into the user's configuration, so upgrading the package changes what runs without
/// rewriting anything the user owns.
#[must_use]
pub fn entry(kind: ShellKind, package_entry: &Path, nsh_bypass: bool) -> String {
    // The path is quoted for the shell that will read this file, by the same rules a launch is
    // quoted by. An installation directory with an apostrophe in it would otherwise end the string
    // and turn the rest of the path into shell syntax.
    let path = crate::host::quoting::quote(kind, &package_entry.display().to_string());
    let mut body = String::new();
    body.push_str(MARKER_BEGIN);
    body.push('\n');
    body.push_str(
        "# Added by `kr shell install`. It is inert outside a KalaReach-created shell, and\n\
         # `kr shell remove` deletes exactly these lines.\n",
    );
    match kind {
        ShellKind::Zsh | ShellKind::Bash => {
            if nsh_bypass {
                body.push_str(&format!(
                    "[ -n \"${{KR_SHELL_BRIDGE:-}}\" ] && export {NSH_BYPASS_VARIABLE}=1\n"
                ));
            }
            body.push_str(&format!("[ -r {path} ] && . {path}\n"));
        }
        ShellKind::Fish => {
            if nsh_bypass {
                body.push_str(&format!(
                    "if set -q KR_SHELL_BRIDGE; set -gx {NSH_BYPASS_VARIABLE} 1; end\n"
                ));
            }
            body.push_str(&format!("if test -r {path}; source {path}; end\n"));
        }
        ShellKind::PowerShell => {
            if nsh_bypass {
                body.push_str(&format!(
                    "if ($env:KR_SHELL_BRIDGE) {{ $env:{NSH_BYPASS_VARIABLE} = '1' }}\n"
                ));
            }
            body.push_str(&format!("if (Test-Path {path}) {{ . {path} }}\n"));
        }
    }
    body.push_str(MARKER_END);
    body.push('\n');
    body
}

/// What installing or removing an entry did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    /// The entry was added.
    Added,
    /// An entry was already there and has been replaced with this one.
    Replaced,
    /// The file already held exactly this entry.
    Unchanged,
    /// The entry was removed.
    Removed,
    /// There was no entry to remove.
    Absent,
}

/// Adds or updates one shell's guarded entry.
///
/// The file is created when it does not exist and appended to when it does. Everything the user
/// wrote is kept: the entry is delimited by its markers and only the text between them is ever
/// rewritten.
///
/// # Errors
///
/// Returns the underlying failure when the file cannot be read or written.
pub fn install(path: &Path, body: &str) -> std::io::Result<Change> {
    let _writing = writing();
    let _held = FileLock::take(path)?;
    let existing = read_or_empty(path)?;
    let (change, updated) = match strip(&existing) {
        Some((before, after)) => {
            let rebuilt = format!("{before}{body}{after}");
            if rebuilt == existing {
                (Change::Unchanged, rebuilt)
            } else {
                (Change::Replaced, rebuilt)
            }
        }
        None => {
            let mut rebuilt = existing.clone();
            if !rebuilt.is_empty() && !rebuilt.ends_with('\n') {
                rebuilt.push('\n');
            }
            rebuilt.push_str(body);
            (Change::Added, rebuilt)
        }
    };
    if change != Change::Unchanged {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        replace(path, &existing, &updated)?;
    }
    Ok(change)
}

/// Removes one shell's guarded entry, and nothing else.
///
/// # Errors
///
/// Returns the underlying failure when the file cannot be read or written.
pub fn remove(path: &Path) -> std::io::Result<Change> {
    let _writing = writing();
    let _held = FileLock::take(path)?;
    let existing = read_or_empty(path)?;
    let Some((before, after)) = strip(&existing) else {
        return Ok(Change::Absent);
    };
    let rebuilt = format!("{before}{after}");
    // A file this entry created and nothing else ever wrote to goes with it. One the user owns
    // stays, with their own lines exactly as they left them. A link the user made is theirs
    // whatever the file it names holds: deleting it would leave that file behind with the entry
    // still in it, and the shell reading a path that no longer exists.
    let created_here = rebuilt.trim().is_empty()
        && before.trim().is_empty()
        && !path
            .symlink_metadata()
            .is_ok_and(|data| data.file_type().is_symlink());
    if created_here {
        std::fs::remove_file(path)?;
    } else {
        replace(path, &existing, &rebuilt)?;
    }
    Ok(Change::Removed)
}

/// How long a startup write waits for another one to finish before it gives up.
const LOCK_PATIENCE: std::time::Duration = std::time::Duration::from_secs(10);

/// A lock beside one startup file, held for a whole read-rebuild-write.
///
/// This is what closes the window between the check before the rename and the rename itself, for
/// the writer that window was about: another `kr` process installing or removing the same entry.
/// The lock file sits beside the startup file, so the two processes need no agreement beyond the
/// directory they are both writing in.
///
/// The lock is the operating system's on both platforms, so a holder that dies releases it and no
/// staleness rule is needed: on Unix it is `flock` on the open file, and on Windows it is the file
/// opened with no sharing at all, which refuses every other opener while the handle is held.
///
/// It says nothing about an editor. A person who saves the file between the check and the rename
/// still has that save replaced, and closing that would need the platform to offer a comparison
/// and a rename in one step.
#[derive(Debug)]
struct FileLock {
    /// The lock file this guard is about.
    path: PathBuf,
    /// The open file the operating system's lock is on, released when this guard drops it.
    held: Option<std::fs::File>,
}

impl FileLock {
    /// Returns where one startup file's lock lives.
    fn beside(path: &Path) -> std::io::Result<PathBuf> {
        let target = resolved(path)?;
        let directory = target
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let name = target.file_name().map_or_else(
            || String::from("startup"),
            |name| name.to_string_lossy().into_owned(),
        );
        // The directory has to be there before anything in it can be locked, and it is this
        // command's to create: a first-time setup writes a profile into a directory the user does
        // not have yet, and a write with no lock taken is the thing this exists to prevent.
        std::fs::create_dir_all(&directory)?;
        Ok(directory.join(format!(".{name}.kalareach-lock")))
    }

    /// Takes the lock for one startup file, waiting for a holder that is still working.
    ///
    /// # Errors
    ///
    /// Returns the underlying failure, or a timeout when another writer held it throughout.
    #[cfg(unix)]
    fn take(path: &Path) -> std::io::Result<Self> {
        let lock = Self::beside(path)?;
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock)?;
        let deadline = std::time::Instant::now() + LOCK_PATIENCE;
        loop {
            match rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => {
                    return Ok(Self {
                        path: lock,
                        held: Some(file),
                    });
                }
                Err(rustix::io::Errno::WOULDBLOCK) => {}
                Err(error) => return Err(std::io::Error::from(error)),
            }
            if std::time::Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "another kr process is writing {}; nothing was written",
                        path.display()
                    ),
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
    }

    /// Takes the lock for one startup file, waiting for a holder that is still working.
    ///
    /// The lock is the operating system's, not an age rule: the file is opened with no sharing at
    /// all, so a second opener is refused while the first holds its handle and the handle closes
    /// with the process that held it. A writer that died leaves a file nobody is holding, and the
    /// next writer opens it.
    ///
    /// # Errors
    ///
    /// Returns the underlying failure, or a timeout when another writer held it throughout.
    #[cfg(not(unix))]
    fn take(path: &Path) -> std::io::Result<Self> {
        use std::os::windows::fs::OpenOptionsExt as _;

        /// What Windows says when another handle holds the file.
        const ERROR_SHARING_VIOLATION: i32 = 32;
        /// What it says when a region of it is locked.
        const ERROR_LOCK_VIOLATION: i32 = 33;

        let lock = Self::beside(path)?;
        let deadline = std::time::Instant::now() + LOCK_PATIENCE;
        loop {
            match std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                // No sharing: while this handle is open, nothing else may open the file at all.
                .share_mode(0)
                .open(&lock)
            {
                Ok(file) => {
                    return Ok(Self {
                        path: lock,
                        held: Some(file),
                    });
                }
                // Somebody is holding it. The platform says so with a sharing or lock violation,
                // and it is the raw code that says which: the standard library does not map either
                // to a kind of its own, so a writer that matched on the kind would give up at once
                // and a real permission failure would wait out the whole deadline.
                Err(error)
                    if matches!(
                        error.raw_os_error(),
                        Some(ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION)
                    ) => {}
                Err(error) => return Err(error),
            }
            if std::time::Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "another kr process is writing {}; nothing was written",
                        path.display()
                    ),
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        // The file stays. A waiter is holding the same name open and waiting on the operating
        // system's own lock, and removing the name would let a third process create another file
        // with it: two writers would then hold two different locks and write over each other.
        // Closing the file is what releases the lock, and the empty file left beside the startup
        // file costs nothing.
        let _ = &self.path;
        drop(self.held.take());
    }
}

/// Serialises this process's own startup-file writes.
///
/// Installing and removing both read a file, rebuild it and write it back. Two of them running at
/// once against the same file could otherwise interleave and lose one of the two results. Another
/// process is excluded by [`FileLock`], and what neither covers is a person's own editor, which is
/// what the check before the rename is for.
fn writing() -> std::sync::MutexGuard<'static, ()> {
    static WRITING: std::sync::Mutex<()> = std::sync::Mutex::new(());

    WRITING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Returns whether a file holds a KalaReach entry.
#[must_use]
pub fn installed(path: &Path) -> bool {
    read_or_empty(path).is_ok_and(|contents| strip(&contents).is_some())
}

/// Splits a file around its KalaReach entry.
fn strip(contents: &str) -> Option<(String, String)> {
    let begin = contents.find(MARKER_BEGIN)?;
    let end = contents[begin..].find(MARKER_END)? + begin;
    let after = end + MARKER_END.len();
    let after = contents[after..]
        .strip_prefix('\n')
        .map_or(&contents[after..], |rest| rest);
    Some((contents[..begin].to_owned(), after.to_owned()))
}

/// Writes a startup file by replacing it, never by truncating it.
///
/// A short write, a full disk or a crash between the truncation and the write would otherwise take
/// the user's own configuration with it. The new contents are written beside the file and renamed
/// over it, which on every platform this host runs on is one step: the file is either what it was
/// or what it is going to be, and never half of either.
///
/// Three things the rename has to respect. A startup file is often a symlink into a dotfiles
/// checkout, so the replacement is written over the file the link points at and the link is left
/// alone. The file beside it is created exclusively under a name of this call's own, so nothing
/// that happens to be there is truncated and two calls cannot share one temporary. And the file
/// may have changed since the caller read it, so the contents and the file's own identity are
/// checked again immediately before the rename, once the slow part is behind us: a replacement
/// built on stale contents would silently drop whatever was saved in between.
///
/// What remains is one window and one writer. This process's own calls are serialised against each
/// other and another `kr` process is excluded by the lock beside the file, so the writer the window
/// is about is a person's own editor saving between the check and the rename; closing that would
/// need the platform to offer a comparison and a rename in one step. The identity half of the
/// check is a Unix one, and it is used only where the filesystem's numbers hold still: elsewhere a
/// file that was replaced rather than edited is caught by its contents.
fn replace(path: &Path, expected: &str, contents: &str) -> std::io::Result<()> {
    // The file the configuration actually lives in. A symlink is a deliberate arrangement of the
    // user's, and renaming over the link would replace it with a regular file and quietly cut the
    // startup entry off from the checkout it belongs to.
    let target = resolved(path)?;
    let directory = target.parent().unwrap_or_else(|| Path::new("."));
    let name = target.file_name().map_or_else(
        || String::from("startup"),
        |name| name.to_string_lossy().into_owned(),
    );
    let temporary = directory.join(format!(".{name}.kalareach-{}", kr_ipc::new_uuid()));
    // The permissions of the file being replaced, so a profile that was owner-only stays so.
    let permissions = std::fs::metadata(&target)
        .ok()
        .map(|data| data.permissions());
    // The identity this rename stands on, and whether it means anything here. A filesystem that
    // hands out a different number for the same unchanged file is one where an identity check
    // would refuse a write it should have made, so what such a filesystem gets is the contents
    // check alone.
    let identity = stable_identity(&target);
    let prepared = write_new(&temporary, contents).and_then(|()| {
        if let Some(permissions) = permissions {
            std::fs::set_permissions(&temporary, permissions)?;
        }
        // The check the rename stands on, taken here rather than before the write: the write, the
        // permissions and the flush are where the time goes, and a check taken before them says
        // nothing about the file the rename is about to replace.
        if read_or_empty(&target)? != expected
            || identity.is_some_and(|identity| stable_identity(&target) != Some(identity))
        {
            return Err(std::io::Error::other(
                "the startup file changed while this entry was being written, so nothing was \
                 written",
            ));
        }
        std::fs::rename(&temporary, &target)
    });
    if prepared.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    prepared
}

/// Returns the file a startup path resolves to, following a link the user made.
fn resolved(path: &Path) -> std::io::Result<std::path::PathBuf> {
    match path.symlink_metadata() {
        Ok(data) if data.file_type().is_symlink() => std::fs::canonicalize(path),
        _ => Ok(path.to_path_buf()),
    }
}

/// Returns a file's identity, when this filesystem gives it one that holds still.
///
/// A file that was replaced between the caller's read and this rename is a different file, whatever
/// its contents happen to be, and the entry belongs in whichever one the startup path names now.
/// That reasoning needs an identity that is stable for an unchanged file, which not every
/// filesystem offers: some network and userspace filesystems synthesise inode numbers and hand out
/// a different one for the same file. There, an identity check would refuse a write it should have
/// made, so this reads the file twice and reports an identity only when the two readings agree.
///
/// Two agreeing readings are a heuristic, not a proof: a filesystem whose numbers move can answer
/// alike twice, and the refusal that follows is one the contents check would not have made. What
/// they do establish is enough to keep the check off the filesystems that would fail it steadily.
///
/// Two readings that disagree because the file really was replaced in between are covered by the
/// contents check, which runs whether or not there is an identity.
fn stable_identity(path: &Path) -> Option<(u64, u64)> {
    let first = identity_of(path)?;
    (identity_of(path)? == first).then_some(first)
}

/// Returns what the platform says identifies this file.
#[cfg(unix)]
fn identity_of(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt as _;

    std::fs::metadata(path)
        .ok()
        .map(|data| (data.dev(), data.ino()))
}

#[cfg(not(unix))]
fn identity_of(path: &Path) -> Option<(u64, u64)> {
    let _ = path;
    None
}

/// Creates one file that was not there before and writes it out in full.
///
/// Exclusive creation and owner-only permissions from the first byte: nothing that is already at
/// that name is opened, and nothing else on the machine can read a half-written profile. The
/// contents reach the disk before the caller renames the file into place.
fn write_new(path: &Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write as _;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()
}

fn read_or_empty(path: &Path) -> std::io::Result<String> {
    match std::fs::read_to_string(path) {
        Ok(contents) => Ok(contents),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layout(root: &Path) -> HomeLayout {
        HomeLayout {
            home: root.to_path_buf(),
            zdotdir: None,
            xdg_config_home: None,
            powershell: None,
        }
    }

    #[test]
    fn zsh_follows_the_configured_zdotdir() {
        let root = tempfile::tempdir().expect("a directory");
        let plain = layout(root.path());
        assert_eq!(
            plain.targets(ShellKind::Zsh)[0].path,
            root.path().join(".zshrc")
        );
        let configured = HomeLayout {
            zdotdir: Some(root.path().join("dotfiles/zsh")),
            ..plain
        };
        assert_eq!(
            configured.targets(ShellKind::Zsh)[0].path,
            root.path().join("dotfiles/zsh/.zshrc"),
            "the file the shell actually reads, not the one in the home directory"
        );
    }

    #[test]
    fn bash_gets_a_login_entry_only_when_the_login_file_ignores_bashrc() {
        let root = tempfile::tempdir().expect("a directory");
        let home = layout(root.path());
        // No login file at all.
        assert_eq!(home.targets(ShellKind::Bash).len(), 1);
        // One that already sources .bashrc needs nothing of its own.
        std::fs::write(
            root.path().join(".bash_profile"),
            "[ -f ~/.bashrc ] && . ~/.bashrc\n",
        )
        .expect("writes");
        assert_eq!(home.targets(ShellKind::Bash).len(), 1);
        // One that does not.
        std::fs::write(
            root.path().join(".bash_profile"),
            "export PATH=$PATH:/opt\n",
        )
        .expect("writes");
        let targets = home.targets(ShellKind::Bash);
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].path, root.path().join(".bashrc"));
        assert_eq!(targets[1].path, root.path().join(".bash_profile"));
    }

    /// Login files that name `.bashrc` without running it.
    const MENTIONS: &[&str] = &[
        "# this used to source ~/.bashrc; it does not any more\n",
        "echo 'see .bashrc for the aliases'\n",
        "BASHRC=~/.bashrc\n",
        "# . ~/.bashrc\n",
        "export EDITOR=vim # source ~/.bashrc\n",
        "PS1='> ' ## . ~/.bashrc\n",
        "echo \"please source ~/.bashrc\"\n",
        "echo 'run . ~/.bashrc yourself'\n",
        "echo source ~/.bashrc\n",
        "echo \"please \\\" source ~/.bashrc\"\n",
        "printf '%s\\n' source ~/.bashrc\n",
        "echo if source ~/.bashrc\n",
        "\"echo\" source ~/.bashrc\n",
        "cat <<EOF\nsource ~/.bashrc\nEOF\n",
        // `<<-` strips leading tabs from the delimiter and nothing else, so a line that
        // begins with a space is body rather than the end of one.
        ": <<-EOF\n EOF\nsource ~/.bashrc\nEOF\n",
        "cat <<'END HERE'\nsource ~/.bashrc\nEND HERE\n",
        // A backslash quotes the delimiter too, so `<<\\EOF` ends at `EOF`.
        "cat <<\\EOF\nsource ~/.bashrc\nEOF\n",
        "cat <<ONE <<TWO\nsource ~/.bashrc\nONE\n. ~/.bashrc\nTWO\n",
        "echo \\\nsource ~/.bashrc\n",
        // A here-document whose delimiter is empty ends at the first empty line.
        ": <<''\nsource ~/.bashrc\n\n",
        // An unquoted delimiter leaves its body expanded, so `x\` and the line after it make
        // `xEOF` rather than the end of the body.
        ": <<EOF\nx\\\nEOF\nsource ~/.bashrc\nEOF\n",
        // A quoted message can hold newlines, and what is inside one is a message.
        "echo \"a message\nsource ~/.bashrc\"\n",
        // A backslash before a newline joins the lines with nothing between them, so this
        // names a command called `source~/.bashrc`.
        "source\\\n~/.bashrc\n",
        // A substitution runs the command inside it in a shell of its own, which leaves the shell
        // this host integrates with nothing.
        "OUT=$(source ~/.bashrc)\n",
        "OUT=`source ~/.bashrc`\n",
        // Parentheses hold array data as readily as a command.
        "parts=(source ~/.bashrc)\n",
        // A substitution that ends leaves the words after it arguments rather than commands.
        "echo $(printf '') source ~/.bashrc\n",
        // `$'…'` takes backslash escapes, so the apostrophe in it does not end the quoting.
        "echo $'it\\'s\nsource ~/.bashrc\n'\n",
        // A separator ends the command before the path, so `source` is given nothing.
        "source; /missing/.bashrc\n",
        // Inside double quotes a backslash goes before the `$` it quotes, so the delimiter is
        // `$EOF` and the line that reads `\$EOF` is body.
        ": <<\"\\$EOF\"\n\\$EOF\nsource ~/.bashrc\n$EOF\n",
        // The inner here-document belongs to the substitution, and the outer body follows the
        // whole command.
        ": <<OUT $(cat <<IN\nOUT\nIN\n)\nsource ~/.bashrc\nOUT\n",
        // Single quotes leave `$HOME` a directory of that name rather than the home.
        "source '$HOME/.bashrc'\n",
        // `||` leads to a command only when what came before it failed.
        "test -f ~/.bashrc || . ~/.bashrc\n",
        // A loop body can run no times at all, and a function body runs when it is called.
        "while false; do . ~/.bashrc; done\n",
        "until true; do . ~/.bashrc; done\n",
        "f() { . ~/.bashrc; }\n",
        // A pipe and a background `&` each lead to a shell of their own.
        "echo x | . ~/.bashrc\n",
        ". ~/.bashrc &\n",
        // A condition this host cannot answer is one it does not read a call through.
        "if false; then . ~/.bashrc; fi\n",
        "false && . ~/.bashrc\n",
        // Double quotes leave `~` a directory of that name rather than the home.
        "source \"~/.bashrc\"\n",
    ];

    /// Login files that run `.bashrc`.
    const SOURCES: &[&str] = &[
        ". ~/.bashrc\n",
        "source ~/.bashrc\n",
        "[ -f ~/.bashrc ] && source \"$HOME/.bashrc\"\n",
        "export PATH=/opt:$PATH; . /home/someone/.bashrc\n",
        "if [ -r ~/.bashrc ]; then . ~/.bashrc; fi\n",
        // A here-document that ends leaves the commands after it commands again.
        "cat <<EOF\nnothing\nEOF\n. ~/.bashrc\n",
        // A here-string opens no body at all.
        "cat <<<'x'\n. ~/.bashrc\n",
        // An assignment in front of a command leaves the command where a command stands.
        "LANG=C source ~/.bashrc\n",
    ];

    /// KR-REQ-07.30: only a login file that actually runs `.bashrc` counts as one that does.
    #[test]
    fn a_login_file_that_only_mentions_bashrc_still_gets_its_own_entry() {
        let root = tempfile::tempdir().expect("a directory");
        let home = layout(root.path());
        for mentions in MENTIONS {
            std::fs::write(root.path().join(".bash_profile"), mentions).expect("writes");
            assert_eq!(
                home.targets(ShellKind::Bash).len(),
                2,
                "a login file that names .bashrc without running it still needs an entry: \
                 {mentions:?}"
            );
        }
        for sources in SOURCES {
            std::fs::write(root.path().join(".bash_profile"), sources).expect("writes");
            assert_eq!(
                home.targets(ShellKind::Bash).len(),
                1,
                "a login file that runs .bashrc needs no entry of its own: {sources:?}"
            );
        }
    }

    /// KR-REQ-07.30: what this host reads as a call is one Bash itself makes.
    ///
    /// The scanner is allowed to miss a call, which costs one guarded entry nothing reads twice.
    /// It is not allowed to see one that is not there, because that leaves a login shell with no
    /// integration at all. That direction is checked against the shell rather than against this
    /// host's reading of it.
    #[cfg(unix)]
    #[test]
    fn nothing_reads_as_a_call_bash_does_not_make() {
        let bash = Path::new("/bin/bash");
        if !bash.exists() {
            eprintln!("skipped: this host has no /bin/bash to compare the scanner against");
            return;
        }
        for text in MENTIONS.iter().chain(SOURCES) {
            let scanned = runs_bashrc(text);
            if !scanned {
                continue;
            }
            assert!(
                bash_sources_bashrc(bash, text),
                "this host reads a call Bash does not make, so a login shell would get no entry: \
                 {text:?}"
            );
        }
    }

    /// Runs one login file under Bash with a home of its own and reports whether `.bashrc` ran.
    #[cfg(unix)]
    fn bash_sources_bashrc(bash: &Path, text: &str) -> bool {
        let home = tempfile::Builder::new()
            .prefix("kr-bash-home-")
            .tempdir()
            .expect("a home directory");
        let ran = home.path().join("ran");
        std::fs::write(
            home.path().join(".bashrc"),
            format!(": > {}\n", ran.display()),
        )
        .expect("writes a .bashrc");
        let script = home.path().join("login");
        // One case names an absolute path rather than the home directory, so that the scanner is
        // read on both shapes. Here it is pointed at this run's own home, or the shell would find
        // nothing to source and every reading of it would look like a miss.
        let text = text.replace("/home/someone", &home.path().display().to_string());
        std::fs::write(&script, &text).expect("writes a login file");
        let mut child = std::process::Command::new(bash)
            .arg(&script)
            .env("HOME", home.path())
            .current_dir(home.path())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("runs the login file");
        // Bounded, because a login file that waits for something would otherwise wait for ever.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) => {}
                Err(_) => break,
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        ran.exists()
    }

    /// KR-REQ-07.40: two writers of one startup file do not interleave, whichever process each
    /// is in.
    #[test]
    fn a_second_writer_waits_for_the_first_and_neither_loses_its_entry() {
        let root = tempfile::tempdir().expect("a directory");
        let path = root.path().join(".zshrc");
        std::fs::write(&path, "export EDITOR=vim\n").expect("writes");

        // A lock is taken for the whole read-rebuild-write, so a writer that is not this process
        // is kept out rather than racing the rename.
        let lock = FileLock::beside(&path).expect("names the lock");
        let held = FileLock::take(&path).expect("takes the lock");
        assert!(lock.is_file(), "the lock is beside the file it is about");
        // A second attempt waits for the first and gives up rather than writing beside it.
        let refused = FileLock::take(&path).expect_err("one writer at a time");
        assert_eq!(refused.kind(), std::io::ErrorKind::TimedOut);
        drop(held);
        // The name stays where a waiter can be holding the same file open; what the drop releases
        // is the kernel's lock, which the next writer takes at once.
        let after = FileLock::take(&path).expect("the next writer takes it straight away");
        drop(after);

        let body = entry(ShellKind::Zsh, Path::new("/opt/kr/zsh-entry.zsh"), false);
        assert_eq!(install(&path, &body).expect("installs"), Change::Added);
        assert!(
            std::fs::read_to_string(&path)
                .expect("reads")
                .starts_with("export EDITOR=vim"),
            "the user's own line is still first"
        );
    }

    /// KR-REQ-07.29: a first-time setup creates the directory and still takes a lock in it.
    #[test]
    fn a_profile_in_a_directory_that_is_not_there_yet_is_written_under_a_lock() {
        let root = tempfile::tempdir().expect("a directory");
        let path = root.path().join("config/powershell/profile.ps1");
        let lock = FileLock::beside(&path).expect("names the lock");
        assert!(
            lock.parent().expect("a directory").is_dir(),
            "the directory the lock lives in is created before the lock is taken"
        );
        let held = FileLock::take(&path).expect("takes the lock");
        assert!(lock.is_file());
        drop(held);

        let body = entry(ShellKind::PowerShell, Path::new("/opt/kr/entry.ps1"), false);
        assert_eq!(install(&path, &body).expect("installs"), Change::Added);
        assert!(installed(&path));
    }

    /// KR-REQ-07.40: a filesystem whose identity numbers move does not refuse a legitimate write.
    #[test]
    fn an_unstable_identity_leaves_the_write_to_the_contents_check() {
        let root = tempfile::tempdir().expect("a directory");
        let path = root.path().join(".zshrc");
        std::fs::write(&path, "export EDITOR=vim\n").expect("writes");
        // On a filesystem that holds still, two readings agree and the identity is used.
        assert_eq!(stable_identity(&path), identity_of(&path));
        // A path that names nothing has no identity either way, and the write is decided by the
        // contents alone, which is what a filesystem with moving numbers gets.
        assert_eq!(stable_identity(&root.path().join("absent")), None);

        let body = entry(ShellKind::Zsh, Path::new("/opt/kr/zsh-entry.zsh"), false);
        assert_eq!(install(&path, &body).expect("installs"), Change::Added);
        assert_eq!(remove(&path).expect("removes"), Change::Removed);
        assert_eq!(
            std::fs::read_to_string(&path).expect("reads"),
            "export EDITOR=vim\n"
        );
    }

    /// KR-REQ-07.29: PowerShell's profile is the one that shell itself names.
    ///
    /// Unix, because the shell it asks is a program this test writes, and writing one needs a
    /// shebang and an executable bit. What the code under test does with the answer is the same on
    /// every platform.
    #[cfg(unix)]
    #[test]
    fn the_powershell_profile_is_the_one_that_shell_names() {
        let root = tempfile::tempdir().expect("a directory");
        let home = layout(root.path());
        assert!(
            home.targets(ShellKind::PowerShell).is_empty(),
            "a host with no PowerShell has no profile to add an entry to, and none is guessed"
        );

        // A shell that answers: the entry goes where it said, wherever that is.
        let wanted = root.path().join("Documents/PowerShell/profile.ps1");
        let asking = HomeLayout {
            powershell: Some(fake_powershell(root.path(), &wanted.display().to_string())),
            ..home.clone()
        };
        let targets = asking.targets(ShellKind::PowerShell);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].path, wanted);

        // A shell that answers nothing leaves this host with no profile rather than one it made up.
        let silent = HomeLayout {
            powershell: Some(fake_powershell(root.path(), "")),
            ..home
        };
        assert!(silent.targets(ShellKind::PowerShell).is_empty());
    }

    /// Writes a program that prints one line, which is all this host asks PowerShell for.
    #[cfg(unix)]
    fn fake_powershell(root: &Path, says: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;

        let path = root.join(format!("pwsh-{}", says.len()));
        std::fs::write(&path, format!("#!/bin/sh\nprintf '%s\\n' '{says}'\n"))
            .expect("writes a program");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .expect("makes it runnable");
        // A file this thread has just written is briefly unrunnable: another thread's fork still
        // holds the descriptor it was written through, and the kernel refuses to run it until that
        // fork reaches its own program. Run it here until it runs, so the test measures the code
        // under test rather than that window.
        let until = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            match std::process::Command::new(&path)
                .stdout(std::process::Stdio::null())
                .status()
            {
                Ok(_) => break path,
                Err(error) => assert!(
                    std::time::Instant::now() < until,
                    "the written program never ran: {error}"
                ),
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    #[test]
    fn the_entry_is_added_beside_what_the_user_wrote_and_removed_without_it() {
        let root = tempfile::tempdir().expect("a directory");
        let path = root.path().join(".zshrc");
        let theirs = "export EDITOR=vim\nalias ll='ls -la'\n";
        std::fs::write(&path, theirs).expect("writes");
        let body = entry(ShellKind::Zsh, Path::new("/opt/kr/zsh-entry.zsh"), false);
        assert_eq!(install(&path, &body).expect("installs"), Change::Added);
        let after = std::fs::read_to_string(&path).expect("reads");
        assert!(after.starts_with(theirs), "the user's own lines are first");
        assert!(after.contains(MARKER_BEGIN) && after.contains(MARKER_END));
        assert!(installed(&path));
        // A second install is not a second entry.
        assert_eq!(install(&path, &body).expect("installs"), Change::Unchanged);
        let updated = entry(ShellKind::Zsh, Path::new("/opt/kr/zsh-entry.zsh"), true);
        assert_eq!(
            install(&path, &updated).expect("installs"),
            Change::Replaced
        );
        assert_eq!(
            std::fs::read_to_string(&path)
                .expect("reads")
                .matches(MARKER_BEGIN)
                .count(),
            1
        );
        assert_eq!(remove(&path).expect("removes"), Change::Removed);
        assert_eq!(std::fs::read_to_string(&path).expect("reads"), theirs);
        assert_eq!(remove(&path).expect("removes"), Change::Absent);
    }

    #[cfg(unix)]
    #[test]
    fn a_startup_file_that_is_a_link_keeps_pointing_at_the_file_it_named() {
        // A startup file is very often a link into a checkout of the user's own. Writing the entry
        // has to reach the file the link names, or the entry would land in a regular file that
        // replaced the link and every later change in the checkout would stop arriving.
        let root = tempfile::tempdir().expect("a directory");
        let checkout = root.path().join("dotfiles");
        std::fs::create_dir_all(&checkout).expect("creates");
        let real = checkout.join("zshrc");
        let theirs = "export EDITOR=vim\n";
        std::fs::write(&real, theirs).expect("writes");
        let link = root.path().join(".zshrc");
        std::os::unix::fs::symlink(&real, &link).expect("links");

        let body = entry(ShellKind::Zsh, Path::new("/opt/kr/zsh-entry.zsh"), false);
        assert_eq!(install(&link, &body).expect("installs"), Change::Added);
        assert!(
            link.symlink_metadata()
                .expect("reads")
                .file_type()
                .is_symlink(),
            "the link is still a link"
        );
        let written = std::fs::read_to_string(&real).expect("reads");
        assert!(written.starts_with(theirs) && written.contains(MARKER_BEGIN));

        assert_eq!(remove(&link).expect("removes"), Change::Removed);
        assert!(
            link.symlink_metadata()
                .expect("reads")
                .file_type()
                .is_symlink()
        );
        assert_eq!(std::fs::read_to_string(&real).expect("reads"), theirs);
    }

    #[cfg(unix)]
    #[test]
    fn removing_an_entry_from_a_linked_file_keeps_the_link_and_empties_the_file_it_names() {
        // The link is the user's arrangement, not this entry's. Deleting it because the file it
        // names came out empty would leave the shell reading a path that is not there, and the
        // checkout holding an entry nothing can remove.
        let root = tempfile::tempdir().expect("a directory");
        let checkout = root.path().join("dotfiles");
        std::fs::create_dir_all(&checkout).expect("creates");
        let real = checkout.join("zshrc");
        std::fs::write(&real, "").expect("writes an empty file");
        let link = root.path().join(".zshrc");
        std::os::unix::fs::symlink(&real, &link).expect("links");

        let body = entry(ShellKind::Zsh, Path::new("/opt/kr/zsh-entry.zsh"), false);
        assert_eq!(install(&link, &body).expect("installs"), Change::Added);
        assert_eq!(remove(&link).expect("removes"), Change::Removed);
        assert!(
            link.symlink_metadata()
                .expect("the link is still there")
                .file_type()
                .is_symlink()
        );
        assert!(
            !installed(&real),
            "and the file it names no longer holds the entry"
        );
    }

    #[cfg(unix)]
    #[test]
    fn nothing_beside_the_startup_file_is_written_over_and_nothing_is_left_behind() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().expect("a directory");
        let path = root.path().join(".zshrc");
        std::fs::write(&path, "setopt autocd\n").expect("writes");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("sets");
        // A file at the name the replacement used to take. Nothing may open it.
        let bystander = root.path().join(".zshrc.kalareach-new");
        std::fs::write(&bystander, "not ours\n").expect("writes");

        let body = entry(ShellKind::Zsh, Path::new("/opt/kr/zsh-entry.zsh"), false);
        assert_eq!(install(&path, &body).expect("installs"), Change::Added);
        assert_eq!(
            std::fs::read_to_string(&bystander).expect("reads"),
            "not ours\n"
        );
        assert_eq!(
            std::fs::metadata(&path)
                .expect("reads")
                .permissions()
                .mode()
                & 0o777,
            0o600,
            "the file keeps the permissions it had"
        );
        let leftovers: Vec<_> = std::fs::read_dir(root.path())
            .expect("lists")
            .filter_map(|entry| entry.ok().map(|entry| entry.file_name()))
            .filter(|name| {
                let name = name.to_string_lossy();
                // The lock file is not a leftover: it is the name a waiter holds open, and on
                // Unix it stays so that two writers cannot end up holding two different locks.
                name.contains("kalareach-")
                    && name != ".zshrc.kalareach-new"
                    && !name.ends_with("kalareach-lock")
            })
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[test]
    fn a_startup_file_that_changed_since_it_was_read_is_left_alone() {
        // `install` reads, rebuilds and writes. Between the read and the write the user's editor
        // may have saved the same file, and a replacement built on what was read would throw that
        // away without a word.
        let root = tempfile::tempdir().expect("a directory");
        let path = root.path().join(".zshrc");
        std::fs::write(&path, "first\n").expect("writes");
        let rebuilt = "first\nours\n";
        std::fs::write(&path, "theirs, saved in between\n").expect("writes");
        let error = replace(&path, "first\n", rebuilt).expect_err("refuses");
        assert_eq!(
            std::fs::read_to_string(&path).expect("reads"),
            "theirs, saved in between\n"
        );
        assert!(error.to_string().contains("changed"), "{error}");
    }

    #[test]
    fn the_bypass_is_only_ever_set_inside_a_kalareach_shell() {
        for kind in ShellKind::ALL {
            let with = entry(*kind, Path::new("/opt/kr/entry"), true);
            assert!(
                with.contains(NSH_BYPASS_VARIABLE),
                "{kind} offers the documented bypass"
            );
            assert!(
                with.contains("KR_SHELL_BRIDGE"),
                "{kind} sets it only where the bridge was exported"
            );
            let without = entry(*kind, Path::new("/opt/kr/entry"), false);
            assert!(
                !without.contains(NSH_BYPASS_VARIABLE),
                "{kind} sets nothing when the option is off"
            );
        }
    }

    #[test]
    fn a_path_with_an_apostrophe_stays_one_word() {
        for kind in ShellKind::ALL {
            let body = entry(*kind, Path::new("/home/it's mine/kr/entry"), false);
            // The apostrophe is escaped rather than ending the string, so the line still names one
            // path and nothing after it is read as shell syntax.
            assert!(
                !body.contains("/home/it's mine/kr/entry"),
                "{kind} left the apostrophe unescaped: {body}"
            );
            assert!(body.contains("mine/kr/entry"), "{kind}: {body}");
        }
    }

    #[test]
    fn nothing_replaces_a_profile_or_points_at_another_zdotdir() {
        for kind in ShellKind::ALL {
            let body = entry(*kind, Path::new("/opt/kr/entry"), true);
            for forbidden in ["ZDOTDIR=", "--rcfile", "--norc", "--noprofile", "exec "] {
                assert!(
                    !body.contains(forbidden),
                    "{kind}'s entry contains {forbidden}"
                );
            }
        }
    }
}

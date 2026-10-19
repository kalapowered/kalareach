//! Where the shell integration is, and where it is not.
//!
//! Section 7: limited shell integration applies only inside KalaReach-created root shells. It must
//! not replace `accept-line` globally, change unrelated key bindings or add OSC 7 and OSC 133
//! reports to a terminal's output. Once the integration is installed, the person's own startup
//! carries the packaged entry and every shell they start reads it, so a shell that is not a root
//! shell meets the entry too. These cases start the built shell three ways, each at its prompt with
//! the same questions put to it: as a person's own shell with nothing of ours in its startup, as one
//! with the entry in its startup and no bootstrap values, which is what a terminal of the person's
//! is once the integration is installed, and as the root shell of a session.

use std::collections::BTreeMap;
use std::path::Path;

use super::*;

/// What each probe line ends by printing, put together by the shell from two pieces.
const PROBED: &str = "kr-probed";

/// What a shell showed of itself.
struct Showed {
    /// What the shell's own test for being a root shell answered.
    root: String,
    /// What the editor does with the keys that accept a line, and the bindings it was given.
    accepting: String,
    /// Every binding the editor holds.
    bindings: String,
    /// The working-directory and prompt marks the shell wrote to its terminal.
    marks: BTreeMap<String, usize>,
}

/// The lines that ask a shell what it is, what its accepting keys do and what it holds bound, each
/// leaving its answer in a file under `$CASE_OUT` rather than on the terminal, where the editor's
/// drawing would be part of what is read.
struct Probe {
    root: &'static str,
    accepting: &'static str,
    bindings: &'static str,
    /// What `root` leaves for a shell that is a root shell.
    is_root: &'static str,
}

fn probe(kind: ShellKind) -> Probe {
    match kind {
        ShellKind::Zsh => Probe {
            root: "builtin kr-bridge status >/dev/null 2>&1; echo $? > \"$CASE_OUT/root\"",
            accepting: "{ bindkey '^M'; bindkey '^J'; zle -lL; } > \"$CASE_OUT/accepting\" 2>&1",
            bindings: "{ bindkey -L; bindkey -lL; } > \"$CASE_OUT/bindings\" 2>&1",
            is_root: "0",
        },
        ShellKind::Bash => Probe {
            root: "builtin kr-bridge status >/dev/null 2>&1; echo $? > \"$CASE_OUT/root\"",
            accepting: "bind -p | grep -F accept-line > \"$CASE_OUT/accepting\" 2>&1",
            bindings: "{ bind -p; bind -s; bind -X; } > \"$CASE_OUT/bindings\" 2>&1",
            is_root: "0",
        },
        ShellKind::Fish => Probe {
            root: "builtin kr-bridge status >/dev/null 2>&1; echo $status > $CASE_OUT/root",
            accepting: "begin; bind enter; bind ctrl-j; end > $CASE_OUT/accepting 2>&1",
            bindings: "bind --all > $CASE_OUT/bindings 2>&1",
            is_root: "0",
        },
        ShellKind::PowerShell => Probe {
            root: "[string][bool](Get-Module KalaReach.ShellBridge) | Set-Content \"$env:CASE_OUT/root\"",
            accepting: "'Enter','Ctrl+j' | % { $h = Get-PSReadLineKeyHandler -Chord $_; \"$_|$($h.Function)|$($h.Description)\" } | Set-Content \"$env:CASE_OUT/accepting\"",
            bindings: "Get-PSReadLineKeyHandler -Bound -Unbound | % { \"$($_.Key)|$($_.Function)|$($_.Description -replace '\\s+',' ')\" } | Set-Content \"$env:CASE_OUT/bindings\"",
            is_root: "True",
        },
    }
}

/// Puts the probe's lines to `session` and reads what it left.
fn put_the_probe_to(session: &mut Session, kind: ShellKind, arena: &Path) -> Showed {
    let probe = probe(kind);
    let done = print_assembled(kind, PROBED);
    for line in [probe.root, probe.accepting, probe.bindings] {
        assert!(
            session.run(&format!("{line}; {done}"), PROBED),
            "{line:?} did not finish:\n{}",
            session.terminal_output()
        );
    }
    let read = |name: &str| {
        std::fs::read_to_string(arena.join(name))
            .unwrap_or_else(|error| panic!("{name}: {error}"))
            .trim()
            .to_owned()
    };
    Showed {
        root: read("root"),
        accepting: read("accepting"),
        bindings: read("bindings"),
        // Counted up to the output of the last probe, which the shell prints from pieces it puts
        // together, so the cut is where that command ran and not a moment in time: what a shell
        // writes for the prompt after it is not part of what the three sessions are compared on.
        marks: {
            let output = session.terminal_output();
            let ran = output
                .rfind(PROBED)
                .unwrap_or_else(|| panic!("the last probe never printed:\n{output}"));
            marks(&output[..ran])
        },
    }
}

/// The marks a terminal's output carries that report the working directory (OSC 7) or mark a
/// prompt (OSC 133, by the mark's letter), each counted: a shell may write these itself, and what
/// the integration may not do is add to them.
fn marks(terminal: &str) -> BTreeMap<String, usize> {
    let mut found = BTreeMap::new();
    for piece in terminal.split("\x1b]").skip(1) {
        let end = piece.find(['\x07', '\x1b']).unwrap_or(piece.len());
        let (number, rest) = piece[..end].split_once(';').unwrap_or((&piece[..end], ""));
        match number {
            "7" => *found.entry("7".to_owned()).or_insert(0) += 1,
            "133" => {
                *found
                    .entry(format!("133;{}", rest.chars().next().unwrap_or(' ')))
                    .or_insert(0) += 1;
            }
            _ => {}
        }
    }
    found
}

/// What a shell does with the keys that accept a line, in the words this shell answers the probe
/// in: its own function accepts the line, and nothing has replaced it. No root shell but
/// PowerShell's changes anything about these keys. PowerShell's root shell binds each key that holds
/// an operation of the editor to a script block of the module's, which runs the operation and then
/// reads the module's mailbox, and labels it with the operation's name; what a probe reads there is
/// that label, so for it this checks that the label names the shell's own function and not that no
/// block stands between the key and the function.
fn assert_stock_accepting(kind: ShellKind, accepting: &str, whose: &str, a_root_shell: bool) {
    assert!(
        (a_root_shell && kind == ShellKind::PowerShell)
            || (!accepting.contains("KalaReach")
                && !accepting.contains("kr-")
                && !accepting.contains("kr_")),
        "{whose}: something of KalaReach's is bound to a key that accepts a line:\n{accepting}"
    );
    match kind {
        ShellKind::Zsh => assert_eq!(
            accepting, "\"^M\" accept-line\n\"^J\" accept-line",
            "{whose}: zsh's own widget accepts the line, and no widget of anyone's replaced it"
        ),
        ShellKind::Bash => {
            assert!(
                accepting
                    .lines()
                    .all(|line| line.ends_with(": accept-line"))
                    && accepting.contains("\"\\C-m\": accept-line"),
                "{whose}: bash's own function accepts the line:\n{accepting}"
            );
        }
        ShellKind::Fish => assert!(
            accepting.contains(" enter execute")
                && accepting.lines().all(|line| line.contains("--preset")),
            "{whose}: fish's own binding executes the line and the person has no binding of ours:\n{accepting}"
        ),
        ShellKind::PowerShell => assert!(
            accepting
                .lines()
                .all(|line| line.split('|').nth(1) == Some("AcceptLine")),
            "{whose}: PSReadLine's own function accepts the line:\n{accepting}"
        ),
    }
}

/// What a shell holds bound, as far as the root shell of a session leaves it alone. Section 7 has
/// the root shell implement the empty-prompt gesture that ends a session's input, and the editors
/// that bind it have it bound to the integration's own handler where the shell's own function was:
/// fish's root shell binds it in each of its modes, and PowerShell's binds it too and, as
/// `assert_stock_accepting` says, wraps every key that holds an operation in a block of its own that
/// is labelled with the operation, so for PowerShell this compares those labels and not the blocks.
/// Every other key keeps its function.
fn keys_and_functions(kind: ShellKind, bindings: &str) -> String {
    match kind {
        ShellKind::Zsh | ShellKind::Bash => bindings.to_owned(),
        ShellKind::Fish => bindings
            .lines()
            .filter(|line| !line.ends_with(" ctrl-d kr-eof-decide"))
            .collect::<Vec<_>>()
            .join("\n"),
        ShellKind::PowerShell => bindings
            .lines()
            .filter(|line| {
                !line.starts_with("Ctrl+d|") && !line.starts_with("Unbound|DeleteCharOrExit|")
            })
            .map(|line| line.rsplit_once('|').map_or(line, |(kept, _)| kept))
            .collect::<Vec<_>>()
            .join("\n"),
    }
}

/// KR-REQ-07.44: the integration is confined to a root shell. A shell that is not one, though its
/// startup carries the packaged entry, is not a root shell, holds the bindings the same shell holds
/// without the entry, binds nothing of ours to a key that accepts a line, and writes no working
/// directory or prompt mark the shell does not write by itself. A root shell is the control: it
/// answers that it is one, keeps the shell's own function on every key but the gesture that Section 7
/// has it implement, and adds no mark. For PowerShell the root shell is the module's, which wraps
/// each key that holds an operation of the editor in a block that runs that labelled operation
/// (`Install-KrObservedHandlers`), so what is compared there is the keys' function by label.
pub fn the_integration_stays_in_the_root_shell_and_adds_no_global_accept_line_or_mark(
    kind: ShellKind,
) {
    let package = Package::built(kind);
    let directory = tempfile::Builder::new()
        .prefix("kr-confine-")
        .tempdir()
        .expect("a directory on the internal disk");
    let root = std::fs::canonicalize(directory.path()).expect("the directory resolves");
    let arena = |name: &str| {
        let path = root.join(name);
        std::fs::create_dir(&path).expect("a place to leave what the shell showed");
        path
    };
    // No terminal program is named, so no system startup file of one (the macOS terminal's own
    // prompt marks, for one) runs in any of the three.
    let environment = |arena: &Path| {
        vec![
            ("CASE_OUT".to_owned(), told(arena)),
            ("TERM_PROGRAM".to_owned(), String::new()),
        ]
    };
    let ready = "kr-ready";

    // The person's own shell: the same binary and configuration, with none of our entry.
    let bare_arena = arena("bare");
    let mut bare = Session::start_unmanaged(
        &package,
        &environment(&bare_arena),
        Profile {
            entry: false,
            ..Profile::ORDINARY
        },
    );
    assert!(bare.answered(ready), "{}", bare.terminal_output());
    let bare = put_the_probe_to(&mut bare, kind, &bare_arena);

    // A shell that is not a root shell, with the entry in its startup.
    let outside_arena = arena("outside");
    let mut outside =
        Session::start_unmanaged(&package, &environment(&outside_arena), Profile::ORDINARY);
    assert!(outside.answered(ready), "{}", outside.terminal_output());
    let outside = put_the_probe_to(&mut outside, kind, &outside_arena);

    // The root shell of a session, with the same entry.
    let inside_arena = arena("inside");
    let mut inside = Session::start_with(&package, &environment(&inside_arena));
    inside.first_prompt();
    inside.forget_events();
    assert!(inside.answered(ready), "{}", inside.terminal_output());
    let inside = put_the_probe_to(&mut inside, kind, &inside_arena);

    let is_root = probe(kind).is_root;
    assert_eq!(
        inside.root, is_root,
        "the root shell is the one the integration is for"
    );
    assert_ne!(
        bare.root, is_root,
        "a shell with no entry is not a root shell"
    );
    assert_ne!(
        outside.root, is_root,
        "a shell that is not a root shell is not made one by the entry in its startup"
    );

    assert_stock_accepting(kind, &bare.accepting, "the person's own shell", false);
    assert_stock_accepting(
        kind,
        &outside.accepting,
        "the shell outside a session",
        false,
    );
    assert_stock_accepting(kind, &inside.accepting, "the root shell", true);
    assert!(
        !bare.bindings.is_empty() && bare.bindings == outside.bindings,
        "the entry changed what the shell outside a session holds bound:\n{}\n--- against ---\n{}",
        outside.bindings,
        bare.bindings
    );
    assert_eq!(
        keys_and_functions(kind, &inside.bindings),
        keys_and_functions(kind, &bare.bindings),
        "the root shell binds a key to something the shell does not"
    );
    assert!(
        kind == ShellKind::Fish || bare.marks.is_empty(),
        "the person's own shell writes marks: {:?}",
        bare.marks
    );
    assert_eq!(
        outside.marks, bare.marks,
        "the shell outside a session wrote marks the shell does not write by itself"
    );
    assert_eq!(
        inside.marks, bare.marks,
        "the root shell wrote marks the shell does not write by itself"
    );
}

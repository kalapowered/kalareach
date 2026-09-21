//! What each package's shell is told, in its own language.
//!
//! The expectations these cases assert come from the committed corpus and are the same for every
//! package. What differs is how a reader is put into the state the corpus names: one shell turns on
//! its own end-of-file setting with `setopt`, another with `set -o`, and two have no such setting
//! at all. Each difference is stated here once, beside the reason, so a case reads as one
//! behaviour rather than as four.

#![allow(dead_code)]

use std::path::Path;

use kr_shell_integration::contract::qualification::{DetachExclusion, ShellKind};

/// The flag a reader raises while it waits inside an operation of the person's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingFlag {
    MultikeySequence,
    ViMotion,
    QuotedInsertion,
}

/// How this reader is left waiting for another key, and what it says about itself while it is.
pub struct PendingWait {
    /// A command that has to run first, and the marker it prints.
    pub prepare: Option<(&'static str, &'static str)>,
    /// What to type to leave the reader inside the wait.
    pub enter: &'static [u8],
    /// The flag the reader raises while it waits.
    pub flag: PendingFlag,
    /// Whether the partial-key queue is the one that holds the input.
    pub partial_key_queue: bool,
    /// The bytes a cancellation reports dropping here, where this session owns what is counted.
    pub discarded_bytes: Option<u32>,
}

/// One state the detach condition excludes, and how this shell is put into it.
pub struct ExclusionDrive {
    pub exclusion: DetachExclusion,
    /// What to type before offering the gesture.
    pub setup: &'static [&'static [u8]],
    /// What to type afterwards to leave the state.
    pub teardown: &'static [&'static [u8]],
    /// A command that has to run first, and the marker it prints.
    pub prepare: Option<(&'static str, &'static str)>,
}

pub const CTRL_C: &[u8] = &[0x03];
pub const CTRL_D: &[u8] = &[0x04];
pub const CTRL_G: &[u8] = &[0x07];
pub const CTRL_R: &[u8] = &[0x12];
pub const CTRL_T: &[u8] = &[0x14];
pub const CTRL_U: &[u8] = &[0x15];
pub const CTRL_V: &[u8] = &[0x16];
pub const ESCAPE: &[u8] = &[0x1b];
pub const ALT_TWO: &[u8] = &[0x1b, b'2'];
pub const CTRL_RIGHT_BRACKET: &[u8] = &[0x1d];

/// What each shell is told, and what it cannot be told at all.
pub struct Dialect {
    /// Prints [`Self::bootstrap_gone`] when neither bootstrap value is exported.
    pub bootstrap_probe: &'static str,
    /// What that prints when both are gone.
    pub bootstrap_gone: &'static str,
    /// Prints `kr-config=1` when the person's own configuration survived.
    pub user_configuration_probe: &'static str,
    /// Turns on the shell's own "an end of file does not end me" setting, printing `kr-ready`.
    pub ignore_eof_on: Option<&'static str>,
    /// Reports that setting afterwards as `kr-ignoreeof=on`.
    pub ignore_eof_report: Option<&'static str>,
    /// Opens a continuation reader, and closes it printing `kr-continuation-ok`.
    pub continuation: Option<(&'static str, &'static str)>,
    /// Changes the terminal's own end-of-file character, printing `kr-veof-set`.
    pub veof_change: Option<&'static str>,
    /// Takes it away, printing `kr-veof-undef`.
    pub veof_disable: Option<&'static str>,
    /// A command that prints the two markers of a launch's literal argument vector.
    pub launch_expectation: &'static str,
    /// A line the shell works out for itself, in three parts: what is typed first, what is typed
    /// after the cancellations, and what the shell prints. The answer is in neither half of the
    /// typing, so seeing it proves the line ran rather than that the keystrokes were echoed.
    pub arithmetic: (&'static str, &'static str, &'static str),
    /// Whether this editor's vi bindings accumulate a count of their own.
    pub vi_counts: bool,
    /// How many of the corpus's exclusions this reader can actually be put into.
    pub driven_exclusions: usize,
    /// Whether this editor reaches its own reader-thread queue only when the reader steps.
    ///
    /// The published API of one of these editors has no asynchronous editing method, which section
    /// 7 says in as many words. Its host delivers the module's signal to the reader's thread when
    /// the reader comes out of its key wait, so a request that arrives at a parked reader is
    /// answered at its next step and a line installed there is accepted at the same one. The
    /// session gives the reader that step, which a person at the keyboard gives it by typing.
    pub answers_at_the_next_step: bool,
    /// Whether a line this editor is not yet reading is lost to it.
    ///
    /// An editor that takes the terminal out of its own line mode reads a typed return as the key
    /// it binds. A line typed before it takes the terminal goes through the terminal's own line
    /// discipline instead, which delivers a line feed, and this editor binds nothing to that. A
    /// person types at a drawn prompt, and against such an editor this session does the same.
    pub types_at_the_prompt: bool,
}

/// A command that prints `marker` out of pieces it puts together as it runs.
///
/// Every shell here echoes the line that is typed at it, so a command that spells its own marker
/// out proves nothing: the word is on the screen whether the command ran or not. Splitting it into
/// two arguments and letting the shell join them means the word appears only once something has
/// run, which is what these checks are about.
///
/// # Panics
///
/// Panics on a marker that cannot be split in two, which is a marker no check should be using.
#[must_use]
pub fn print_assembled(kind: ShellKind, marker: &str) -> String {
    let split = marker.rfind('-').map_or(marker.len() / 2, |at| at + 1);
    assert!(
        split > 0 && split < marker.len() && !marker.contains('\''),
        "{marker:?} cannot be printed from two pieces"
    );
    let (head, tail) = marker.split_at(split);
    match kind {
        ShellKind::PowerShell => format!("Write-Output ('{head}' + '{tail}')"),
        _ => format!("printf '%s%s\\n' '{head}' '{tail}'"),
    }
}

/// The child probe: the same package started as a child of the managed root shell.
#[must_use]
pub fn child_probe(kind: ShellKind, executable: &Path) -> String {
    match kind {
        ShellKind::PowerShell => format!(
            "& '{}' -NoLogo -NoProfile -Command 'if ($env:KR_SHELL_BRIDGE) {{ \"kr-child=[$env:KR_SHELL_BRIDGE]\" }} else {{ \"kr-child=[unset]\" }}'",
            executable.display()
        ),
        ShellKind::Fish => format!(
            "{} -c 'echo kr-child=[(set -q KR_SHELL_BRIDGE; and echo $KR_SHELL_BRIDGE; or echo unset)]'",
            executable.display()
        ),
        _ => format!(
            "{} -c 'echo kr-child=[${{KR_SHELL_BRIDGE:-unset}}]'",
            executable.display()
        ),
    }
}

/// Everything this package's shell is told.
#[must_use]
pub fn dialect(kind: ShellKind) -> Dialect {
    match kind {
        ShellKind::Zsh => Dialect {
            bootstrap_probe: "echo \"kr-endpoint=[${KR_SHELL_BRIDGE:-unset}] kr-secret=[${KR_SHELL_BRIDGE_SECRET:-unset}]\"",
            bootstrap_gone: "kr-endpoint=[unset] kr-secret=[unset]",
            user_configuration_probe: "echo kr-config=$KR_TEST_USER_CONFIGURATION",
            ignore_eof_on: Some("setopt ignoreeof; printf '%s%s\\n' kr- ready"),
            ignore_eof_report: Some(
                "echo kr-ignoreeof=$([[ -o ignoreeof ]] && echo on || echo off)",
            ),
            continuation: Some((
                "echo 'kr-continuation",
                "' >/dev/null; printf '%s%s\\n' kr-continuation- ok",
            )),
            veof_change: Some("stty eof ^G; printf '%s%s\\n' kr-veof- set"),
            veof_disable: Some("stty eof undef; printf '%s%s\\n' kr-veof- undef"),
            launch_expectation: "kr launch ok|$(echo substituted)|",
            arithmetic: ("echo kr-$((6*7))", "-ok", "kr-42-ok"),
            vi_counts: false,
            driven_exclusions: 9,
            answers_at_the_next_step: false,
            types_at_the_prompt: false,
        },
        ShellKind::Bash => Dialect {
            bootstrap_probe: "echo \"kr-endpoint=[${KR_SHELL_BRIDGE:-unset}] kr-secret=[${KR_SHELL_BRIDGE_SECRET:-unset}]\"",
            bootstrap_gone: "kr-endpoint=[unset] kr-secret=[unset]",
            user_configuration_probe: "echo kr-config=$KR_TEST_USER_CONFIGURATION",
            ignore_eof_on: Some("set -o ignoreeof; printf '%s%s\\n' kr- ready"),
            ignore_eof_report: Some(
                "case $- in *o*) :;; esac; echo kr-ignoreeof=$(set -o | grep -q 'ignoreeof.*on' && echo on || echo off)",
            ),
            continuation: Some((
                "echo 'kr-continuation",
                "' >/dev/null; printf '%s%s\\n' kr-continuation- ok",
            )),
            veof_change: Some("stty eof ^G; printf '%s%s\\n' kr-veof- set"),
            veof_disable: Some("stty eof undef; printf '%s%s\\n' kr-veof- undef"),
            launch_expectation: "kr launch ok|$(echo substituted)|",
            arithmetic: ("echo kr-$((6*7))", "-ok", "kr-42-ok"),
            vi_counts: false,
            driven_exclusions: 9,
            answers_at_the_next_step: false,
            types_at_the_prompt: false,
        },
        ShellKind::Fish => Dialect {
            bootstrap_probe: "echo \"kr-endpoint=[$(set -q KR_SHELL_BRIDGE; and echo $KR_SHELL_BRIDGE; or echo unset)] kr-secret=[$(set -q KR_SHELL_BRIDGE_SECRET; and echo $KR_SHELL_BRIDGE_SECRET; or echo unset)]\"",
            bootstrap_gone: "kr-endpoint=[unset] kr-secret=[unset]",
            user_configuration_probe: "echo kr-config=$KR_TEST_USER_CONFIGURATION",
            // This shell has no end-of-file setting of its own; the editor's own answer to the
            // gesture outside the detach condition is what `delete-or-exit` does with it.
            ignore_eof_on: None,
            ignore_eof_report: None,
            // Its editor edits a whole command in one buffer, so it starts no continuation reader.
            continuation: None,
            veof_change: Some("stty eof ^G; printf '%s%s\\n' kr-veof- set"),
            veof_disable: Some("stty eof undef; printf '%s%s\\n' kr-veof- undef"),
            launch_expectation: "kr launch ok|(echo substituted)|",
            arithmetic: ("echo kr-(math 6 x 7)", "-ok", "kr-42-ok"),
            vi_counts: true,
            driven_exclusions: 7,
            answers_at_the_next_step: false,
            types_at_the_prompt: false,
        },
        ShellKind::PowerShell => Dialect {
            // Short on purpose: every character of a command is drawn again by this editor as it
            // is typed, so a long line is a slow one.
            bootstrap_probe: "\"kr-bootstrap=[$env:KR_SHELL_BRIDGE][$env:KR_SHELL_BRIDGE_SECRET]\"",
            bootstrap_gone: "kr-bootstrap=[][]",
            user_configuration_probe: "\"kr-config=$KR_TEST_USER_CONFIGURATION\"",
            ignore_eof_on: None,
            ignore_eof_report: None,
            continuation: None,
            // The gesture on this editor is a chord the worker configures, so the line discipline's
            // own character is not what it follows.
            veof_change: None,
            veof_disable: None,
            launch_expectation: "kr launch ok|$(echo substituted)|",
            arithmetic: ("Write-Output \"kr-$(6*7)", "-ok\"", "kr-42-ok"),
            vi_counts: false,
            driven_exclusions: 1,
            answers_at_the_next_step: true,
            types_at_the_prompt: true,
        },
    }
}

/// The states this reader can actually be put into, with what puts it there.
#[must_use]
pub fn exclusion_drives(kind: ShellKind) -> Vec<ExclusionDrive> {
    match kind {
        ShellKind::Zsh | ShellKind::Bash => vec![
            ExclusionDrive {
                exclusion: DetachExclusion::BufferNotEmpty,
                setup: &[b"kr"],
                teardown: &[],
                prepare: None,
            },
            ExclusionDrive {
                exclusion: DetachExclusion::QuotedInsertion,
                setup: &[CTRL_V],
                teardown: &[],
                prepare: None,
            },
            ExclusionDrive {
                exclusion: DetachExclusion::MultikeySequence,
                setup: &[ESCAPE],
                teardown: &[],
                prepare: None,
            },
            ExclusionDrive {
                exclusion: DetachExclusion::NumericArgument,
                setup: &[ESCAPE, b"2"],
                teardown: &[],
                prepare: None,
            },
            ExclusionDrive {
                exclusion: DetachExclusion::Search,
                setup: &[CTRL_R],
                teardown: &[CTRL_G],
                prepare: None,
            },
            ExclusionDrive {
                exclusion: DetachExclusion::Paste,
                setup: &[b"\x1b[200~"],
                teardown: &[b"\x1b[201~"],
                prepare: None,
            },
        ],
        ShellKind::Fish => vec![
            ExclusionDrive {
                exclusion: DetachExclusion::BufferNotEmpty,
                setup: &[b"kr"],
                teardown: &[],
                prepare: None,
            },
            ExclusionDrive {
                // This reader resolves a lone escape on its own timer, so the sequence it waits
                // inside indefinitely is one the person bound.
                exclusion: DetachExclusion::MultikeySequence,
                setup: &[b"j"],
                teardown: &[b"k"],
                prepare: Some(("bind j,k cancel; echo kr-bound-seq", "kr-bound-seq")),
            },
            ExclusionDrive {
                exclusion: DetachExclusion::Search,
                setup: &[CTRL_R],
                teardown: &[ESCAPE],
                prepare: None,
            },
            ExclusionDrive {
                exclusion: DetachExclusion::Paste,
                setup: &[b"\x1b[200~"],
                teardown: &[b"\x1b[201~"],
                prepare: None,
            },
        ],
        ShellKind::PowerShell => vec![ExclusionDrive {
            exclusion: DetachExclusion::BufferNotEmpty,
            setup: &[b"kr"],
            teardown: &[],
            prepare: None,
        }],
    }
}

/// How this reader is left waiting for the rest of a key sequence.
#[must_use]
pub fn pending_wait(kind: ShellKind) -> Option<PendingWait> {
    match kind {
        // Both readers wait for the rest of an escape sequence until another key arrives.
        ShellKind::Zsh | ShellKind::Bash => Some(PendingWait {
            prepare: None,
            enter: ESCAPE,
            flag: PendingFlag::MultikeySequence,
            partial_key_queue: true,
            // What these two readers count is their own package's, and asserted with it.
            discarded_bytes: None,
        }),
        // This reader resolves a lone escape on its own timer, so the sequence it waits inside
        // indefinitely is one the person bound.
        ShellKind::Fish => Some(PendingWait {
            prepare: Some(("bind j,k cancel; echo kr-bound-seq", "kr-bound-seq")),
            enter: b"j",
            flag: PendingFlag::MultikeySequence,
            partial_key_queue: true,
            // The one key the sequence is waiting behind, which arrived as one byte.
            discarded_bytes: Some(1),
        }),
        // This editor runs its own nested read for the operations that wait for another key, and
        // nothing of this package's runs on the reader's thread while one of them is running: the
        // mailbox is answered between operations here, and a worker that asks during one waits for
        // the reader's next idle report. There is therefore no wait a cancellation can be measured
        // inside.
        ShellKind::PowerShell => None,
    }
}

/// How this reader is left waiting for a literal character of the person's.
#[must_use]
pub fn quoted_wait(kind: ShellKind) -> Option<PendingWait> {
    match kind {
        ShellKind::Zsh | ShellKind::Bash => Some(PendingWait {
            prepare: None,
            enter: CTRL_V,
            flag: PendingFlag::QuotedInsertion,
            partial_key_queue: false,
            discarded_bytes: None,
        }),
        // This editor has no quoted insertion of its own. `get-key` waits for a literal key in
        // the same way and the bridge reports that state, but nothing in this session puts the
        // reader into it: the key that would start it is claimed by the terminal's own protocol
        // before the editor's binding table sees it.
        ShellKind::Fish => None,
        // This editor has no quoted insertion of its own.
        ShellKind::PowerShell => None,
    }
}

/// The exclusions that need a state this reader cannot be put into, with the reason.
#[must_use]
pub fn not_constructible_here(kind: ShellKind, exclusion: DetachExclusion) -> Option<&'static str> {
    match exclusion {
        // Not a state of a managed root editor at all, but the requirement that the contract
        // applies to this reader: a reader that fails it is some other program.
        DetachExclusion::NotManagedRootEditor => Some("not a state of a managed reader"),
        DetachExclusion::ReadBuiltin => match kind {
            // This editor's reader through the editor ends on the gesture rather than surviving
            // it, so driving it here would end the session it is being observed in.
            ShellKind::Zsh => Some("vared ends on the gesture"),
            // The host's own `Read-Host` does not read through this editor at all.
            ShellKind::PowerShell => Some("Read-Host does not use the editor"),
            _ => None,
        },
        DetachExclusion::ContinuationInput => match kind {
            // Both editors edit a whole command in one buffer and start no continuation reader.
            ShellKind::Fish | ShellKind::PowerShell => Some("one buffer holds the whole command"),
            _ => None,
        },
        DetachExclusion::NumericArgument => match kind {
            // Its numeric argument is a state between keys rather than a wait, and the key that
            // follows it is the one the argument applies to.
            ShellKind::PowerShell => Some("a numeric argument is not a wait"),
            _ => None,
        },
        DetachExclusion::Search => match kind {
            // Its interactive search runs the editor's own nested read, which takes the key
            // itself rather than offering it to a handler.
            ShellKind::PowerShell => Some("the search reads its own keys"),
            _ => None,
        },
        DetachExclusion::MacroInput => match kind {
            ShellKind::Fish => Some("this editor replays no macro of its own"),
            ShellKind::PowerShell => Some("this editor replays no macro of its own"),
            _ => None,
        },
        DetachExclusion::QuotedInsertion => match kind {
            ShellKind::PowerShell => Some("this editor has no quoted insertion"),
            ShellKind::Fish => Some("this editor has no quoted insertion of its own"),
            _ => None,
        },
        DetachExclusion::MultikeySequence => match kind {
            // Its chords are resolved inside the editor's own dispatch, where no handler runs.
            ShellKind::PowerShell => Some("a pending chord is not visible to a handler"),
            _ => None,
        },
        DetachExclusion::Paste => match kind {
            // Its paste is one operation rather than a state the reader waits in.
            ShellKind::PowerShell => Some("a paste is not a state this reader waits in"),
            _ => None,
        },
        DetachExclusion::ViMotion => match kind {
            // Its character search takes the keys it needs before any handler of this package's
            // sees them, so the state it waits in is not one this session can offer a gesture to.
            ShellKind::PowerShell => Some("the character search reads its own keys"),
            _ => None,
        },
        _ => None,
    }
}

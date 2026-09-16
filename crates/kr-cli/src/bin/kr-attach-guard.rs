//! The out-of-process terminal restoration guard.
//!
//! This process exists to outlive `kr attach` by a few milliseconds. It holds two things: a handle
//! on the user's terminal, and the complete state that terminal had before the attach began. Then
//! it waits on a pipe whose other end only the attach process holds.
//!
//! * End of file means the attach process is gone, however it went. The terminal is restored.
//! * A release byte means the attach process restored the terminal itself and this one should
//!   leave without touching anything.
//!
//! It confirms that it is holding the state before the attach process changes anything, so there is
//! no window in which the terminal is raw and nothing is holding its previous state.
//!
//! It runs in its own process group, so a signal aimed at the attach process's group does not reach
//! it. By the time it acts that group is in the background, and a background process that changes
//! the terminal is stopped by `SIGTTOU`. Catching that signal is not enough: the call still fails.
//! The guard **ignores** it instead, which is what lets the change through.
//!
//! It never promises to survive the terminal emulator itself: if that is gone there is nothing to
//! restore.

use std::io::{Read as _, Write as _};
use std::process::ExitCode;

use clap::Parser;
use kr_cli::attach::{GUARD_BEGIN, GUARD_KEYBOARD, GUARD_READY, GUARD_RELEASE};
#[cfg(unix)]
use kr_cli::terminal::RESET_SEQUENCES;
use kr_cli::terminal::{KEYBOARD_BEGIN_SEQUENCES, KeyboardState, SavedModes};

#[derive(Debug, Parser)]
#[command(
    name = "kr-attach-guard",
    version,
    about = "Restores a terminal when the attach process that owned it is gone."
)]
struct Arguments {
    /// The terminal state to restore.
    #[arg(long)]
    modes: String,
}

fn main() -> ExitCode {
    let arguments = Arguments::parse();
    let Ok(saved) = SavedModes::decode(&arguments.modes) else {
        return ExitCode::FAILURE;
    };

    // Ignored, not caught. A background process that changes the terminal is stopped by `SIGTTOU`
    // unless the signal is ignored; a handler that merely records the signal leaves the call
    // failing. This is set before anything is written back, and before readiness is reported, so
    // there is no moment at which the guard is holding state it could not restore.
    if kr_cli::platform::ignore_background_write_signal().is_err() {
        return ExitCode::FAILURE;
    }

    // Standard error is the readiness pipe, standard input is the release pipe, and standard
    // output is the terminal. Reporting readiness here rather than at startup means the attach
    // process learns that the guard is armed, not merely that it was spawned.
    let mut ready = std::io::stderr();
    if ready.write_all(&[GUARD_READY]).is_err() || ready.flush().is_err() {
        return ExitCode::FAILURE;
    }

    // What the attach process has to say, until it says it is done or it is gone. It sends the
    // keyboard protocols this terminal had once it has read them, which it cannot do before this
    // guard is holding the terminal's modes; it asks for the keyboard entry to be opened when it
    // is about to forward; and then it sends either the release byte or nothing at all.
    let mut keyboard = None;
    let mut pushed = false;
    let mut line = Vec::new();
    let mut byte = [0_u8; 1];
    let mut input = std::io::stdin();
    let mut released = false;
    loop {
        match input.read(&mut byte) {
            // The attach process is gone, however it went. The terminal is restored.
            Ok(0) | Err(_) => break,
            Ok(_) => match byte[0] {
                // It restored the terminal's modes itself. What this guard pushed is still this
                // guard's to pop, so it does that below and then leaves.
                GUARD_RELEASE => {
                    released = true;
                    break;
                }
                b'\n' => {
                    if let Some(state) = line
                        .strip_prefix(&[GUARD_KEYBOARD])
                        .and_then(|rest| std::str::from_utf8(rest).ok())
                        .and_then(|text| KeyboardState::decode(text).ok())
                    {
                        keyboard = Some(state);
                    }
                    // The entry that holds what this terminal had negotiated. This guard opens it
                    // rather than the attach process, because a push and the pop that answers it
                    // are one pair and only one process is certain to be there for both.
                    if line.first() == Some(&GUARD_BEGIN) && !pushed {
                        let mut terminal = std::io::stdout();
                        if terminal.write_all(KEYBOARD_BEGIN_SEQUENCES).is_err()
                            || terminal.flush().is_err()
                        {
                            return ExitCode::FAILURE;
                        }
                        pushed = true;
                        if ready.write_all(&[GUARD_READY]).is_err() || ready.flush().is_err() {
                            return ExitCode::FAILURE;
                        }
                    }
                    line.clear();
                }
                // A line longer than any message this protocol has is not one of them.
                other if line.len() < 64 => line.push(other),
                _ => line.clear(),
            },
        }
    }

    // A released guard has had the modes put back for it and only owes the keyboard entry; one
    // whose process is gone owes everything.
    let restored = if released {
        !pushed || give_back_the_keyboard(keyboard.as_ref())
    } else {
        restore(
            &saved,
            pushed.then_some(keyboard.as_ref()).flatten(),
            pushed,
        )
    };
    if restored {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Pops the entry this guard pushed, and writes back whatever the terminal had reported.
#[cfg(unix)]
fn give_back_the_keyboard(keyboard: Option<&KeyboardState>) -> bool {
    let terminal = std::io::stdout();
    let mut handle = terminal.lock();
    let sequences = keyboard.copied().unwrap_or(KeyboardState::EMPTY);
    handle.write_all(&sequences.cleanup_sequences()).is_ok() && handle.flush().is_ok()
}

/// Pops the entry this guard pushed, and writes back whatever the terminal had reported.
#[cfg(not(unix))]
fn give_back_the_keyboard(keyboard: Option<&KeyboardState>) -> bool {
    let mut handle = std::io::stdout();
    let sequences = keyboard.copied().unwrap_or(KeyboardState::EMPTY);
    handle.write_all(&sequences.cleanup_sequences()).is_ok() && handle.flush().is_ok()
}

#[cfg(unix)]
fn restore(saved: &SavedModes, keyboard: Option<&KeyboardState>, pushed: bool) -> bool {
    use rustix::termios::OptionalActions;

    let terminal = std::io::stdout();
    let Ok(mut modes) = rustix::termios::tcgetattr(&terminal) else {
        return false;
    };
    saved.apply(&mut modes);
    for _ in 0..8 {
        match rustix::termios::tcsetattr(&terminal, OptionalActions::Flush, &modes) {
            Ok(()) => {
                let mut handle = terminal.lock();
                let _ = handle.write_all(RESET_SEQUENCES);
                // The entry this guard opened, given back, together with whatever the terminal
                // itself reported before the attachment began. A guard that never opened one
                // leaves the keyboard protocols alone: nothing it is cleaning up had begun to
                // change them.
                if pushed {
                    let sequences = keyboard.copied().unwrap_or(KeyboardState::EMPTY);
                    let _ = handle.write_all(&sequences.cleanup_sequences());
                }
                let _ = handle.flush();
                return true;
            }
            // An interrupted call is retried. Anything else is a terminal this guard cannot reach:
            // the emulator has gone, and there is nothing left to restore.
            Err(rustix::io::Errno::INTR) => {}
            Err(_) => return false,
        }
    }
    false
}

#[cfg(not(unix))]
fn restore(saved: &SavedModes, keyboard: Option<&KeyboardState>, pushed: bool) -> bool {
    let Ok(terminal) = kr_cli::terminal::ControllingTerminal::open() else {
        return false;
    };
    let keyboard = pushed.then(|| keyboard.copied().unwrap_or(KeyboardState::EMPTY));
    terminal.restore(saved, keyboard.as_ref()).is_ok()
}

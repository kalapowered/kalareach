//! Holding a window open after a command failed.
//!
//! A terminal profile starts `kr new --attach --hold-on-failure`, and a window that closes the
//! moment its only command fails shows nobody the error. When the command fails, the failure is
//! printed as it always is and then this waits for one key, so the window stays until it has been
//! read.

use std::io::{IsTerminal as _, Read as _, Write as _};

use crate::terminal::{ControllingTerminal, ScreenModes};

/// What a held window says when the wait begins. The terminal is in raw mode, so the line ends in
/// both a carriage return and a line feed.
const HOLD_LINE: &str =
    "kr: this window stays open so the error above can be read; press any key to close it\r\n";

/// Waits for one key at the terminal, if this command is run at one.
///
/// Nothing waits when standard input or standard output is not a terminal, because a script that
/// reads the output of `kr new` must not stop for a key nobody will press. The terminal is put into
/// single-key mode with its signal keys off, so Ctrl-C is a key like another, what was typed
/// before the wait began is thrown away, and one key, the end of the input or a failure to read it
/// ends the wait. The terminal's modes are put back on every path out. A hangup or a terminate
/// signal during the wait ends the process the way that signal would have, after the modes are
/// back; closing the window is such a hangup.
///
/// A terminal that cannot be put into the mode is left alone and the wait is skipped: the failure
/// has been printed, and the command exits with its status.
pub async fn for_a_key() {
    if !(std::io::stdin().is_terminal() && crate::output::is_terminal()) {
        return;
    }
    // Registered before the terminal is touched, so a signal that comes while the modes are
    // changed is caught and the modes are put back, never missed.
    let mut ending = Ending::register();
    let Ok(terminal) = ControllingTerminal::open() else {
        return;
    };
    let Ok(saved) = terminal.enter_raw_mode() else {
        return;
    };
    let restored = PutBack(|| {
        let _ = terminal.restore(&saved, None, &ScreenModes::UNASKED);
    });
    if terminal.discard_input().is_err() {
        return;
    }
    {
        let mut screen = terminal.handle();
        if screen.write_all(HOLD_LINE.as_bytes()).is_err() || screen.flush().is_err() {
            return;
        }
    }
    let Ok(mut keys) = terminal.handle().try_clone() else {
        return;
    };
    let read = tokio::task::spawn_blocking(move || {
        let mut buffer = [0_u8; 64];
        loop {
            match keys.read(&mut buffer) {
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                _ => break,
            }
        }
    });
    tokio::select! {
        _ = read => {}
        signal = ending.arrived() => {
            drop(restored);
            end_by(signal);
        }
    }
}

/// Ends this process by `signal`, after the terminal is back.
#[cfg(unix)]
fn end_by(signal: std::os::raw::c_int) {
    crate::platform::end_by_signal(signal);
}

/// Windows has no such signals, so none arrives to end the process by.
#[cfg(not(unix))]
const fn end_by(_signal: i32) {}

/// Runs the closure it holds when it is dropped.
struct PutBack<F: FnMut()>(F);

impl<F: FnMut()> Drop for PutBack<F> {
    fn drop(&mut self) {
        (self.0)();
    }
}

/// The signals that end the wait: a hangup and a terminate.
#[cfg(unix)]
struct Ending {
    hangup: Option<tokio::signal::unix::Signal>,
    terminate: Option<tokio::signal::unix::Signal>,
}

#[cfg(unix)]
impl Ending {
    /// Starts catching both. One that cannot be caught keeps its default action.
    fn register() -> Self {
        use tokio::signal::unix::{SignalKind, signal};

        Self {
            hangup: signal(SignalKind::hangup()).ok(),
            terminate: signal(SignalKind::terminate()).ok(),
        }
    }

    /// Waits for one of them and says which came.
    async fn arrived(&mut self) -> std::os::raw::c_int {
        async fn next(signal: &mut Option<tokio::signal::unix::Signal>) {
            match signal {
                Some(signal) => {
                    signal.recv().await;
                }
                None => std::future::pending().await,
            }
        }

        tokio::select! {
            () = next(&mut self.hangup) => libc::SIGHUP,
            () = next(&mut self.terminate) => libc::SIGTERM,
        }
    }
}

/// Windows has no such signals: a console that is closed ends the process.
#[cfg(not(unix))]
struct Ending;

#[cfg(not(unix))]
impl Ending {
    const fn register() -> Self {
        Self
    }

    async fn arrived(&mut self) -> i32 {
        std::future::pending().await
    }
}

//! The host this application's commands go to when it is not the one on this machine.
//!
//! A phone has no host of its own. It pairs with one, and from then on the commands the page calls
//! are asked of that host over the connection this device is authorised for, with the rights its
//! grant carries and no more. The host the person chose is remembered across runs; a connection
//! that ends is taken up again, after a pause that grows while the host does not answer, until the
//! person chooses another.
//!
//! The application says what is true at each moment: connected, with the rights, or not connected,
//! with why. A command made while it is not connected is refused as such, and none is sent down a
//! connection that is gone.

use std::time::{Duration, Instant};

use kr_client::pairing::paired::PairedHost;
use tauri::{AppHandle, Emitter as _, Manager as _, Runtime};

use crate::connection::{self, CONNECTION_EVENT, Connection, ConnectionState};
use crate::error::{CommandError, Result};
use crate::state::AppState;

/// The pause before the first attempt to take a lost connection up again.
const FIRST_RETRY: Duration = Duration::from_millis(250);

/// The longest pause between attempts while the host does not answer.
const LONGEST_RETRY: Duration = Duration::from_secs(30);

/// How long [`use_host`] waits for the first attempt before it answers with where things stand.
const FIRST_ATTEMPT_WITHIN: Duration = Duration::from_secs(60);

/// How long a connection must last before the next loss is treated as a first one, and not as a
/// host that accepts and then closes.
const LASTED: Duration = Duration::from_secs(10);

/// The pause after `failures` attempts in a row that ended without a connection that lasted.
fn pause(failures: u32) -> Duration {
    FIRST_RETRY
        .saturating_mul(2_u32.saturating_pow(failures.min(16)))
        .min(LONGEST_RETRY)
}

/// Makes `host` the one this application's commands go to, and says where that stands once the
/// first attempt to reach it has ended.
///
/// The choice is kept for the next run before it is made, so one that could not be kept is not made
/// and the host in use stays as it was. The connection is kept: when it ends it is taken up again,
/// and the application says it is not connected for as long as it is not.
///
/// # Errors
///
/// Returns a local failure when this computer's pairing records could not be opened or the choice
/// could not be kept.
pub async fn use_host<R: Runtime>(app: &AppHandle<R>, host: PairedHost) -> Result<ConnectionState> {
    let state = app.state::<AppState>();
    let device = state.device()?;
    let (first, reached) = tokio::sync::oneshot::channel();
    // One step: the host chosen before is let go, this choice is kept, and the task that keeps its
    // connection starts, so no task of an earlier choice can put its connection back.
    state.choose_host(
        "this application is reaching the host you chose",
        |choice| {
            device.use_host(host.host_device_id)?;
            Ok(tauri::async_runtime::spawn(keep(
                app.clone(),
                host,
                choice,
                Some(first),
            )))
        },
    )?;
    // The page is told at once that the host it was talking to is no longer the one in use.
    let _ = app.emit(CONNECTION_EVENT, state.connection_state());
    let _ = tokio::time::timeout(FIRST_ATTEMPT_WITHIN, reached).await;
    Ok(state.connection_state())
}

/// Takes up the host this application's commands went to the last time, when there was one and
/// this computer is still paired with it. Nothing is waited for.
pub fn resume<R: Runtime>(app: &AppHandle<R>) {
    let state = app.state::<AppState>();
    let Ok(device) = state.device() else {
        return;
    };
    if let Some(host) = device.host_in_use() {
        let _ = state.choose_host(
            "this application is reaching the host you chose",
            |choice| {
                Ok(tauri::async_runtime::spawn(keep(
                    app.clone(),
                    host,
                    choice,
                    None,
                )))
            },
        );
    }
}

/// Keeps a connection to `host` for `choice`: reaches it, forwards what it publishes, and when it
/// ends reaches it again. `first` is told once the first attempt has ended either way.
///
/// A task ends as soon as another host is chosen: it installs a connection, or records that it has
/// none, only while its own choice is the one in force.
async fn keep<R: Runtime>(
    app: AppHandle<R>,
    host: PairedHost,
    choice: u64,
    mut first: Option<tokio::sync::oneshot::Sender<()>>,
) {
    let mut failures: u32 = 0;
    loop {
        let state = app.state::<AppState>();
        let Ok(device) = state.device() else {
            return;
        };
        let outcome = Connection::paired(&device, &host).await;
        match outcome {
            Ok(connection) => {
                let session = connection.session();
                if !state.connected_for(choice, connection) {
                    return;
                }
                let _ = app.emit(CONNECTION_EVENT, state.connection_state());
                if let Some(first) = first.take() {
                    let _ = first.send(());
                }
                let began = Instant::now();
                connection::forward_events(app.clone(), session).await;
                // A connection that did not last is not a recovery: a host that accepts and then
                // closes is waited for as one that does not answer.
                failures = if began.elapsed() >= LASTED {
                    0
                } else {
                    failures.saturating_add(1)
                };
            }
            Err(error) => {
                failures = failures.saturating_add(1);
                if !state.disconnected_for(choice, error.message) {
                    return;
                }
                let _ = app.emit(CONNECTION_EVENT, state.connection_state());
                if let Some(first) = first.take() {
                    let _ = first.send(());
                }
            }
        }
        tokio::time::sleep(pause(failures)).await;
    }
}

/// What the page is refused with when it names a host this computer is not paired with.
pub fn unknown_host() -> CommandError {
    CommandError::invalid("this computer is not paired with that host")
}

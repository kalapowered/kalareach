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

use std::time::Duration;

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

/// The pause after `failures` attempts in a row that ended without a connection that lasted.
fn pause(failures: u32) -> Duration {
    FIRST_RETRY
        .saturating_mul(2_u32.saturating_pow(failures.min(16)))
        .min(LONGEST_RETRY)
}

/// Makes `host` the one this application's commands go to, and says where that stands once the
/// first attempt to reach it has ended.
///
/// The choice is remembered. The connection is kept: when it ends it is taken up again, and the
/// application says it is not connected for as long as it is not.
///
/// # Errors
///
/// Returns a local failure when this computer's pairing records could not be opened.
pub async fn use_host<R: Runtime>(app: &AppHandle<R>, host: PairedHost) -> Result<ConnectionState> {
    let state = app.state::<AppState>();
    let device = state.device()?;
    // What is held for the host before this one is let go before anything else is asked of it.
    state.end_supervision();
    state.disconnected("this application is reaching the host you chose");
    device.use_host(host.host_device_id);
    let (first, reached) = tokio::sync::oneshot::channel();
    let handle = tauri::async_runtime::spawn(keep(app.clone(), host, Some(first)));
    state.supervise(handle);
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
        let handle = tauri::async_runtime::spawn(keep(app.clone(), host, None));
        state.supervise(handle);
    }
}

/// Keeps a connection to `host`: reaches it, forwards what it publishes, and when it ends reaches
/// it again. `first` is told once the first attempt has ended either way.
async fn keep<R: Runtime>(
    app: AppHandle<R>,
    host: PairedHost,
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
                failures = 0;
                let session = connection.session();
                state.connected(connection);
                let _ = app.emit(CONNECTION_EVENT, state.connection_state());
                if let Some(first) = first.take() {
                    let _ = first.send(());
                }
                connection::forward_events(app.clone(), session).await;
            }
            Err(error) => {
                failures = failures.saturating_add(1);
                state.disconnected(error.message);
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

//! The host this application's commands go to when it is not the one on this machine.
//!
//! A phone has no host of its own. It pairs with one, and from then on the commands the page calls
//! are asked of that host over the connection this device is authorised for, with the rights its
//! grant carries and no more. The host the person chose is remembered across runs; a connection
//! that ends is taken up again ([`connection::keep`]) until the person chooses another.
//!
//! The application says what is true at each moment: connected, with the rights, or not connected,
//! with why. A command made while it is not connected is refused as such, and none is sent down a
//! connection that is gone.

use std::time::Duration;

use kr_client::pairing::paired::PairedHost;
use tauri::{AppHandle, Emitter as _, Manager as _, Runtime};

use crate::connection::{self, Attempt, CONNECTION_EVENT, Connection, ConnectionState};
use crate::error::{CommandError, Result};
use crate::state::AppState;

/// How long [`use_host`] waits for the first attempt before it answers with where things stand.
const FIRST_ATTEMPT_WITHIN: Duration = Duration::from_secs(60);

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
            // The host was found before this lock was taken, and it can have been forgotten since:
            // a record forgotten while this choice waited is not one to connect to.
            if !device.is_paired_with(host.host_device_id)? {
                return Err(unknown_host());
            }
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

/// Forgets `host`: this computer no longer lists it, uses it or tries it, and says where that
/// leaves the connection.
///
/// A local action. It reaches no host, so it works for one that no longer answers, among them one
/// that revoked this computer. When `host` is the one in use its connection ends and none is in
/// use until the person chooses another; any other host's connection is left as it is.
///
/// # Errors
///
/// Returns a local failure when this computer's pairing records could not be changed, and then the
/// host is still listed.
pub fn forget_host<R: Runtime>(app: &AppHandle<R>, host: &PairedHost) -> Result<ConnectionState> {
    let state = app.state::<AppState>();
    let device = state.device()?;
    state.forget_host(
        "no host is in use: you forgot the one this application was reaching",
        || device.forget_host(host.host_device_id),
    )?;
    // The feed of a host this computer no longer reaches is one it no longer reads, so a request
    // it left there is not waited for: nothing could say it is settled.
    if let Ok(settings) = state.settings() {
        settings
            .requests()
            .forget_host(&crate::device::hosts::reference_of(host));
    }
    let _ = app.emit(CONNECTION_EVENT, state.connection_state());
    Ok(state.connection_state())
}

/// Takes up the host this application's commands went to the last time, when there was one and
/// this computer is still paired with it. Nothing is waited for.
pub fn resume<R: Runtime>(app: &AppHandle<R>) {
    let state = app.state::<AppState>();
    let Ok(device) = state.device() else {
        return;
    };
    // The host is read inside the step that makes the choice, so a choice the person made a moment
    // earlier is not replaced by the one read before it.
    let _ = state.choose_host(
        "this application is reaching the host you chose",
        |choice| {
            let host = device
                .host_in_use()
                .ok_or_else(CommandError::not_connected)?;
            Ok(tauri::async_runtime::spawn(keep(
                app.clone(),
                host,
                choice,
                None,
            )))
        },
    );
}

/// Keeps a connection to `host` for `choice`: reaches it, forwards what it publishes, and when it
/// ends reaches it again. `first` is told once the first attempt has ended either way.
async fn keep<R: Runtime>(
    app: AppHandle<R>,
    host: PairedHost,
    choice: u64,
    first: Option<tokio::sync::oneshot::Sender<()>>,
) {
    let kept = app.clone();
    connection::keep(app, choice, first, move || {
        let kept = kept.clone();
        let host = host.clone();
        async move {
            let Ok(device) = kept.state::<AppState>().device() else {
                return Attempt::Nothing;
            };
            match Connection::paired(&device, &host).await {
                Ok(connection) => Attempt::Reached(connection),
                Err(error) => Attempt::Failed(error),
            }
        }
    })
    .await;
}

/// What the page is refused with when it names a host this computer is not paired with.
pub fn unknown_host() -> CommandError {
    CommandError::invalid("this computer is not paired with that host")
}

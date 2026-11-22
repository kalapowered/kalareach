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

use std::sync::Arc;
use std::time::Duration;

use kr_client::pairing::paired::PairedHost;
use tauri::{AppHandle, Manager as _, Runtime};

use crate::connection::{self, Attempt, Connection};
use crate::contact::{Publication, Target};
use crate::device::hosts::{UNNAMED_HOST, reference_of};
use crate::error::{CommandError, Result};
use crate::state::{AppState, Started};

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
/// could not be kept. The step that makes the choice can also stop part of the way, through a
/// panic, which is logged: the failure then says so and sends the person to the connection's state,
/// because the choice may or may not have been made.
pub async fn use_host<R: Runtime>(app: &AppHandle<R>, host: PairedHost) -> Result<Publication> {
    choose(app, host, false).await
}

/// Makes `host` the one this application's commands go to when none is in use and none is reached,
/// and says where that stands once the first attempt to reach it has ended. It is what a computer
/// does with the first host it pairs with.
///
/// Whether a host is in use or reached is read inside the step that makes the choice, under the
/// choice gate, so two changes of the pairing that ask for the first choice together make one:
/// the second finds the host in use and does nothing, instead of choosing again and replacing the
/// connection the first one made.
///
/// # Errors
///
/// Returns a refusal when a host is in use or reached, and then nothing has changed; otherwise
/// what [`use_host`] returns.
pub async fn use_first_host<R: Runtime>(
    app: &AppHandle<R>,
    host: PairedHost,
) -> Result<Publication> {
    choose(app, host, true).await
}

/// The choice [`use_host`] and [`use_first_host`] make; `first_only` is whether it is made only
/// while no host is in use and none is reached.
async fn choose<R: Runtime>(
    app: &AppHandle<R>,
    host: PairedHost,
    first_only: bool,
) -> Result<Publication> {
    let state = app.state::<AppState>();
    let device = state.device()?;
    let (first, reached) = tokio::sync::oneshot::channel();
    // One step: the host chosen before is let go, this choice is kept, and the task that keeps its
    // connection starts, so no task of an earlier choice can put its connection back. The step
    // takes the choice gate and writes the use file, so it runs on a thread of its own and holds
    // no thread of the runtime that the other commands' tasks run on.
    let handle = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        handle
            .state::<AppState>()
            .choose_host("this application is reaching the host you chose", {
                let handle = handle.clone();
                move || {
                    // The host was found before the gate was taken, and it can have been
                    // forgotten since, or paired again, which gives this device another identity
                    // with it: a record that is not the one this choice names is not one to
                    // connect to.
                    if device.paired_as(host.host_device_id)? != Some(host.device_id) {
                        return Err(unknown_host());
                    }
                    if first_only
                        && (device.host_in_use().is_some()
                            || handle.state::<AppState>().connection_state().connected)
                    {
                        return Err(CommandError::refused("a host is already in use"));
                    }
                    device.use_host(host.host_device_id)?;
                    Ok(Started {
                        target: target_of(&host),
                        spawn: Box::new(move |choice| {
                            tauri::async_runtime::spawn(keep(handle, host, choice, Some(first)))
                        }),
                    })
                }
            })
    })
    .await
    .map_err(|error| unfinished(&error))??;
    let _ = tokio::time::timeout(FIRST_ATTEMPT_WITHIN, reached).await;
    Ok(state.connection_state())
}

/// The failure when the step that makes a choice stopped part of the way. The choice may or may not
/// have been made, so the words send the person to the connection's state, which shows the host in
/// use. What stopped the step, a task number and the text of a panic, is for the log.
fn unfinished(error: &tauri::Error) -> CommandError {
    tracing::error!(%error, "the step that makes a choice of host stopped part of the way");
    CommandError::local_failure(
        "the choice of host stopped part of the way; the connection's state shows which host is in use",
    )
}

/// The host a choice names, as the owner holds it: the identity the host has, the one it gave this
/// device in the pairing, what the page names it by and what people call it.
pub(crate) fn target_of(host: &PairedHost) -> Target {
    Target::Paired {
        host: host.host_device_id,
        pairing: host.device_id,
        reference: reference_of(host),
        name: host.name.clone().unwrap_or_else(|| UNNAMED_HOST.to_owned()),
    }
}

/// Forgets `host`: this computer no longer lists it, uses it or tries it, and says where that
/// leaves the connection.
///
/// A local action. It reaches no host, so it works for one that no longer answers, among them one
/// that revoked this computer. When `host` is the one in use its connection ends and none is in use
/// until the person chooses another; any other host's connection is left as it is. What the push
/// desk keeps of the host goes with it, and the owner has let go of what it held of the host. The
/// device's one endpoint then forgets the host: its address lookups and the relays that no other
/// host names. That is the last step, and it runs to its end in a task of its own, so a command
/// that stops waiting for it, or an application that ends in it, leaves nothing else of the
/// forgetting undone, and the host is not left in the endpoint. The only thing that waits for the
/// endpoint is the command's return. The endpoint's forget waits for the introduction of its own
/// host, if a visit or a look is making one, and for the device lock and the transport's turn at
/// the relay map, which all hosts share. It then takes the host out, so a visit or a look that
/// began before the forget does not put the host back, and one that reaches the endpoint after it
/// is refused. When that takes long the host is already gone from the list and the connection event
/// has been sent: only the command's answer is late.
///
/// # Errors
///
/// Returns a local failure when this computer's pairing records could not be changed, and then the
/// host is still listed.
pub async fn forget_host<R: Runtime>(app: &AppHandle<R>, host: &PairedHost) -> Result<Publication> {
    let state = app.state::<AppState>();
    let device = state.device()?;
    state.forget_host(
        host.host_device_id,
        "no host is in use: you forgot the one this application was reaching",
        || device.forget_host(host.host_device_id).map(|_| ()),
    )?;
    // The feed of a host this computer no longer reaches is one it no longer reads, so a request
    // it left there is not waited for: nothing could say it is settled.
    if let Ok(settings) = state.settings() {
        settings
            .requests()
            .forget_host(&crate::device::hosts::reference_of(host));
    }
    // What is kept of a host's notifications goes with the host. The host's own destination stays
    // until its owner removes this device: only the host revokes an authorisation it holds.
    if let Some(desk) = state.push() {
        desk.forgotten(host.host_device_id);
    }
    // What is being sent to the host, and every entry, copy and draft kept for this pairing, goes with
    // it: a host paired again gives this device another identity, so nothing would act on them.
    state.transfers().forgotten(host.device_id);
    state.paired_drafts().forgotten(host.device_id);
    let (link, forgotten) = (Arc::clone(&device.pairing().link), host.clone());
    // A task that panics has left nothing to wait for, and the person's forgetting has been done.
    let _ = tauri::async_runtime::spawn(async move { link.forget_host(&forgotten).await }).await;
    Ok(state.connection_state())
}

/// What the voice calls ask of the pairings: how this computer is paired with `host`, and nothing
/// while the records cannot be read. The pairing record is written before an unpairing is
/// reported, and a host paired again gives this device another identity, so it outlives a launch
/// whatever happened to what the calls kept.
pub fn pairing_known<R: Runtime>(
    app: AppHandle<R>,
) -> impl Fn(kr_protocol::ids::DeviceId) -> crate::voice::PairedNow + Send + Sync + 'static {
    use crate::voice::PairedNow;

    move |host| {
        let Some(device) = app
            .try_state::<AppState>()
            .and_then(|state| state.device().ok())
        else {
            return PairedNow::Unknown;
        };
        match device.paired_as(host) {
            Ok(Some(device_id)) => PairedNow::As(device_id),
            Ok(None) => PairedNow::Not,
            Err(_) => PairedNow::Unknown,
        }
    }
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
    let handle = app.clone();
    let _ = state.choose_host(
        "this application is reaching the host you chose",
        move || {
            let host = device
                .host_in_use()
                .ok_or_else(CommandError::not_connected)?;
            Ok(Started {
                target: target_of(&host),
                spawn: Box::new(move |choice| {
                    tauri::async_runtime::spawn(keep(handle, host, choice, None))
                }),
            })
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
            match crate::places::as_the_main_link(Connection::paired(&device, &host)).await {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A choice whose step panics is told in words that say it stopped part of the way and where the
    /// host in use shows, with nothing of the panic in them.
    #[tokio::test]
    async fn a_choice_that_stops_part_of_the_way_is_told_without_the_panic() {
        // The step stops with a panic payload and no panic message, so the one panic this case
        // prints is its own assertion's.
        let error = tauri::async_runtime::spawn_blocking(|| -> u8 {
            std::panic::resume_unwind(Box::new("the keeper broke"))
        })
        .await
        .expect_err("the step panicked");
        let failure = unfinished(&error);
        assert_eq!(
            failure.message,
            "the choice of host stopped part of the way; the connection's state shows which host is in use"
        );
        assert!(
            !failure.message.contains("keeper broke"),
            "{}",
            failure.message
        );
    }
}

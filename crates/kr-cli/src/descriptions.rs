//! `kr host descriptions`: what session descriptions offer on this host, turning them on or off,
//! and fetching or cancelling the fetch of the model's files.
//!
//! Everything goes through the control daemon under this user's own authority on this host: the
//! settings are written to the host's configuration and apply at once, and a fetch is a task of
//! the daemon's. Without an option the command only reads, and what it prints first is what the
//! fetch would cost: the exact size and where it would go. Nothing is fetched until `--download`
//! asks for it, and it needs no account.

use kr_client::shown::Shown;
use kr_ipc::paths::HostPaths;
use kr_protocol::describe::{
    DescriptionConfigureParams, DescriptionDownload, DescriptionDownloadAction,
    DescriptionDownloadParams, DescriptionPause, DescriptionSetup, DescriptionSetupParams,
    DescriptionState,
};
use kr_protocol::method::Method;
use kr_protocol::scalars::Nullable;

use crate::cli::DescriptionsArguments;
use crate::daemon::Daemon;
use crate::error::{CliError, Result};
use crate::output::{self, Asked, Document, Line, Request, closed};
use crate::report::Completion;
use crate::stdout_line;

/// Runs `kr host descriptions` and prints what setup shows afterwards.
///
/// # Errors
///
/// Returns a usage failure for a battery setting that is not `on` or `off`, the daemon's refusal,
/// or a transport failure.
pub async fn run(
    paths: &HostPaths,
    arguments: DescriptionsArguments,
    json: bool,
) -> Result<Completion> {
    let battery = arguments
        .battery
        .as_deref()
        .map(|chosen| match chosen {
            "on" => Ok(true),
            "off" => Ok(false),
            _ => Err(CliError::Usage(Shown::said(
                "the battery setting is on or off",
            ))),
        })
        .transpose()?;
    let enabled = match (arguments.on, arguments.off) {
        (true, _) => Some(true),
        (_, true) => Some(false),
        _ => None,
    };
    let mut daemon = Daemon::open(paths, &arguments.selector).await?;
    let mut setup: Option<DescriptionSetup> = None;
    if enabled.is_some() || battery.is_some() {
        setup = Some(
            daemon
                .mutate(
                    Method::DescriptionConfigure,
                    &DescriptionConfigureParams {
                        enabled: Nullable(enabled),
                        on_battery: Nullable(battery),
                    },
                )
                .await?,
        );
    }
    let fetch = if arguments.download {
        Some(DescriptionDownloadAction::Start)
    } else if arguments.cancel {
        Some(DescriptionDownloadAction::Cancel)
    } else {
        None
    };
    if let Some(action) = fetch {
        setup = Some(
            daemon
                .mutate(
                    Method::DescriptionDownload,
                    &DescriptionDownloadParams { action },
                )
                .await?,
        );
    }
    let setup = match setup {
        Some(setup) => setup,
        None => {
            daemon
                .read(Method::DescriptionSetup, &DescriptionSetupParams {})
                .await?
        }
    };
    if json {
        output::document(&document(&setup));
    } else {
        output::lines(&lines(&setup));
    }
    Ok(Completion::Done)
}

/// What setup shows, as lines for a person.
fn lines(setup: &DescriptionSetup) -> Vec<Line> {
    let mut lines = Vec::new();
    if let Some(why) = &setup.unavailable.0 {
        lines.push(stdout_line!(
            "This host offers no session descriptions: {}",
            Asked::text(Request::Descriptions, why)
        ));
        return lines;
    }
    lines.push(stdout_line!(
        "Session descriptions are {}, and inference on battery is {}.",
        if setup.enabled { "on" } else { "off" },
        if setup.on_battery {
            "allowed"
        } else {
            "not allowed"
        }
    ));
    if let Some(profile) = &setup.profile_id.0 {
        lines.push(stdout_line!(
            "The model is {}: {} bytes, fetched from {}{}.",
            Asked::text(Request::Descriptions, profile),
            setup.asset_bytes.get(),
            Asked::text(Request::Descriptions, &setup.sources.join(", ")),
            if setup.needs_hosted_account {
                ", with an account"
            } else {
                ", and no account is needed"
            }
        ));
    }
    match setup.download {
        DescriptionDownload::NotStarted => {
            lines.push(stdout_line!("Nothing has been fetched."));
        }
        DescriptionDownload::Running => lines.push(stdout_line!(
            "Fetching: {} of {} bytes so far.",
            setup.fetched_bytes.get(),
            setup.asset_bytes.get()
        )),
        DescriptionDownload::Verified => lines.push(stdout_line!(
            "The model's files are here, and each matched the profile's size and digest."
        )),
        DescriptionDownload::Cancelled => lines.push(stdout_line!(
            "The fetch was cancelled, and what it had written is gone."
        )),
        DescriptionDownload::Failed => lines.push(stdout_line!(
            "The fetch failed: {}",
            Asked::text(
                Request::Descriptions,
                setup.failure.0.as_deref().unwrap_or("no reason was given")
            )
        )),
    }
    lines.push(match setup.paused.0 {
        Some(pause) => stdout_line!("Inference is paused: {}.", pause_words(pause)),
        None => stdout_line!("Inference is {}.", state_words(setup.state)),
    });
    if setup.paused.0 == Some(DescriptionPause::NotDownloaded)
        && setup.download != DescriptionDownload::Running
    {
        lines.push(stdout_line!(
            "kr host descriptions --download fetches the files. Until then nothing new is \
             generated, and a session shows the title it has from metadata, a pin or an earlier \
             description."
        ));
    }
    if setup.can_cancel {
        lines.push(stdout_line!(
            "kr host descriptions --cancel stops the fetch and removes what it wrote."
        ));
    }
    lines
}

/// What a pause says, in words.
const fn pause_words(pause: DescriptionPause) -> &'static str {
    match pause {
        DescriptionPause::MemoryReserve => "loading the model would leave too little memory",
        DescriptionPause::MemoryPressure => "the host is short of memory",
        DescriptionPause::Thermal => "the host is hot",
        DescriptionPause::Battery => "the host is on battery",
        DescriptionPause::SignalUnqualified => "the host cannot read a signal the decision needs",
        DescriptionPause::Disabled => "descriptions are off",
        DescriptionPause::NoModelHere => "this environment runs no model",
        DescriptionPause::NotDownloaded => "the model's files are not on this host",
        DescriptionPause::InferenceFailed => {
            "the description process failed three times running, and is left alone for a while"
        }
    }
}

/// What a state says, in words.
const fn state_words(state: DescriptionState) -> &'static str {
    match state {
        DescriptionState::Ready => "ready, with no model loaded",
        DescriptionState::Resident => "running, with the model loaded",
        DescriptionState::ResourcePaused => "paused",
    }
}

/// What setup shows, for a script, in the shape the protocol answers it.
fn document(setup: &DescriptionSetup) -> Document {
    Document::new()
        .with("offered", setup.offered)
        .with("enabled", setup.enabled)
        .with("on_battery", setup.on_battery)
        .with(
            "profile_id",
            setup
                .profile_id
                .0
                .as_deref()
                .map(|profile| Asked::text(Request::Descriptions, profile)),
        )
        .with("asset_bytes", closed(&setup.asset_bytes))
        .with(
            "sources",
            setup
                .sources
                .iter()
                .map(|source| Asked::text(Request::Descriptions, source))
                .collect::<Vec<_>>(),
        )
        .with("download", closed(&setup.download))
        .with("fetched_bytes", closed(&setup.fetched_bytes))
        .with(
            "failure",
            setup
                .failure
                .0
                .as_deref()
                .map(|failure| Asked::text(Request::Descriptions, failure)),
        )
        .with("can_cancel", setup.can_cancel)
        .with("can_disable", setup.can_disable)
        .with("needs_hosted_account", setup.needs_hosted_account)
        .with(
            "unavailable",
            setup
                .unavailable
                .0
                .as_deref()
                .map(|why| Asked::text(Request::Descriptions, why)),
        )
        .with("state", closed(&setup.state))
        .with("paused", closed(&setup.paused))
        .with("ok", true)
}

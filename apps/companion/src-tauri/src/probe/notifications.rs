//! The checks a debug build runs for a phone's notifications, against a host and a gateway a device
//! run started.
//!
//! A script puts a request in the application's data directory (`kr-probe/push-request.json`),
//! starts the application, and reads the result the application writes beside it
//! (`kr-probe/push-result-<run>.txt`, one `check=<name> ok=<0 or 1> detail=<text>` line per check
//! and `done=1` last). The request names the gateway as this phone reaches it, and may name the
//! registration token a provider would have given it. A debug build takes the origin from the
//! request in place of the managed service's, and the token in place of the platform's; a request
//! with no token leaves the platform's, which is how a run through a real provider reaches this
//! phone. A release build has no request to read.
//!
//! What a request may ask for, in the order the application does it:
//!
//! * `invitation`: pair with the host it names, and wait for the connection;
//! * `enable`: turn notifications on for the paired host, the way the person does, and wait until
//!   the host has the phone as a destination or the steps stop;
//! * `reissue`: ask the gateway to issue the phone's authorisation for the host again, and keep the
//!   credential nowhere and tell the host nothing, which leaves the host holding one the gateway no
//!   longer accepts;
//! * `look`: look again at where notifications stand, as the application does when it comes to the
//!   front, and say where they stand;
//! * `previews`: choose whether the notification shows what needs the person, the way the page's
//!   switch does, and wait until the host has been told or the steps stop;
//! * `route`: wait for a tap on a notification to open the application on a screen.
//!
//! The host, the gateway and what each of them saw are the script's and the host's suite to read:
//! these lines say what the phone did. The request holds an invitation's secret and, when it has
//! one, a token for a recording server, both thrown away with the run. Each request is run once: a
//! result file that exists says its run was.

use std::path::Path;
use std::time::{Duration, Instant};

use serde_json::Value;
use tauri::{AppHandle, Manager as _, Runtime};

use super::{Check, Checks, harness};
use crate::commands;

/// How long the steps are given to end with the host holding the phone as a destination: the
/// challenge's own five minutes, and the rest of the steps.
const ENABLED_WITHIN: Duration = Duration::from_secs(8 * 60);

/// How long a tap on a notification is waited for.
const TAP_WITHIN: Duration = Duration::from_secs(180);

/// The look between two reads of where things stand.
const LOOK: Duration = Duration::from_millis(500);

/// What a device run asks of one launch.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// Names the run, which the result file's name repeats.
    pub run: String,
    /// The gateway, as this phone reaches it.
    #[allow(dead_code)]
    pub origin: String,
    /// The registration token a provider would have given this installation, when the run has one
    /// to give; with none, the platform's own is used.
    #[serde(default)]
    #[allow(dead_code)]
    pub token: Option<String>,
    /// A direct invitation to pair with first, when the phone is not paired yet.
    #[serde(default)]
    pub invitation: Option<String>,
    /// Whether to turn notifications on for the paired host.
    #[serde(default)]
    pub enable: bool,
    /// Whether to have the gateway issue the authorisation again, and tell the host nothing.
    #[serde(default)]
    pub reissue: bool,
    /// Whether to look again at where notifications stand.
    #[serde(default)]
    pub look: bool,
    /// The choice of previews to make for the paired host, when one is to be made.
    #[serde(default)]
    pub previews: Option<bool>,
    /// Whether to wait for a tap on a notification.
    #[serde(default)]
    pub route: bool,
}

/// Reads a request from the text a script left, when it is one this phone runs: it names its run
/// the way a result file can carry, and holds no key a request does not define.
fn parse(text: &str) -> Option<Request> {
    let request = serde_json::from_str::<Request>(text).ok()?;
    super::is_a_run_name(&request.run).then_some(request)
}

/// Reads the request a script left in `directory`, when there is one that has not been run.
fn take_in(directory: &Path) -> Option<Request> {
    let text = std::fs::read_to_string(directory.join("push-request.json")).ok()?;
    let request = parse(&text)?;
    // A request is run once: the result file is the record that it was, and a relaunch for another
    // purpose runs nothing again. The request itself stays, because the debug build reads the token
    // and the origin from it for as long as the device run lasts.
    (!directory
        .join(format!("push-result-{}.txt", request.run))
        .exists())
    .then_some(request)
}

/// Reads the request a script left, when there is one that has not been run.
#[must_use]
pub fn take<R: Runtime>(app: &AppHandle<R>) -> Option<Request> {
    take_in(&app.path().app_data_dir().ok()?.join("kr-probe"))
}

/// Runs what a request asks for, writing each check as it is made.
pub fn start<R: Runtime>(app: &AppHandle<R>, request: Request) {
    let Ok(data) = app.path().app_data_dir() else {
        return;
    };
    let file = data
        .join("kr-probe")
        .join(format!("push-result-{}.txt", request.run));
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let append = |text: &str| {
            use std::io::Write as _;
            if let Ok(mut open) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&file)
            {
                let _ = open.write_all(text.as_bytes());
            }
        };
        append(&format!("run={}\n", request.run));
        let mut report = |check: &Check| append(&format!("{}\n", check.line()));
        run(&app, &request, &mut report).await;
        append("done=1\n");
    });
}

async fn run<R: Runtime>(
    app: &AppHandle<R>,
    request: &Request,
    report: &mut (dyn FnMut(&Check) + Send),
) {
    let mut checks = Checks {
        all: Vec::new(),
        report,
    };
    if let Some(invitation) = &request.invitation
        && !(harness::pair(app, invitation, &mut checks).await
            && harness::connect(app, &mut checks).await)
    {
        return;
    }
    if request.enable && !enable(app, &mut checks).await {
        return;
    }
    if request.enable {
        preview_key(app, &mut checks);
    }
    if request.reissue {
        reissue(app, &mut checks).await;
    }
    if request.look {
        look(app, &mut checks).await;
    }
    if let Some(on) = request.previews {
        previews(app, on, &mut checks).await;
    }
    if request.route {
        route(app, &mut checks).await;
    }
}

/// Where the one paired host's notifications stand, as the page reads it.
fn standing<R: Runtime>(app: &AppHandle<R>) -> Option<(String, String, String)> {
    let view = commands::push_view(app.state()).ok()?;
    let view = serde_json::to_value(view).ok()?;
    let host = view["hosts"].as_array()?.first()?.clone();
    Some((
        host["reference"].as_str()?.to_owned(),
        host["state"].as_str()?.to_owned(),
        host["words"].as_str().unwrap_or_default().to_owned(),
    ))
}

/// Turns notifications on, the way the page does, and waits for the end of the steps.
async fn enable<R: Runtime>(app: &AppHandle<R>, checks: &mut Checks<'_>) -> bool {
    let Some((reference, ..)) = standing(app) else {
        checks.push(Check::found(
            "notifications are asked for",
            false,
            "this phone has no paired host to turn them on for",
        ));
        return false;
    };
    if let Err(error) = commands::push_enable(app.state(), reference, None) {
        checks.push(Check::found(
            "notifications are asked for",
            false,
            format!("{error:?}"),
        ));
        return false;
    }
    let end = Instant::now() + ENABLED_WITHIN;
    let mut last = String::new();
    let mut steps = Vec::<String>::new();
    while let Some((_, state, words)) = standing(app) {
        let line = format!("{state}: {words}");
        if line != last {
            steps.push(line.clone());
            last = line;
        }
        if matches!(state.as_str(), "on" | "needs_attention") || Instant::now() >= end {
            break;
        }
        tokio::time::sleep(LOOK).await;
    }
    let on = last.starts_with("on:");
    checks.push(Check::found(
        "the host holds this phone as a destination",
        on,
        steps.join(" | "),
    ));
    on
}

/// Says which notification-preview key this phone holds, by the identifier a sealed preview names
/// its recipient by, so that a run can compare it with the key the host seals to and the key the
/// receiver's store holds. The identifier is a hash of the public key and reveals neither key.
fn preview_key<R: Runtime>(app: &AppHandle<R>, checks: &mut Checks<'_>) {
    let state = app.state::<crate::state::AppState>();
    let id = state.device().ok().map(|device| {
        device
            .identity()
            .keys
            .notification_preview
            .key_id()
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    });
    checks.push(Check::found(
        "this phone's preview key identifier",
        id.is_some(),
        id.unwrap_or_default(),
    ));
}

/// Has the gateway issue the authorisation again under the same record, and tells the host nothing.
async fn reissue<R: Runtime>(app: &AppHandle<R>, checks: &mut Checks<'_>) {
    let state = app.state::<crate::state::AppState>();
    let host = state
        .device()
        .ok()
        .and_then(|device| device.pairing().hosts.list().ok())
        .and_then(|hosts| hosts.into_iter().next());
    let (Some(desk), Some(host)) = (state.push(), host) else {
        checks.push(Check::found(
            "the gateway issued the authorisation again",
            false,
            "no notifications desk or no paired host",
        ));
        return;
    };
    match desk.reissue_unannounced(&host).await {
        Ok(revision) => checks.push(Check::found(
            "the gateway issued the authorisation again",
            true,
            format!("the gateway now holds revision {revision}"),
        )),
        Err(words) => checks.push(Check::found(
            "the gateway issued the authorisation again",
            false,
            words,
        )),
    }
}

/// Chooses whether the notification shows what needs the person, the way the page's switch does, and
/// waits for the end of the steps that tell the host.
async fn previews<R: Runtime>(app: &AppHandle<R>, on: bool, checks: &mut Checks<'_>) {
    let name = "the choice of previews was made";
    let Some((reference, ..)) = standing(app) else {
        checks.push(Check::found(name, false, "this phone has no paired host"));
        return;
    };
    if let Err(error) = commands::push_previews(app.state(), reference, on).await {
        checks.push(Check::found(name, false, format!("{error:?}")));
        return;
    }
    let end = Instant::now() + ENABLED_WITHIN;
    let mut last = String::new();
    while let Some((_, state, words)) = standing(app) {
        last = format!("{state}: {words}");
        if matches!(state.as_str(), "on" | "needs_attention") || Instant::now() >= end {
            break;
        }
        tokio::time::sleep(LOOK).await;
    }
    let chosen = commands::push_view(app.state())
        .ok()
        .and_then(|view| serde_json::to_value(view).ok())
        .and_then(|view| view["hosts"][0]["previews"].as_bool());
    checks.push(Check::found(
        name,
        last.starts_with("on:") && chosen == Some(on),
        format!("previews {} -> {last}", if on { "on" } else { "off" }),
    ));
}

/// Looks again, as the application does at each foreground, and says where things stand.
async fn look<R: Runtime>(app: &AppHandle<R>, checks: &mut Checks<'_>) {
    let view = commands::push_refresh(app.state()).await;
    let line = view.ok().and_then(|view| serde_json::to_value(view).ok());
    let Some(Value::Object(view)) = line else {
        checks.push(Check::found(
            "notifications were looked at",
            false,
            "no view",
        ));
        return;
    };
    let host = view
        .get("hosts")
        .and_then(Value::as_array)
        .and_then(|hosts| hosts.first())
        .cloned()
        .unwrap_or(Value::Null);
    // The sequence a look starts is given the time to end: a state that is working is not where
    // things stand.
    let end = Instant::now() + ENABLED_WITHIN;
    let mut state = host["state"].as_str().unwrap_or("none").to_owned();
    let mut words = host["words"].as_str().unwrap_or_default().to_owned();
    while state == "working" && Instant::now() < end {
        tokio::time::sleep(LOOK).await;
        if let Some((_, next, said)) = standing(app) {
            state = next;
            words = said;
        }
    }
    checks.push(Check::found(
        "notifications stand",
        true,
        format!("{state}: {words}"),
    ));
}

/// Waits for a tap on a notification to open the application on a screen.
async fn route<R: Runtime>(app: &AppHandle<R>, checks: &mut Checks<'_>) {
    let end = Instant::now() + TAP_WITHIN;
    loop {
        if let Ok(Some(screen)) = commands::notification_route(app.state()).await {
            checks.push(Check::found(
                "a tap on a notification opened the application on the attention screen",
                screen == "attention",
                format!("the screen is {screen}"),
            ));
            return;
        }
        if Instant::now() >= end {
            checks.push(Check::found(
                "a tap on a notification opened the application on the attention screen",
                false,
                "no tap within the time",
            ));
            return;
        }
        tokio::time::sleep(LOOK).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A request that names no registration token is read, so that the application asks the
    /// platform for its own, whether it is written as an object or as a list that ends before the
    /// token; a request that names one carries it, and a key the request does not define, or a run
    /// name that a result file cannot carry, is still refused.
    #[test]
    fn a_request_may_leave_the_registration_token_to_the_platform() {
        let without = parse(
            r#"{"run":"live","origin":"http://127.0.0.1:8787","invitation":"an-invitation","enable":true}"#,
        );
        assert!(without.is_some(), "a request with no token is read");
        let without = without.expect("a request that was read");
        assert_eq!(without.token, None);
        assert_eq!(without.invitation.as_deref(), Some("an-invitation"));
        assert!(without.enable);

        let with = parse(r#"{"run":"live","origin":"http://127.0.0.1:8787","token":"a-token"}"#);
        assert!(with.is_some(), "a request with a token is read");
        assert_eq!(
            with.and_then(|request| request.token).as_deref(),
            Some("a-token")
        );

        // The decoder also reads a request written as a list in the order of the type's members,
        // where a member left out of the end needs the explicit default.
        assert!(
            parse(r#"["live","http://127.0.0.1:8787"]"#).is_some(),
            "a request written as a list, with no token, is read"
        );

        assert!(
            parse(r#"{"run":"live","origin":"http://127.0.0.1:8787","tokn":"a-token"}"#).is_none(),
            "a key the request does not define is refused"
        );
        assert!(
            parse(r#"{"run":"../live","origin":"http://127.0.0.1:8787"}"#).is_none(),
            "a run name that a result file cannot carry is refused"
        );
    }

    /// A request in the application's probe directory is taken only for a run name that a result
    /// file can carry, and only until that run has written its result file.
    #[test]
    fn a_request_is_taken_once_and_only_for_a_run_a_result_file_can_carry() {
        let directory = tempfile::tempdir().expect("a directory");
        let request = directory.path().join("push-request.json");

        assert!(
            take_in(directory.path()).is_none(),
            "with no request there is nothing to take"
        );

        std::fs::write(
            &request,
            r#"{"run":"../live","origin":"http://127.0.0.1:8787"}"#,
        )
        .expect("a request");
        assert!(
            take_in(directory.path()).is_none(),
            "a run name that a result file cannot carry is not taken"
        );

        std::fs::write(
            &request,
            r#"{"run":"live","origin":"http://127.0.0.1:8787"}"#,
        )
        .expect("a request");
        let taken = take_in(directory.path());
        assert!(taken.is_some(), "a request for a valid run is taken");
        assert_eq!(taken.map(|request| request.run).as_deref(), Some("live"));

        std::fs::write(directory.path().join("push-result-live.txt"), "run=live\n")
            .expect("a result file");
        assert!(
            take_in(directory.path()).is_none(),
            "a run that has written its result file is not taken again"
        );
    }
}

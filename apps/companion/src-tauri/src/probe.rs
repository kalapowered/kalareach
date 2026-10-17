//! The checks a debug build runs for the voice call's bridge on a phone.
//!
//! A script puts a request in the application's data directory (`kr-probe/request.json`, naming a
//! run), starts the application on a simulator or an emulator, and reads the result the application
//! writes beside it (`kr-probe/result-<run>.txt`, one `check=<name> ok=<0 or 1> detail=<text>` line
//! per check and `done=1` last). The checks drive the real commands: the application's own call,
//! reached through the platform plugin, from an offer to an end. The answer to the offer is built
//! here from the offer's own sections, so the connection is described and applied but never
//! carries media: what is proved is the bridge, not a provider.
//!
//! Compiled into debug builds only. A release build has no request to read.

use std::time::Duration;

use companion_platform::call::{
    CallEvent, CallEvents, CallFailure, CallId, CallPlatform, CaptureState, FailureKind, Heard,
    Mute,
};

/// How long a check waits for news it expects, which a healthy bridge delivers at once.
const NEWS_WITHIN: Duration = Duration::from_secs(10);

/// How long the news is watched after a call is permitted, and after its microphone is muted.
const AFTER_PERMIT: Duration = Duration::from_secs(3);

/// One check and what it found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Check {
    /// Its name.
    pub name: &'static str,
    /// Whether it found what it expected.
    pub ok: bool,
    /// What it found, on one line.
    pub detail: String,
}

impl Check {
    fn found(name: &'static str, ok: bool, detail: impl std::fmt::Display) -> Self {
        Self {
            name,
            ok,
            detail: detail.to_string().replace(['\n', '\r'], " "),
        }
    }

    /// The line the result file holds.
    #[must_use]
    pub fn line(&self) -> String {
        format!(
            "check={} ok={} detail={}",
            self.name,
            u8::from(self.ok),
            self.detail
        )
    }
}

/// The answer a provider would give to `offer`, built from the offer's own sections.
///
/// Every section of the offer is answered in its place, with its own identifier: an audio section
/// with the one codec the offer and the provider share, and the data section the provider's events
/// channel is made in. The answer is an ICE-lite agent's, with a fingerprint and candidates that
/// lead nowhere, so a connection that applies it never connects. It is shaped as the recorded
/// answer of the provider's service is.
///
/// # Errors
///
/// Returns why the offer cannot be answered: it holds no audio section, no data section, or a kind
/// of section this answer does not know.
pub fn answer_for(offer: &str) -> Result<String, String> {
    let mut sections: Vec<(&str, String)> = Vec::new();
    let mut current: Option<(&str, String)> = None;
    for line in offer.lines().map(str::trim_end) {
        if let Some(media) = line.strip_prefix("m=") {
            if let Some(done) = current.take() {
                sections.push(done);
            }
            let kind = media.split_whitespace().next().unwrap_or_default();
            current = Some((
                match kind {
                    "audio" => "audio",
                    "application" => "application",
                    _ => {
                        return Err(format!(
                            "the offer holds a {kind} section, which is not answered"
                        ));
                    }
                },
                String::new(),
            ));
        } else if let Some((_, text)) = current.as_mut() {
            text.push_str(line);
            text.push('\n');
        }
    }
    sections.extend(current);
    let mut mids = Vec::new();
    for (_, text) in &sections {
        let mid = text
            .lines()
            .find_map(|line| line.strip_prefix("a=mid:"))
            .ok_or("a section of the offer has no identifier")?;
        mids.push(mid.to_owned());
    }
    if !sections.iter().any(|(kind, _)| *kind == "audio") {
        return Err("the offer holds no audio section".to_owned());
    }
    if !sections.iter().any(|(kind, _)| *kind == "application") {
        return Err("the offer holds no data section".to_owned());
    }
    let mut answer = String::new();
    answer.push_str("v=0\r\no=- 1155667488797280743 1789504978 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\n");
    answer.push_str("a=msid-semantic:WMS *\r\n");
    answer.push_str(
        "a=fingerprint:sha-256 DD:0A:C5:DD:11:BB:23:F1:D5:85:19:90:CC:82:1E:E5:A3:04:88:D1:D3:53:83:5F:1A:D2:BA:2D:5A:42:40:25\r\n",
    );
    answer.push_str("a=ice-lite\r\na=extmap-allow-mixed\r\n");
    answer.push_str(&format!("a=group:BUNDLE {}\r\n", mids.join(" ")));
    for ((kind, _), mid) in sections.iter().zip(&mids) {
        match *kind {
            "audio" => {
                answer.push_str(
                    "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\nc=IN IP4 0.0.0.0\r\na=setup:active\r\n",
                );
                answer.push_str(&format!("a=mid:{mid}\r\n"));
                answer.push_str(
                    "a=ice-ufrag:FDTJv7/u0/3oMbfr\r\na=ice-pwd:GXuZvi9ZeCVsqv3XzFgEgVWxk25QYfLD\r\n\
                     a=rtcp-mux\r\na=rtcp-rsize\r\na=rtpmap:111 opus/48000/2\r\n\
                     a=fmtp:111 minptime=10;useinbandfec=1\r\n\
                     a=ssrc:3677868517 cname:realtimeapi\r\na=ssrc:3677868517 msid:realtimeapi audio\r\n\
                     a=ssrc:3677868517 mslabel:realtimeapi\r\na=ssrc:3677868517 label:audio\r\n\
                     a=msid:realtimeapi audio\r\na=sendrecv\r\n\
                     a=candidate:3826567912 1 udp 2130706431 127.0.0.1 3478 typ host ufrag FDTJv7/u0/3oMbfr\r\n",
                );
            }
            _ => {
                answer.push_str(
                    "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\na=setup:active\r\n",
                );
                answer.push_str(&format!("a=mid:{mid}\r\n"));
                answer.push_str(
                    "a=sendrecv\r\na=sctp-port:5000\r\na=max-message-size:1073741823\r\n\
                     a=ice-ufrag:FDTJv7/u0/3oMbfr\r\na=ice-pwd:GXuZvi9ZeCVsqv3XzFgEgVWxk25QYfLD\r\n",
                );
            }
        }
    }
    Ok(answer)
}

/// Reads news until `wanted` is heard or `within` passes, answering every item read.
async fn hear(
    events: &mut CallEvents,
    within: Duration,
    wanted: impl Fn(&CallEvent) -> bool,
) -> Vec<Heard> {
    let mut heard = Vec::new();
    let _ = tokio::time::timeout(within, async {
        while let Some(item) = events.recv().await {
            let done = matches!(&item, Heard::Event(event) if wanted(event));
            heard.push(item);
            if done {
                break;
            }
        }
    })
    .await;
    heard
}

fn words(heard: &[Heard]) -> String {
    heard
        .iter()
        .map(|item| match item {
            Heard::Lost => "lost".to_owned(),
            Heard::Event(CallEvent::Connection { state }) => format!("connection:{state:?}"),
            Heard::Event(CallEvent::ProviderEvent { bytes }) => {
                format!("provider_event:{}", bytes.len())
            }
            Heard::Event(CallEvent::FirstAudio) => "first_audio".to_owned(),
            Heard::Event(CallEvent::Capture { state }) => format!("capture:{state:?}"),
            Heard::Event(CallEvent::Ended) => "ended".to_owned(),
            Heard::Event(CallEvent::Lost) => "lost".to_owned(),
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// Whether a command was refused as one of `kind`. What a command that was not refused returned is
/// not written down: it can be an offer, whose credentials a result file must not hold.
fn refused<T>(result: Result<T, CallFailure>, kind: &[FailureKind]) -> (bool, String) {
    match result {
        Err(failure) if kind.contains(&failure.kind) => (true, format!("{:?}", failure.kind)),
        Err(failure) => (
            false,
            format!("refused as {:?}: {}", failure.kind, failure.message),
        ),
        Ok(_) => (false, "was not refused".to_owned()),
    }
}

/// The checks made so far, each reported the moment it is made: a run that is cut short, by the
/// system ending the application for instance, still says how far it got.
struct Checks<'a> {
    all: Vec<Check>,
    report: &'a mut (dyn FnMut(&Check) + Send),
}

impl Checks<'_> {
    fn push(&mut self, check: Check) {
        (self.report)(&check);
        self.all.push(check);
    }
}

fn failed(failure: &CallFailure) -> String {
    format!("{:?}: {}", failure.kind, failure.message)
}

/// Ends `call` and checks that the end is told and that nothing is held afterwards.
async fn end_and_check(
    platform: &dyn CallPlatform,
    call: &CallId,
    events: &mut CallEvents,
    checks: &mut Checks<'_>,
) {
    match platform.stop(call).await {
        Ok(()) => {
            let heard = hear(events, NEWS_WITHIN, |event| {
                matches!(event, CallEvent::Ended)
            })
            .await;
            checks.push(Check::found(
                "the end is told",
                heard.contains(&Heard::Event(CallEvent::Ended)),
                words(&heard),
            ));
        }
        Err(failure) => checks.push(Check::found("the end is told", false, failure.message)),
    }
    match platform.held().await {
        Ok(held) => checks.push(Check::found(
            "nothing held after stop",
            held.call.is_none(),
            format!("{held:?}"),
        )),
        Err(failure) => checks.push(Check::found(
            "nothing held after stop",
            false,
            failure.message,
        )),
    }
}

/// Makes `call`'s offer and applies an answer built from it. False when the call cannot go on.
async fn negotiate(platform: &dyn CallPlatform, call: &CallId, checks: &mut Checks<'_>) -> bool {
    let offer = match platform.offer(call).await {
        Ok(offer) => offer,
        Err(failure) => {
            checks.push(Check::found("offer", false, failed(&failure)));
            return false;
        }
    };
    checks.push(Check::found(
        "offer",
        offer.contains("m=audio") && offer.contains("m=application"),
        format!("{} bytes", offer.len()),
    ));
    match answer_for(&offer) {
        Ok(answer) => match platform.accept(call, &answer).await {
            Ok(answered) => {
                checks.push(Check::found(
                    "answer applied",
                    !answered.uses_dtx,
                    format!("{answered:?}"),
                ));
                true
            }
            Err(failure) => {
                checks.push(Check::found("answer applied", false, failed(&failure)));
                false
            }
        },
        Err(why) => {
            checks.push(Check::found("answer applied", false, why));
            false
        }
    }
}

/// Drives the call's commands from an open to an end, and says what each did.
///
/// The checks that need no audio come first and the ones that permit a call, which starts the
/// device's audio, come last, so a device whose audio cannot start (a simulator's, for one) still
/// shows everything before it. `closes_at_epoch_ms` is when the call it permits is to close, in UTC
/// milliseconds. `report` is given each check as it is made.
pub async fn bridge_check(
    platform: &dyn CallPlatform,
    closes_at_epoch_ms: u64,
    report: &mut (dyn FnMut(&Check) + Send),
) -> Vec<Check> {
    let mut checks = Checks {
        all: Vec::new(),
        report,
    };

    let mut opened = match platform.open().await {
        Ok(opened) => {
            checks.push(Check::found(
                "open",
                true,
                format!("notifications {:?}", opened.notifications),
            ));
            opened
        }
        Err(failure) => {
            checks.push(Check::found("open", false, failed(&failure)));
            return checks.all;
        }
    };
    let call: CallId = opened.call.clone();

    let (ok, detail) = refused(
        platform.open().await.map(|second| second.call),
        &[FailureKind::AlreadyRunning],
    );
    checks.push(Check::found("a second open is refused", ok, detail));

    match platform.held().await {
        Ok(held) => checks.push(Check::found(
            "held before permit",
            held.call.as_ref() == Some(&call) && held.capture == CaptureState::Idle,
            format!("{held:?}"),
        )),
        Err(failure) => checks.push(Check::found("held before permit", false, failure.message)),
    }

    if !negotiate(platform, &call, &mut checks).await {
        return checks.all;
    }

    // A call that was never permitted ends when it is stopped, and then refuses commands.
    end_and_check(platform, &call, &mut opened.events, &mut checks).await;
    let (ok, detail) = refused(platform.offer(&call).await, &[FailureKind::Ended]);
    checks.push(Check::found(
        "a command to an ended call is refused",
        ok,
        detail,
    ));

    // An answer that does not describe the offer is refused, and a call that cannot use its answer
    // ends rather than being left half made.
    match platform.open().await {
        Ok(mut second) => {
            let second_call = second.call.clone();
            let _ = platform.offer(&second_call).await;
            let (ok, detail) = refused(
                platform
                    .accept(&second_call, "v=0\r\nnot a description\r\n")
                    .await,
                &[FailureKind::Engine],
            );
            checks.push(Check::found(
                "an answer that is not one is refused",
                ok,
                detail,
            ));
            let heard = hear(&mut second.events, NEWS_WITHIN, |event| {
                matches!(event, CallEvent::Ended)
            })
            .await;
            checks.push(Check::found(
                "a call that could not use its answer ends",
                heard.contains(&Heard::Event(CallEvent::Ended)),
                words(&heard),
            ));
            let _ = platform.stop(&second_call).await;
        }
        Err(failure) => checks.push(Check::found(
            "an answer that is not one is refused",
            false,
            format!("a new call was refused: {:?}", failure.kind),
        )),
    }

    // A permitted call, last: permitting starts the device's audio.
    let mut permitted = match platform.open().await {
        Ok(opened) => opened,
        Err(failure) => {
            checks.push(Check::found(
                "a permitted call opens",
                false,
                failed(&failure),
            ));
            return checks.all;
        }
    };
    let call = permitted.call.clone();
    if !negotiate(platform, &call, &mut checks).await {
        return checks.all;
    }
    match platform
        .permit(
            &call,
            "5b2f0a3c-8a56-4c53-bb7e-6a4a4a1c9e01",
            closes_at_epoch_ms,
        )
        .await
    {
        Ok(was) => checks.push(Check::found("permit", was, format!("permitted {was}"))),
        Err(failure) => checks.push(Check::found("permit", false, failed(&failure))),
    }
    let settled = hear(&mut permitted.events, AFTER_PERMIT, |_| false).await;
    checks.push(Check::found(
        "news after permit has no gap",
        !settled.contains(&Heard::Lost),
        words(&settled),
    ));

    // A mute is carried out whatever the microphone was doing. What the gate shows of it depends on
    // the device: a microphone that is capturing reads as muted, and one with no recorder running
    // (a call whose connection never carries media) stays unavailable, which says more. So the
    // check holds what must be true either way: the person's mute is held, the microphone is never
    // shown as capturing afterwards, and the news and the state agree.
    match platform.mute(&call, Mute::Microphone, true).await {
        Ok(()) => {
            let heard = hear(&mut permitted.events, AFTER_PERMIT, |_| false).await;
            let told = heard.iter().rev().find_map(|item| match item {
                Heard::Event(CallEvent::Capture { state }) => Some(*state),
                _ => None,
            });
            match platform.held().await {
                Ok(held) => checks.push(Check::found(
                    "a muted microphone is held and never reported as capturing",
                    !heard.contains(&Heard::Lost)
                        && held.microphone_muted
                        && held.capture != CaptureState::Capturing
                        && told.is_none_or(|state| state == held.capture),
                    format!(
                        "muted {}, state {:?}, news {}",
                        held.microphone_muted,
                        held.capture,
                        words(&heard)
                    ),
                )),
                Err(failure) => checks.push(Check::found(
                    "a muted microphone is held and never reported as capturing",
                    false,
                    failure.message,
                )),
            }
        }
        Err(failure) => checks.push(Check::found(
            "a muted microphone is held and never reported as capturing",
            false,
            failure.message,
        )),
    }

    end_and_check(platform, &call, &mut permitted.events, &mut checks).await;
    checks.all
}

/// What a script asks a run for.
#[cfg(mobile)]
#[derive(serde::Deserialize)]
struct Request {
    /// Names the run, which the result file's name and its first line repeat.
    run: String,
}

/// Whether `run` is a name a result file can carry: letters, digits and hyphens, and short.
#[cfg(any(mobile, test))]
fn is_a_run_name(run: &str) -> bool {
    !run.is_empty()
        && run.len() <= 64
        && run
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

/// Runs the checks a script asked for, if it asked: the request is read once and taken away.
#[cfg(mobile)]
pub fn start<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    use tauri::Manager as _;

    let Ok(data) = app.path().app_data_dir() else {
        return;
    };
    let directory = data.join("kr-probe");
    let Ok(text) = std::fs::read_to_string(directory.join("request.json")) else {
        return;
    };
    let _ = std::fs::remove_file(directory.join("request.json"));
    let Ok(request) = serde_json::from_str::<Request>(&text) else {
        return;
    };
    if !is_a_run_name(&request.run) {
        return;
    }
    let platform = companion_platform::call::NativeCalls::new(
        companion_platform::call::PluginCommands::new(app.clone()),
    );
    tauri::async_runtime::spawn(async move {
        let closes_at = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |since| since.as_millis()),
        )
        .unwrap_or(0)
            + 120_000;
        let file = directory.join(format!("result-{}.txt", request.run));
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
        bridge_check(&platform, closes_at, &mut |check| {
            append(&format!("{}\n", check.line()));
        })
        .await;
        append("done=1\n");
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A libwebrtc-shaped offer: an audio section and the data section, in that order.
    const OFFER: &str = "v=0\r\no=- 4611731400430051336 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n\
        a=group:BUNDLE 0 1\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111 63\r\nc=IN IP4 0.0.0.0\r\na=mid:0\r\n\
        a=rtpmap:111 opus/48000/2\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
        c=IN IP4 0.0.0.0\r\na=mid:1\r\na=sctp-port:5000\r\n";

    /// The answer takes the offer's sections in the offer's order, each by its own identifier.
    #[test]
    fn an_answer_follows_the_offers_sections() {
        let answer = answer_for(OFFER).expect("an answer");

        assert!(answer.contains("a=group:BUNDLE 0 1\r\n"), "{answer}");
        let audio = answer.find("m=audio").expect("an audio section");
        let data = answer.find("m=application").expect("a data section");
        assert!(audio < data);
        assert!(answer[audio..data].contains("a=mid:0\r\n"));
        assert!(answer[data..].contains("a=mid:1\r\n"));
        assert!(answer.contains("a=ice-lite\r\n"));
    }

    /// An offer whose data section comes first is answered in that order.
    #[test]
    fn an_offer_with_its_data_section_first_is_answered_in_that_order() {
        let offer = "v=0\r\ns=-\r\nt=0 0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=mid:data\r\n\
            m=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=mid:voice\r\n";

        let answer = answer_for(offer).expect("an answer");

        assert!(answer.contains("a=group:BUNDLE data voice\r\n"), "{answer}");
        assert!(answer.find("m=application").unwrap() < answer.find("m=audio").unwrap());
    }

    use std::sync::Mutex;

    use companion_platform::call::{
        Answered, CallFuture, EventFrame, EventSink, Held, OpenedCall, Permission, event_queue,
    };

    /// A bridge that answers as native code does: one call at a time, news in order, an answer
    /// that is not one ends the call. `tell_the_end` is whether it says so when a call ends.
    struct Native {
        tell_the_end: bool,
        held: Mutex<Option<(CallId, EventSink, u64)>>,
        capture: Mutex<CaptureState>,
        /// A bridge that takes the command and does nothing with it.
        ignores_mutes: bool,
        /// A bridge whose recorder does not run: the gate shows the microphone unavailable.
        recorder_stopped: bool,
        /// Whether the person's mute is held.
        muted: Mutex<bool>,
    }

    impl Native {
        fn new(tell_the_end: bool) -> Self {
            Self {
                tell_the_end,
                held: Mutex::new(None),
                capture: Mutex::new(CaptureState::Idle),
                ignores_mutes: false,
                recorder_stopped: false,
                muted: Mutex::new(false),
            }
        }

        fn ignoring_mutes(mut self) -> Self {
            self.ignores_mutes = true;
            self
        }

        fn without_a_recorder(mut self) -> Self {
            self.recorder_stopped = true;
            self
        }

        fn is_now(&self, state: CaptureState) {
            *self.capture.lock().unwrap() = state;
        }

        fn tell(&self, call: &CallId, event: CallEvent) {
            let mut held = self.held.lock().unwrap();
            if let Some((id, sink, seq)) = held.as_mut()
                && id == call
            {
                *seq += 1;
                sink.deliver(EventFrame {
                    call: call.clone(),
                    seq: *seq,
                    event,
                });
            }
        }

        fn named(&self, call: &CallId) -> Result<(), CallFailure> {
            match self.held.lock().unwrap().as_ref() {
                Some((id, ..)) if id == call => Ok(()),
                _ => Err(CallFailure::new(FailureKind::Ended, "that call has ended")),
            }
        }

        fn end(&self, call: &CallId) {
            if self.tell_the_end {
                self.tell(call, CallEvent::Ended);
            }
            *self.held.lock().unwrap() = None;
            *self.muted.lock().unwrap() = false;
            self.is_now(CaptureState::Idle);
        }
    }

    impl CallPlatform for Native {
        fn open(&self) -> CallFuture<'_, OpenedCall> {
            Box::pin(async move {
                let mut held = self.held.lock().unwrap();
                if held.is_some() {
                    return Err(CallFailure::new(
                        FailureKind::AlreadyRunning,
                        "a call is held",
                    ));
                }
                let call = CallId::next();
                let (sink, events) = event_queue(call.clone());
                *held = Some((call.clone(), sink, 0));
                Ok(OpenedCall {
                    call,
                    notifications: Permission::Granted,
                    events,
                })
            })
        }

        fn offer<'a>(&'a self, call: &'a CallId) -> CallFuture<'a, String> {
            Box::pin(async move {
                self.named(call)?;
                Ok(OFFER.to_owned())
            })
        }

        fn accept<'a>(&'a self, call: &'a CallId, answer: &'a str) -> CallFuture<'a, Answered> {
            Box::pin(async move {
                self.named(call)?;
                if answer.contains("m=audio") {
                    return Ok(Answered { uses_dtx: false });
                }
                self.end(call);
                Err(CallFailure::new(
                    FailureKind::Engine,
                    "that is not an answer",
                ))
            })
        }

        fn permit<'a>(
            &'a self,
            call: &'a CallId,
            _voice_session_id: &'a str,
            _closes_at_epoch_ms: u64,
        ) -> CallFuture<'a, bool> {
            Box::pin(async move {
                self.named(call)?;
                let shown = if self.recorder_stopped {
                    CaptureState::Unavailable
                } else {
                    CaptureState::Capturing
                };
                self.is_now(shown);
                self.tell(call, CallEvent::Capture { state: shown });
                Ok(true)
            })
        }

        fn mute<'a>(&'a self, call: &'a CallId, what: Mute, muted: bool) -> CallFuture<'a, ()> {
            Box::pin(async move {
                self.named(call)?;
                if what == Mute::Microphone && muted && !self.ignores_mutes {
                    *self.muted.lock().unwrap() = true;
                    if !self.recorder_stopped {
                        self.is_now(CaptureState::MutedByPerson);
                        self.tell(
                            call,
                            CallEvent::Capture {
                                state: CaptureState::MutedByPerson,
                            },
                        );
                    }
                }
                Ok(())
            })
        }

        fn stop<'a>(&'a self, call: &'a CallId) -> CallFuture<'a, ()> {
            Box::pin(async move {
                self.named(call)?;
                self.end(call);
                Ok(())
            })
        }

        fn held(&self) -> CallFuture<'_, Held> {
            Box::pin(async move {
                let call = self
                    .held
                    .lock()
                    .unwrap()
                    .as_ref()
                    .map(|(id, ..)| id.clone());
                Ok(Held {
                    call,
                    capture: *self.capture.lock().unwrap(),
                    microphone_muted: *self.muted.lock().unwrap(),
                    playing: false,
                })
            })
        }

        fn alive<'a>(&'a self, call: &'a CallId) -> CallFuture<'a, Held> {
            Box::pin(async move {
                self.named(call)?;
                self.held().await
            })
        }
    }

    /// Against a bridge that does what native code does, every check passes: the check reads a
    /// healthy bridge as healthy.
    #[tokio::test(start_paused = true)]
    async fn every_check_passes_against_a_bridge_that_behaves() {
        let mut reported = Vec::new();
        let checks = bridge_check(&Native::new(true), 1, &mut |check| {
            reported.push(check.name);
        })
        .await;
        assert_eq!(
            reported,
            checks.iter().map(|check| check.name).collect::<Vec<_>>(),
            "each check is reported as it is made, in order"
        );

        let failed: Vec<_> = checks
            .iter()
            .filter(|check| !check.ok)
            .map(Check::line)
            .collect();
        assert!(failed.is_empty(), "{failed:#?}");
        assert!(checks.len() >= 10, "{} checks", checks.len());
    }

    /// Against a bridge that never says a call has ended, the check that waits for the end fails:
    /// a quiet bridge is not read as a healthy one.
    #[tokio::test(start_paused = true)]
    async fn a_bridge_that_never_tells_the_end_fails_the_checks_that_wait_for_it() {
        let checks = bridge_check(&Native::new(false), 1, &mut |_| {}).await;

        let failed: Vec<&str> = checks
            .iter()
            .filter(|check| !check.ok)
            .map(|check| check.name)
            .collect();
        assert!(failed.contains(&"the end is told"), "{failed:?}");
        assert!(
            failed.contains(&"a call that could not use its answer ends"),
            "{failed:?}"
        );
    }

    /// A recorder that does not run shows the microphone unavailable whatever the person did: the
    /// mute check passes when the person's mute is held and fails when it is not, so a state that
    /// never changed cannot pass for a mute that was ignored.
    #[tokio::test(start_paused = true)]
    async fn the_mute_check_reads_the_held_mute_when_the_recorder_does_not_run() {
        let kept = bridge_check(&Native::new(true).without_a_recorder(), 1, &mut |_| {}).await;
        assert!(kept.iter().all(|check| check.ok), "{kept:#?}");

        let ignored = bridge_check(
            &Native::new(true).without_a_recorder().ignoring_mutes(),
            1,
            &mut |_| {},
        )
        .await;
        let failed: Vec<&str> = ignored
            .iter()
            .filter(|check| !check.ok)
            .map(|check| check.name)
            .collect();
        assert_eq!(
            failed,
            vec!["a muted microphone is held and never reported as capturing"]
        );
    }

    /// A command that was not refused is not written down: an offer's credentials stay out of the
    /// result file.
    #[test]
    fn a_command_that_was_not_refused_writes_down_nothing_it_returned() {
        let (ok, detail) = refused(
            Ok::<_, CallFailure>("a=ice-pwd:SECRET".to_owned()),
            &[FailureKind::Ended],
        );

        assert!(!ok);
        assert!(!detail.contains("SECRET"), "{detail}");
    }

    /// A run is named by letters, digits and hyphens, so the name cannot leave the directory its
    /// result is written in.
    #[test]
    fn a_run_name_cannot_name_a_path() {
        assert!(is_a_run_name("6250EC7D-2E3F-423D-AEE0-B89F7AEB7D4B"));
        assert!(!is_a_run_name(""));
        assert!(!is_a_run_name("../elsewhere"));
        assert!(!is_a_run_name("a/b"));
        assert!(!is_a_run_name("a b"));
        assert!(!is_a_run_name(&"a".repeat(65)));
    }

    /// Against a bridge that takes a mute and goes on reporting the microphone as capturing, the
    /// mute check fails: a command that was accepted and had no effect is not read as one that did.
    #[tokio::test(start_paused = true)]
    async fn a_bridge_that_ignores_a_mute_fails_the_check_that_reads_its_effect() {
        let checks = bridge_check(&Native::new(true).ignoring_mutes(), 1, &mut |_| {}).await;

        let failed: Vec<&str> = checks
            .iter()
            .filter(|check| !check.ok)
            .map(|check| check.name)
            .collect();
        assert_eq!(
            failed,
            vec!["a muted microphone is held and never reported as capturing"]
        );
    }

    /// An offer that cannot be answered says why, whichever way it falls short.
    #[test]
    fn an_offer_that_cannot_be_answered_is_refused() {
        assert!(answer_for("v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=mid:0\r\n").is_err());
        assert!(answer_for("v=0\r\nm=application 9 UDP/DTLS/SCTP x\r\na=mid:0\r\n").is_err());
        assert!(answer_for("v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=mid:0\r\n").is_err());
        assert!(
            answer_for("v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\nm=application 9 x\r\n").is_err()
        );
    }
}

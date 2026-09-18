//! Attaching a terminal and driving it until the attachment ends.
//!
//! An attach is three things happening at once: bytes from the terminal going to the session, bytes
//! from the session going to the terminal, and a connection that can end at any moment. They run in
//! one loop rather than in tasks that each decide separately when to stop, because every way this
//! ends has to end the *other two* as well. A terminal left in raw mode because one half was still
//! waiting for a keystroke is the failure section 8 names.

use std::sync::Arc;

use kr_ipc::client::LocalClient;
use kr_protocol::attachment::ViewportPosition;
use kr_protocol::envelope::ControlFrame;
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{InputLeaseEpoch, SessionId};
use kr_protocol::method::Method;
use kr_protocol::scalars::{Nullable, U64};
use kr_protocol::session::Dimensions;
use kr_protocol::worker::WorkerDescriptor;

use crate::attach::{Attachment, RestorationGuard};
use crate::error::{CliError, Result};
use crate::terminal::ControllingTerminal;

/// Why an attachment ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttachOutcome {
    /// The terminal's own input ended, or the user detached.
    Detached,
    /// The session closed while this terminal was attached.
    SessionClosed,
    /// The input lease moved to somebody else.
    LeaseLost,
    /// The connection to the worker ended.
    Disconnected,
    /// Input could not be delivered, and whether it arrived is not known.
    DeliveryUncertain(String),
}

impl AttachOutcome {
    /// Returns the sentence a person is shown.
    #[must_use]
    pub fn detail(&self) -> String {
        match self {
            Self::Detached => "detached".to_owned(),
            Self::SessionClosed => "the session closed".to_owned(),
            Self::LeaseLost => "another attachment took the input lease".to_owned(),
            Self::Disconnected => "the connection to the session ended".to_owned(),
            Self::DeliveryUncertain(detail) => {
                format!("some input may not have reached the session: {detail}")
            }
        }
    }

    /// Returns whether this outcome is a failure the exit code must carry.
    #[must_use]
    pub const fn is_failure(&self) -> bool {
        match self {
            Self::Detached | Self::SessionClosed => false,
            Self::LeaseLost | Self::Disconnected | Self::DeliveryUncertain(_) => true,
        }
    }

    /// Returns the failure this outcome is reported as.
    #[must_use]
    pub fn into_error(self) -> Option<CliError> {
        match self {
            Self::Detached | Self::SessionClosed => None,
            Self::LeaseLost => Some(CliError::Refused(kr_protocol::error::ProtocolError::new(
                ErrorCode::LeaseLost,
                self.detail(),
            ))),
            Self::Disconnected => Some(CliError::HostUnavailable(self.detail())),
            Self::DeliveryUncertain(_) => Some(CliError::Refused(
                kr_protocol::error::ProtocolError::new(ErrorCode::OutcomeUnknown, self.detail()),
            )),
        }
    }
}

/// How an attach presents the session.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AttachOptions {
    /// Take size ownership for this terminal.
    pub take_geometry: bool,
    /// Skip the outer terminal's capability probe and use the conservative profile.
    pub no_probe: bool,
    /// Come back to the live screen as soon as the session writes something.
    ///
    /// Off by default, because a person reading their scrollback has asked to look at what is
    /// above the live page and a chatty session would pull them off it on the next line. It is the
    /// client's own choice: nothing on the wire follows or does not follow, and the host goes on
    /// delivering live output either way.
    pub follow_live: bool,
    /// What the person typed before this attachment began, which nothing has delivered yet.
    ///
    /// Creating a session with `--palette probe` asks this terminal a question of its own, and
    /// what the person typed while it was being asked is theirs. It is carried here so the
    /// attachment that follows delivers it in front of its own handshake's typing, in the order
    /// it was typed.
    pub typed_before: Vec<u8>,
}

/// How far one scroll-back step moves this terminal's window.
///
/// A whole window less one line. The line that stays is the join: a person reading upwards keeps
/// one line of what they have just read at the other edge, and knows the two pages are continuous.
fn scroll_step(rows: u16) -> u64 {
    u64::from(rows.saturating_sub(1)).max(1)
}

/// What one key the person pressed asks of this terminal's own scroll-back.
///
/// It asks nothing of the session: section 8 puts passive scrollback with focus events and
/// terminal replies among the things that do not seize the input lease, so these keys are answered
/// by reporting where this window is looking and never by writing input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scroll {
    /// Back, towards the oldest rows the session still holds.
    Back,
    /// Forward, towards the live screen.
    Forward,
}

/// Shift and Page Up, which is what a terminal sends for the usual scroll-back key.
const SCROLL_BACK_KEY: &[u8] = b"\x1b[5;2~";

/// Shift and Page Down.
const SCROLL_FORWARD_KEY: &[u8] = b"\x1b[6;2~";

/// Takes the scroll-back keys out of what the terminal sent, leaving the session's own input.
///
/// A key is recognised inside the read it arrived in. A terminal writes the bytes of one key in
/// one go, and holding back the beginning of a sequence in case the rest of it is coming would
/// delay an Escape the person meant - which is the one key an editor cannot wait for.
fn split_scrollback(bytes: &[u8]) -> (Vec<Scroll>, Vec<u8>) {
    let mut scrolls = Vec::new();
    let mut input = Vec::with_capacity(bytes.len());
    let mut at = 0_usize;
    while at < bytes.len() {
        let rest = &bytes[at..];
        if rest.starts_with(SCROLL_BACK_KEY) {
            scrolls.push(Scroll::Back);
            at += SCROLL_BACK_KEY.len();
        } else if rest.starts_with(SCROLL_FORWARD_KEY) {
            scrolls.push(Scroll::Forward);
            at += SCROLL_FORWARD_KEY.len();
        } else {
            input.push(bytes[at]);
            at += 1;
        }
    }
    (scrolls, input)
}

/// The row an answer says this window landed on, or `None` for the live screen.
const fn landed(position: Option<ViewportPosition>) -> Option<u64> {
    match position {
        None => None,
        Some(ViewportPosition::Row(row) | ViewportPosition::Above(row)) => Some(row.get()),
    }
}

/// Where a scroll-back step puts this terminal's window.
///
/// `parked` is the row the host last said this window starts at, and `None` means it is on the
/// live screen. Going back from the live screen is the one case that cannot name a row: this
/// client has not been given one above the page it is looking at, so it asks by distance and the
/// host answers with the row it landed on.
fn scrolled(parked: Option<u64>, scroll: Scroll, step: u64) -> Option<ViewportPosition> {
    match (parked, scroll) {
        (None, Scroll::Back) => Some(ViewportPosition::Above(U64::new(step))),
        (Some(row), Scroll::Back) => {
            Some(ViewportPosition::Row(U64::new(row.saturating_sub(step))))
        }
        // Already on the live screen, which is as far forward as a window goes.
        (None, Scroll::Forward) => None,
        (Some(row), Scroll::Forward) => {
            Some(ViewportPosition::Row(U64::new(row.saturating_add(step))))
        }
    }
}

/// Attaches this terminal to a session and drives it until the attachment ends.
///
/// # Errors
///
/// Returns the host's refusal, a terminal failure, or the failure the attachment ended with.
pub async fn run(
    descriptor: &WorkerDescriptor,
    options: AttachOptions,
) -> Result<(AttachOutcome, SessionId)> {
    let terminal = ControllingTerminal::open()?;
    let size = terminal.size()?;
    let dimensions = Dimensions::new(u64::from(size.columns), u64::from(size.rows));

    // Everything that touches this terminal happens after the guard is holding its state. The
    // capability handshake changes the terminal's modes to read the answers, so it is inside that
    // protection too: a process killed during the handshake must still leave a terminal somebody
    // can put back.
    let saved = terminal.modes()?;
    let mut guard = RestorationGuard::arm(
        &crate::attach::guard_program(),
        &terminal,
        &crate::terminal::SavedModes::from_state(&saved),
    )?;
    // Section 8's bounded synchronous handshake, before any application input. It asks the terminal
    // what it is and what keyboard protocols it has negotiated, so that what is put back afterwards
    // is this terminal's own state rather than nothing at all, and it ends with the
    // device-attributes terminator. A terminal that does not finish it fails this attach rather
    // than forwarding live input on a stream that may still receive a late reply.
    //
    // This process has written nothing to the terminal yet, so the stream is clean. `--no-probe` is
    // chosen here, before any probe: choosing it afterwards would not unsend the questions.
    // What this terminal declares itself to be decides which questions may be asked of it, because
    // section 8 requires every question asked to be answered. A terminal the profile cannot require
    // anything of beyond the terminator is asked only that.
    let declared = std::env::var("TERM").ok();
    // Whether a probe has already gone out on this terminal, which is a fact about the terminal
    // rather than about this process: a second `kr attach` in a window where one failed is looking
    // at the same input stream, and a late reply from the first is still coming to it.
    let context = crate::terminal::input_context(&terminal);
    let probe = if options.no_probe {
        crate::terminal::Probe::unasked(context)
    } else {
        terminal.probe(context, declared.as_deref())
    };
    let probe = match probe {
        Ok(probe) => probe,
        Err(error) => {
            // Nothing has begun forwarding, so the outer terminal's own keyboard negotiation is
            // not this attachment's to clear. Its modes are put back and the failure is reported.
            // The record that makes the next attempt require a fresh terminal was written before
            // the first question went out, and an exchange that did not finish leaves it there.
            // Nothing was read, so nothing but the documented defaults can be put back.
            let _ = terminal.restore(&saved, None, &crate::terminal::ScreenModes::UNASKED);
            guard.release();
            return Err(error);
        }
    };
    let keyboard = probe.keyboard;
    // The mouse modes, the cursor visibility and the bracketed-paste state this terminal had before
    // anything of this attachment's changed them. Held here because the rest of the probe is handed
    // to the loop, and the restoration at the end of this function needs them.
    let modes = probe.modes;
    // The guard is told them *here*, before anything else can fail. Whatever happens from now on -
    // a worker that cannot be reached, an attachment the host refuses, this process killed outright
    // - the guard puts the terminal back, and what it writes is the reset block. That block is the
    // documented default for every one of these modes, so a guard that had not been told them would
    // clear a person's mouse reporting on the way out of a failure that never touched it.
    guard.learn_modes(&modes);

    let mut client = crate::resolve::open_worker(descriptor, crate::build_id()).await?;
    // A terminal attachment claims the session's size. Section 8 makes that the default: a
    // terminal that did not claim it would be shown a projection of somebody else's size, which is
    // exactly what a lone attachment does not need. `--take-geometry` goes further and takes the
    // claim from whoever holds it.
    let attachment: Attachment =
        crate::attach::attach(&mut client, descriptor, dimensions, true, !options.no_probe).await?;
    // The transfer's own answer is what the loop starts from. Starting from the attach result
    // instead would leave it quoting an epoch the transfer has already moved, and believing
    // somebody else still owns the size it has just taken.
    let geometry = if options.take_geometry {
        crate::attach::take_geometry(
            &mut client,
            descriptor,
            attachment.attachment_id,
            attachment.result.geometry.epoch,
        )
        .await?
        .geometry
    } else {
        attachment.result.geometry.clone()
    };
    // `None` where the host would not let this terminal type: section 8 requires it to check that
    // a controller can supply the encoding the application reads, and a terminal nobody was allowed
    // to ask about cannot be shown to. The attachment stands and watches, and the person is told
    // which of the two they have before the screen arrives over it.
    let epoch = attachment.lease.as_ref().map(|lease| lease.lease.epoch);
    if epoch.is_none() {
        eprintln!(
            "kr: this terminal was not asked what it is, so the host will not let it type. \
             Attach without --no-probe to control the session."
        );
    }

    // From the cursor the attachment was allocated at, not from the beginning of what is retained.
    // Replaying historical bytes into this terminal would replay whatever they contained: a
    // clipboard write, a bell, a query whose answer would arrive at the wrong moment.
    crate::attach::subscribe(
        &mut client,
        descriptor.session_id,
        attachment.attachment_id,
        Some(attachment.result.output_cursor.get()),
    )
    .await?;

    // Forwarding begins here, and the terminal's keyboard protocols are dealt with at this exact
    // boundary and not before.
    //
    // An attachment that asked its terminal nothing changes nothing about its keyboard: the host
    // serves it a screen that installs no protocol, because nothing could put back what installing
    // one would take away. There is then nothing for the guard to give back.
    //
    // One that did ask hands the guard the answers it got and tells it that forwarding is about to
    // begin. The guard then owes those protocols back however this attachment ends, and it writes
    // them as the state they are: no stack of the terminal's is operated, because an entry pushed
    // here could be taken off by an application inside the session and the pop would then land on
    // somebody else's. The guard confirms before this returns, so nothing is forwarded until
    // something that outlives this process is holding what the terminal had. An attach that failed
    // on its way here told it nothing.
    if !options.no_probe {
        guard.learn_keyboard(&keyboard);
        guard.begin_keyboard()?;
    }
    let raw_replaced = terminal.enter_raw_mode()?;

    let handle = Arc::new(
        terminal
            .handle()
            .try_clone()
            .map_err(|error| CliError::Terminal(error.to_string()))?,
    );
    let input_handle = terminal
        .handle()
        .try_clone()
        .map_err(|error| CliError::Terminal(error.to_string()))?;
    let mut input = crate::attach::spawn_input_reader(input_handle);

    // The terminal's size can change while the attachment runs. The session is told, so the
    // application sees the resize the way it would in any other terminal.
    let mut resized = window_changes();
    // What this terminal shows while it is projected, with each keyboard protocol decided on its
    // own terms. The `modifyOtherKeys` level goes in when the person here can type, because that is
    // the encoding the host advertises for them and `CSI > 4 m` puts any terminal back to the level
    // it started with. The Kitty flags go in only when this terminal reported its own, because
    // nothing else could put those back and a person left in an encoding their shell does not
    // expect is the failure they cannot work around.
    let mut display =
        crate::render::ProjectedDisplay::with_keyboard(epoch.is_some(), keyboard.kitty.is_some());
    let outcome = drive(
        &mut client,
        descriptor,
        [options.typed_before, probe.typed].concat(),
        Attached {
            attachment_id: attachment.attachment_id,
            lease_epoch: epoch,
            geometry_epoch: geometry.epoch,
            owns_geometry: geometry.owner.as_ref() == Some(&attachment.attachment_id),
        },
        &mut input,
        &handle,
        &terminal,
        resized.as_mut(),
        &mut display,
        options.follow_live,
    )
    .await;

    // The terminal comes back here on every path out of the loop, and the guard is released only
    // once it has.
    // The modes are this process's to put back; the keyboard protocols are the guard's, and it
    // writes them back as it is released, which is what keeps the two halves in order.
    terminal.restore(&raw_replaced, None, &modes)?;
    guard.release();
    // Said after the terminal is its own again, never during the attachment: a sentence written
    // into a terminal that is showing a projection would wrap, overwrite cells and scroll the
    // bottom row, which is damage to the very screen it is describing.
    if let Some(detail) = display.degradation() {
        eprintln!(
            "kr: this terminal was showing a projection of the session, and it did not carry all \
             of it: {detail}"
        );
    }
    // And what this attachment could not establish about the terminal itself: the modes it had to
    // put back to their documented default because nothing could be read for them, and a
    // destination whose declared identity is not qualified for the character widths this session
    // measures with. Both are the attachment making a smaller promise than a qualified terminal
    // gets, and both are said out loud rather than assumed either way.
    let qualification = crate::render::Qualification {
        defaulted_modes: modes.unanswered(),
        width_unqualified: (display.frames().0 > 0)
            .then(|| {
                declared
                    .clone()
                    .unwrap_or_else(|| "a terminal with no name of its own".to_owned())
            })
            .filter(|identity| !kr_term::profile::width_qualified(identity)),
    };
    if let Some(detail) = qualification.report() {
        eprintln!("kr: not everything about this terminal could be established: {detail}");
    }
    Ok((outcome, descriptor.session_id))
}

/// What the attach established, which the loop then keeps up to date.
#[derive(Clone, Copy, Debug)]
struct Attached {
    attachment_id: kr_protocol::ids::AttachmentId,
    /// The input lease, where this attachment was given one. `None` is an attachment that watches:
    /// the host would not let this terminal type, because what its keys mean was never established.
    lease_epoch: Option<InputLeaseEpoch>,
    /// The geometry epoch this terminal last saw. A resize quotes it, so a claim that moved while
    /// the window was being dragged is refused rather than silently applied to a stale view.
    geometry_epoch: kr_protocol::ids::GeometryEpoch,
    /// Whether this attachment owns the session's size.
    owns_geometry: bool,
}

/// What one outstanding request was for, so its answer is read as an answer to that.
#[derive(Clone, Copy, Debug)]
enum Outstanding {
    /// Input at this sequence number.
    Input(u64),
    /// A size change this terminal made as the size owner.
    Resize,
    /// A size this terminal reported while somebody else owns the size.
    Viewport,
    /// A fresh screen this terminal asked for after a resynchronisation marker.
    Resubscribe,
    /// Where this terminal's window is now looking, after a scroll-back key.
    Scrollback,
}

/// Runs the attachment's input, output and connection in one loop.
#[expect(
    clippy::too_many_arguments,
    reason = "one attachment is its client, its session, its terminal and everything it started with"
)]
async fn drive(
    client: &mut LocalClient,
    descriptor: &WorkerDescriptor,
    typed_during_the_probe: Vec<u8>,
    attached: Attached,
    input: &mut tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    output: &Arc<std::fs::File>,
    terminal: &ControllingTerminal,
    resized: Option<&mut WindowChanges>,
    display: &mut crate::render::ProjectedDisplay,
    follow_live: bool,
) -> AttachOutcome {
    use std::io::Write as _;

    let session_id = descriptor.session_id;
    let attachment_id = attached.attachment_id;
    // `None` where this terminal may not type. What it types is then dropped rather than sent:
    // the host has already refused it the lease, so every keystroke would be one refused request,
    // and the attachment would end on the first of them. Watching is what is left, and watching is
    // what this attachment asked for when it chose not to be asked about.
    let epoch = attached.lease_epoch;
    let mut geometry_epoch = attached.geometry_epoch;
    let mut owns_geometry = attached.owns_geometry;
    let mut resized = resized;

    let mut sequence = 0_u64;
    let mut outstanding: std::collections::BTreeMap<kr_protocol::ids::RequestId, Outstanding> =
        std::collections::BTreeMap::new();
    let mut next_request = 1_u64;
    // The row this terminal's window starts at while it is looking above the live page. `None` is
    // the live screen. It is reported with every size report as well, so a window the person has
    // scrolled back to stays where they put it when they resize their terminal.
    let mut parked: Option<u64> = None;

    // What the person typed while the host was asking the terminal what it was. It was buffered
    // rather than discarded, and it is the first thing the application receives, in the order it
    // was typed in.
    if !typed_during_the_probe.is_empty()
        && let Some(epoch) = epoch
    {
        let request_id = kr_protocol::ids::RequestId::new(next_request);
        next_request += 1;
        if !send_input(
            client,
            request_id,
            session_id,
            attachment_id,
            epoch,
            sequence,
            typed_during_the_probe,
        )
        .await
        {
            return AttachOutcome::DeliveryUncertain(
                "the connection ended while input was being sent".to_owned(),
            );
        }
        outstanding.insert(request_id, Outstanding::Input(sequence));
        sequence += 1;
    }
    loop {
        tokio::select! {
            // Biased towards the worker, so output and refusals are seen before more input is sent.
            biased;
            message = client.recv() => {
                match message {
                    Ok(ControlFrame::Notification(notification)) => {
                        if notification.event_type.as_str() == "session.output"
                            && let Ok(event) = notification
                                .payload
                                .to_typed::<kr_protocol::recovery::OutputEvent>()
                        {
                            let mut handle = output.as_ref();
                            if handle.write_all(event.bytes.as_slice()).is_err() {
                                return AttachOutcome::Disconnected;
                            }
                            let _ = handle.flush();
                        }
                        // A projected attachment is sent the canonical grid as state and draws it
                        // itself. The renderer is shared with the client library, so this terminal
                        // and the companion application put a canonical cell in the same place.
                        if crate::render::is_projection_event(notification.event_type.as_str()) {
                            let Some(event) =
                                crate::render::decode(
                                    notification.event_type.as_str(),
                                    &notification.payload,
                                )
                            else {
                                // A payload this build cannot decode is not drawn and not guessed
                                // at. What is held goes with it, because the next thing drawn has
                                // to be a screen this terminal was actually sent.
                                display.discard();
                                let request_id = kr_protocol::ids::RequestId::new(next_request);
                                next_request += 1;
                                if !resubscribe(client, descriptor, request_id, attachment_id).await
                                {
                                    return AttachOutcome::Disconnected;
                                }
                                outstanding.insert(request_id, Outstanding::Resubscribe);
                                continue;
                            };
                            let changed = notification.event_type.as_str()
                                == kr_protocol::projection::PROJECTION_DELTA_EVENT;
                            let drawn = display.apply(event);
                            // The client's own choice, not the session's: a person who asked to
                            // follow the live screen is taken back to it the moment the session
                            // writes, and one who did not stays where they scrolled to while the
                            // output goes on arriving underneath.
                            if follow_live && changed && parked.is_some() {
                                let request_id = kr_protocol::ids::RequestId::new(next_request);
                                next_request += 1;
                                if let Ok(size) = terminal.size()
                                    && size.columns > 0
                                    && size.rows > 0
                                {
                                    let params =
                                        kr_protocol::attachment::AttachmentViewportParams {
                                            attachment_id,
                                            dimensions: Dimensions::new(
                                                u64::from(size.columns),
                                                u64::from(size.rows),
                                            ),
                                            position: Nullable(None),
                                        };
                                    if !send_geometry(
                                        client,
                                        descriptor,
                                        request_id,
                                        Method::AttachmentViewport,
                                        &params,
                                    )
                                    .await
                                    {
                                        return AttachOutcome::Disconnected;
                                    }
                                    outstanding.insert(request_id, Outstanding::Scrollback);
                                }
                            }
                            if !drawn.bytes.is_empty() {
                                let mut handle = output.as_ref();
                                if handle.write_all(&drawn.bytes).is_err() {
                                    return AttachOutcome::Disconnected;
                                }
                                let _ = handle.flush();
                            }
                            if drawn.resubscribe {
                                let request_id = kr_protocol::ids::RequestId::new(next_request);
                                next_request += 1;
                                if !resubscribe(client, descriptor, request_id, attachment_id).await
                                {
                                    return AttachOutcome::Disconnected;
                                }
                                outstanding.insert(request_id, Outstanding::Resubscribe);
                            }

                        }
                        // A resynchronisation marker means this terminal's view of the session is
                        // no longer continuous: its size changed, its presentation changed, or it
                        // fell behind. It is not a reason to end the attachment — a person resizing
                        // a window would lose their session — so the marker is answered by asking
                        // for the screen again, which is what the marker is for.
                        if notification.event_type.as_str() == "session.resync" {
                            // Whatever this terminal was holding is no longer the session's screen.
                            // It is discarded before the fresh one is asked for, so nothing is
                            // drawn from it in between.
                            display.discard();
                            let request_id = kr_protocol::ids::RequestId::new(next_request);
                            next_request += 1;
                            if !resubscribe(client, descriptor, request_id, attachment_id).await {
                                return AttachOutcome::Disconnected;
                            }
                            outstanding.insert(request_id, Outstanding::Resubscribe);
                        }
                        // This attachment was ended somewhere else, which is what `kr detach` from
                        // another window does. The terminal comes back and the command finishes.
                        if notification.event_type.as_str() == "session.detached" {
                            return AttachOutcome::Detached;
                        }
                    }
                    Ok(ControlFrame::Response(response)) => {
                        let Some(what) = outstanding.remove(&response.request_id) else {
                            continue;
                        };
                        match (what, response.outcome) {
                            // A size report is a report, not an insistence. Another attachment may
                            // own the size, and the answer then says so; the terminal is shown that
                            // size rather than taking it, and the attachment carries on.
                            (Outstanding::Resize, outcome) => match outcome {
                                kr_protocol::envelope::Outcome::Ok(value) => {
                                    if let Ok(result) = value
                                        .to_typed::<kr_protocol::attachment::GeometryResult>()
                                    {
                                        geometry_epoch = result.geometry.epoch;
                                        owns_geometry =
                                            result.geometry.owner.as_ref() == Some(&attachment_id);
                                    }
                                }
                                // Somebody else owns the size now, or owns it at another epoch.
                                // The refusal carries neither, so this asks the only question whose
                                // answer does: a viewport report, which says who owns the size and
                                // at which epoch and changes nothing. Without it this terminal would
                                // go on sending owner-only resizes for the rest of the attachment
                                // and go on being refused them.
                                kr_protocol::envelope::Outcome::Error(error)
                                    if error.code == ErrorCode::GeometryNotOwner =>
                                {
                                    owns_geometry = false;
                                    let Ok(size) = terminal.size() else {
                                        continue;
                                    };
                                    if size.columns == 0 || size.rows == 0 {
                                        // A terminal with no size is one the host would refuse
                                        // anyway. Asking would swap one refusal for another.
                                        continue;
                                    }
                                    let request_id =
                                        kr_protocol::ids::RequestId::new(next_request);
                                    next_request += 1;
                                    let params =
                                        kr_protocol::attachment::AttachmentViewportParams {
                                            attachment_id,
                                            dimensions: Dimensions::new(
                                                u64::from(size.columns),
                                                u64::from(size.rows),
                                            ),
                                            position: Nullable(
                                                parked.map(|row| {
                                                    ViewportPosition::Row(U64::new(row))
                                                }),
                                            ),
                                        };
                                    if !send_geometry(
                                        client,
                                        descriptor,
                                        request_id,
                                        Method::AttachmentViewport,
                                        &params,
                                    )
                                    .await
                                    {
                                        return AttachOutcome::Disconnected;
                                    }
                                    outstanding.insert(request_id, Outstanding::Viewport);
                                }
                                kr_protocol::envelope::Outcome::Error(_) => {}
                            },
                            // A viewport report answers with the presentation it produced as well
                            // as the geometry, so it has its own result type and its own decoder.
                            (Outstanding::Viewport, outcome) => {
                                if let kr_protocol::envelope::Outcome::Ok(value) = outcome
                                    && let Ok(result) = value.to_typed::<
                                        kr_protocol::attachment::AttachmentViewportResult,
                                    >()
                                {
                                    parked = landed(result.position.0);
                                    geometry_epoch = result.geometry.epoch;
                                    owns_geometry =
                                        result.geometry.owner.as_ref() == Some(&attachment_id);
                                    // A report this terminal made because a resize was refused for
                                    // a stale epoch answers with the epoch it should have quoted.
                                    // The size it asked for is still the size the person is looking
                                    // at, so it asks again, once, with what the answer said.
                                    if owns_geometry
                                        && let Ok(size) = terminal.size()
                                        && size.columns > 0
                                        && size.rows > 0
                                    {
                                        let dimensions = Dimensions::new(
                                            u64::from(size.columns),
                                            u64::from(size.rows),
                                        );
                                        if dimensions != result.geometry.dimensions {
                                            let request_id =
                                                kr_protocol::ids::RequestId::new(next_request);
                                            next_request += 1;
                                            let params =
                                                kr_protocol::attachment::TerminalResizeParams {
                                                    attachment_id,
                                                    dimensions,
                                                    expected_geometry_epoch: geometry_epoch,
                                                };
                                            if !send_geometry(
                                                client,
                                                descriptor,
                                                request_id,
                                                Method::TerminalResize,
                                                &params,
                                            )
                                            .await
                                            {
                                                return AttachOutcome::Disconnected;
                                            }
                                            outstanding.insert(request_id, Outstanding::Resize);
                                        }
                                    }
                                }
                            }
                            (
                                Outstanding::Input(sent),
                                kr_protocol::envelope::Outcome::Error(error),
                            ) => {
                                return match error.code {
                                    ErrorCode::LeaseLost => AttachOutcome::LeaseLost,
                                    ErrorCode::SessionClosed => AttachOutcome::SessionClosed,
                                    code => AttachOutcome::DeliveryUncertain(format!(
                                        "{code} at input {sent}: {}",
                                        error.message
                                    )),
                                };
                            }
                            (Outstanding::Input(_), kr_protocol::envelope::Outcome::Ok(_)) => {}
                            // A scroll-back report answers with the row the window actually
                            // landed on, which is not always the one it asked for: a row the
                            // session has given up becomes the oldest one it still holds, and a
                            // row inside the live page becomes the live screen. The pages that
                            // cover it arrive as ordinary output.
                            (Outstanding::Scrollback, outcome) => {
                                if let kr_protocol::envelope::Outcome::Ok(value) = outcome
                                    && let Ok(result) = value.to_typed::<
                                        kr_protocol::attachment::AttachmentViewportResult,
                                    >()
                                {
                                    parked = landed(result.position.0);
                                }
                            }
                            // The screen follows as ordinary output. A refusal means the session no
                            // longer has this attachment, which is the end of it.
                            (Outstanding::Resubscribe, outcome) => {
                                if let kr_protocol::envelope::Outcome::Error(error) = outcome {
                                    return match error.code {
                                        ErrorCode::SessionClosed => AttachOutcome::SessionClosed,
                                        _ => AttachOutcome::Disconnected,
                                    };
                                }
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(_) => return AttachOutcome::Disconnected,
                }
            }
            () = wait_for_resize(&mut resized) => {
                // The outer terminal changed size. The session is told, so the application is
                // redrawn at the size the person is actually looking at. The request goes out on
                // this loop's own connection and its answer comes back through the arm above:
                // calling out to a separate request-and-wait here would read this attachment's
                // output, resynchronisation and detach events as though they were the answer.
                let Ok(size) = terminal.size() else {
                    continue;
                };
                let dimensions = Dimensions::new(
                    u64::from(size.columns),
                    u64::from(size.rows),
                );
                let request_id = kr_protocol::ids::RequestId::new(next_request);
                next_request += 1;
                // The owner moves the session's size; anybody else reports the size it is
                // looking at, which changes which presentation it is served and nothing else.
                let (sent, what) = if owns_geometry {
                    let params = kr_protocol::attachment::TerminalResizeParams {
                        attachment_id,
                        dimensions,
                        expected_geometry_epoch: geometry_epoch,
                    };
                    (
                        send_geometry(
                            client,
                            descriptor,
                            request_id,
                            Method::TerminalResize,
                            &params,
                        )
                        .await,
                        Outstanding::Resize,
                    )
                } else {
                    let params = kr_protocol::attachment::AttachmentViewportParams {
                        attachment_id,
                        dimensions,
                        position: Nullable(
                            parked.map(|row| ViewportPosition::Row(U64::new(row))),
                        ),
                    };
                    (
                        send_geometry(
                            client,
                            descriptor,
                            request_id,
                            Method::AttachmentViewport,
                            &params,
                        )
                        .await,
                        Outstanding::Viewport,
                    )
                };
                if !sent {
                    return AttachOutcome::Disconnected;
                }
                outstanding.insert(request_id, what);
            }
            bytes = input.recv() => {
                let Some(bytes) = bytes else {
                    // The terminal's own input ended. Nothing is left to forward.
                    return AttachOutcome::Detached;
                };
                // The scroll-back keys first. They belong to this terminal's own presentation:
                // they move the window it is looking through and never reach the session, so an
                // attachment that may not type can still read what is above the live page.
                let (scrolls, bytes) = split_scrollback(&bytes);
                for scroll in scrolls {
                    let Ok(size) = terminal.size() else {
                        continue;
                    };
                    if size.columns == 0 || size.rows == 0 {
                        continue;
                    }
                    let Some(position) = scrolled(parked, scroll, scroll_step(size.rows)) else {
                        // Already on the live screen, which is as far forward as a window goes.
                        continue;
                    };
                    let request_id = kr_protocol::ids::RequestId::new(next_request);
                    next_request += 1;
                    let params = kr_protocol::attachment::AttachmentViewportParams {
                        attachment_id,
                        dimensions: Dimensions::new(
                            u64::from(size.columns),
                            u64::from(size.rows),
                        ),
                        position: Nullable(Some(position)),
                    };
                    if !send_geometry(
                        client,
                        descriptor,
                        request_id,
                        Method::AttachmentViewport,
                        &params,
                    )
                    .await
                    {
                        return AttachOutcome::Disconnected;
                    }
                    outstanding.insert(request_id, Outstanding::Scrollback);
                }
                if bytes.is_empty() {
                    continue;
                }
                let Some(epoch) = epoch else {
                    // This terminal may not type. The bytes go nowhere, and the attachment goes on
                    // watching rather than ending on a refusal it already knows about.
                    continue;
                };
                let request_id = kr_protocol::ids::RequestId::new(next_request);
                next_request += 1;
                if !send_input(
                    client,
                    request_id,
                    session_id,
                    attachment_id,
                    epoch,
                    sequence,
                    bytes,
                )
                .await
                {
                    // The bytes were handed to a connection that has gone. Whether they arrived
                    // cannot be established from here, and the exit code says so.
                    return AttachOutcome::DeliveryUncertain(
                        "the connection ended while input was being sent".to_owned(),
                    );
                }
                outstanding.insert(request_id, Outstanding::Input(sequence));
                sequence += 1;
            }
        }
    }
}

/// Asks for the session's screen again, on this loop's own connection.
///
/// A resynchronisation marker says the view is no longer continuous; this is how the view is made
/// continuous again. The screen arrives as ordinary output on the same stream.
async fn resubscribe(
    client: &mut LocalClient,
    descriptor: &WorkerDescriptor,
    request_id: kr_protocol::ids::RequestId,
    attachment_id: kr_protocol::ids::AttachmentId,
) -> bool {
    let mut streams = kr_protocol::scalars::CanonicalSet::new();
    streams.insert(kr_protocol::recovery::EventStream::Output);
    let params = kr_protocol::recovery::EventsSubscribeParams {
        session_id: descriptor.session_id,
        attachment_id,
        streams,
        from_cursor: kr_protocol::scalars::Nullable::null(),
    };
    let Ok(params) = kr_protocol::envelope::ParamsValue::from_typed(&params) else {
        return false;
    };
    let request = kr_protocol::envelope::Request {
        request_id,
        method: Method::EventsSubscribe.into(),
        method_version: kr_protocol::method::MethodVersion::V1,
        params,
    };
    client
        .writer()
        .write_message(&ControlFrame::Request(request))
        .await
        .is_ok()
}

/// Writes one batch of terminal input on this loop's own connection.
///
/// Returns whether it reached the socket. Its answer comes back through the loop, like every other
/// answer on this connection.
async fn send_input(
    client: &mut LocalClient,
    request_id: kr_protocol::ids::RequestId,
    session_id: SessionId,
    attachment_id: kr_protocol::ids::AttachmentId,
    epoch: InputLeaseEpoch,
    sequence: u64,
    bytes: Vec<u8>,
) -> bool {
    let params = kr_protocol::input::InputWriteParams {
        session_id,
        attachment_id,
        epoch,
        sequence: kr_protocol::ids::InputSequence::new(sequence),
        bytes: kr_protocol::scalars::Bytes::new(bytes),
    };
    let Ok(params) = kr_protocol::envelope::ParamsValue::from_typed(&params) else {
        return false;
    };
    client
        .writer()
        .write_message(&ControlFrame::Request(kr_protocol::envelope::Request {
            request_id,
            method: Method::InputWrite.into(),
            method_version: kr_protocol::method::MethodVersion::V1,
            params,
        }))
        .await
        .is_ok()
}

/// Writes one size report on this loop's own connection.
///
/// Returns whether it reached the socket. The answer comes back through the loop, like every other
/// answer on this connection.
async fn send_geometry<T: serde::Serialize + ?Sized>(
    client: &mut LocalClient,
    descriptor: &WorkerDescriptor,
    request_id: kr_protocol::ids::RequestId,
    method: Method,
    params: &T,
) -> bool {
    let Ok(params) = kr_protocol::envelope::ParamsValue::from_typed(params) else {
        return false;
    };
    let mutation = kr_protocol::envelope::MutationRequest {
        request_id,
        method: method.into(),
        method_version: kr_protocol::method::MethodVersion::V1,
        action_id: kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
        grant_id: kr_protocol::scalars::Nullable::null(),
        target: crate::attach::target(descriptor),
        expected: kr_protocol::envelope::ParamsValue::empty(),
        action_window_id: client.action_window().action_window_id.clone(),
        requested_ttl_ms: kr_protocol::scalars::DurationMs::new(
            kr_protocol::limits::DEFAULT_MUTATION_TTL.get(),
        ),
        params,
    };
    client
        .writer()
        .write_message(&ControlFrame::Mutation(Box::new(mutation)))
        .await
        .is_ok()
}

/// How this platform reports that the terminal changed size.
///
/// Unix delivers a signal. Windows delivers a console input record instead, which arrives on the
/// input stream this loop is already reading, so there is nothing separate to wait on there.
#[cfg(unix)]
pub type WindowChanges = tokio::signal::unix::Signal;

/// How this platform reports that the terminal changed size.
#[cfg(not(unix))]
pub type WindowChanges = std::convert::Infallible;

/// Returns the stream of window-size changes, where the platform has one.
#[cfg(unix)]
fn window_changes() -> Option<WindowChanges> {
    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change()).ok()
}

/// Returns the stream of window-size changes, where the platform has one.
#[cfg(not(unix))]
const fn window_changes() -> Option<WindowChanges> {
    None
}

/// Waits for the next window-size change, or for ever when the platform reports none.
#[cfg(unix)]
async fn wait_for_resize(resized: &mut Option<&mut WindowChanges>) {
    match resized {
        Some(signal) => {
            signal.recv().await;
        }
        None => std::future::pending().await,
    }
}

/// Waits for the next window-size change, or for ever when the platform reports none.
#[cfg(not(unix))]
async fn wait_for_resize(_resized: &mut Option<&mut WindowChanges>) {
    std::future::pending().await
}

#[cfg(test)]
mod tests {
    use super::{
        SCROLL_BACK_KEY, SCROLL_FORWARD_KEY, Scroll, landed, scroll_step, scrolled,
        split_scrollback,
    };
    use kr_protocol::attachment::ViewportPosition;

    /// Section 8 line 459: a scroll-back key is this terminal's own, and never the session's.
    #[test]
    fn the_scroll_back_keys_never_reach_the_session() {
        let (scrolls, input) = split_scrollback(SCROLL_BACK_KEY);
        assert_eq!(scrolls, vec![Scroll::Back]);
        assert!(
            input.is_empty(),
            "nothing of it is written into the application: {input:?}"
        );
        let (scrolls, input) = split_scrollback(SCROLL_FORWARD_KEY);
        assert_eq!(scrolls, vec![Scroll::Forward]);
        assert!(input.is_empty());
    }

    #[test]
    fn everything_else_the_person_typed_is_theirs() {
        let mut typed = b"ls -l".to_vec();
        typed.extend_from_slice(SCROLL_BACK_KEY);
        typed.extend_from_slice(b"\r");
        typed.extend_from_slice(SCROLL_FORWARD_KEY);
        typed.extend_from_slice(b"\x1b[5~\x1b");
        let (scrolls, input) = split_scrollback(&typed);
        assert_eq!(scrolls, vec![Scroll::Back, Scroll::Forward]);
        assert_eq!(
            input, b"ls -l\r\x1b[5~\x1b",
            "an unshifted Page Up and a lone Escape are the application's"
        );
    }

    #[test]
    fn a_step_is_a_window_less_the_line_that_joins_the_two_pages() {
        assert_eq!(scroll_step(24), 23);
        assert_eq!(scroll_step(2), 1);
        assert_eq!(scroll_step(1), 1, "a window of one row still moves");
        assert_eq!(scroll_step(0), 1);
    }

    #[test]
    fn a_window_on_the_live_screen_asks_by_distance_and_then_by_row() {
        let first = scrolled(None, Scroll::Back, 23).expect("a window can go back from live");
        assert!(
            matches!(first, ViewportPosition::Above(rows) if rows.get() == 23),
            "a client with no row identifier above its page asks by distance: {first:?}"
        );
        // The host answered with the row it landed on, and from there the window names it.
        let next = scrolled(Some(500), Scroll::Back, 23).expect("and keeps going back");
        assert!(matches!(next, ViewportPosition::Row(row) if row.get() == 477));
        let forward = scrolled(Some(477), Scroll::Forward, 23).expect("and comes back down");
        assert!(matches!(forward, ViewportPosition::Row(row) if row.get() == 500));
        assert!(
            scrolled(None, Scroll::Forward, 23).is_none(),
            "the live screen is as far forward as a window goes"
        );
        let floor = scrolled(Some(10), Scroll::Back, 23).expect("a window near the beginning");
        assert!(
            matches!(floor, ViewportPosition::Row(row) if row.get() == 0),
            "which asks for the first row rather than for one below it: {floor:?}"
        );
    }

    #[test]
    fn where_the_window_landed_is_read_from_the_answer() {
        assert_eq!(landed(None), None, "no position at all is the live screen");
        assert_eq!(
            landed(Some(ViewportPosition::Row(kr_protocol::scalars::U64::new(
                42
            )))),
            Some(42)
        );
    }
}

//! What a paired device is told of a failure.
//!
//! A message built from a failure on this host can name the host: a path under the home
//! directory, which names the account; the numbers of the accounts that own a directory; the
//! command that would mend it. The owner at this machine is told all of it, and a paired device
//! is not. This module is the one place that decides, and it decides at the three points where
//! this host's words reach a device that is not at the machine: the write boundary of an
//! authorised connection, the refusal of a connection that is not admitted, and the pairing
//! surface a candidate reaches before it is paired.
//!
//! The rule: an error a device receives keeps its code, its retry category and its diagnostic
//! identifier. Its message is kept when it names nothing of this host. A command quoted in
//! backticks is a quotation with an end, so it is replaced by `a command` and the sentence it was
//! in is kept. Anything else that names the host (a path of any kind, the number of an account, the
//! name of a program that changes who may use a file) has no end this module can find, so the device
//! is given the part of the message that comes before the first such name, if that is a clause of
//! its own, and otherwise a sentence composed here from the code.
//!
//! The same rule reaches an error wherever it is, because the text of an error that has already
//! been made (a worker's, one a store kept, one a catalogue receipt holds) cannot be made again:
//! an error in a response, a receipt, or anywhere inside a result. A closure's list of what it left
//! behind is the one other place this host's failures are written as plain text, and it is held to
//! the same rule.

use std::borrow::Cow;
use std::sync::Arc;

use kr_cbor::{CanonicalMap, CanonicalValue};
use kr_protocol::envelope::{ControlFrame, Notification, Outcome, ParamsValue, Response};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::method::Method;
use kr_protocol::scalars::Nullable;
use kr_transport::preauth::{ConnectionPeer, PairingMethod, PairingSurface};

/// What follows a clause kept from a message, or a description of what failed, to say why the rest
/// is not here.
const WHY_NOT_SHOWN: &str = "the detail names the host and is not sent to a paired device";

/// As [`WHY_NOT_SHOWN`], for a refusal withheld whatever it says, because the host cannot tell the
/// agent's words from its own.
const WHY_WHATEVER_IT_SAYS: &str = "the detail is not sent to a paired device";

/// As [`WHY_NOT_SHOWN`], for what the pairing store or the rendezvous service reported to a
/// candidate that has not paired.
const WHY_THE_STORE: &str = "what the service reported is not sent to a candidate";

/// The longest message an error carries.
const LONGEST_MESSAGE: usize = kr_protocol::error::MAX_ERROR_MESSAGE_LEN;

/// The schemes of the web addresses a message may quote: they name another host and not this one.
/// Any other scheme (`file`, `unix`, `ssh`) names a place on this machine or an account on another.
const WEB_SCHEMES: [&str; 6] = ["http", "https", "ws", "wss", "socks5", "socks5h"];

/// The words that introduce an account's number.
const ACCOUNT_WORDS: [&str; 7] = ["user", "owner", "uid", "gid", "group", "account", "gui"];

/// The programs whose use on this host a message can tell a person to repeat.
const COMMAND_WORDS: [&str; 6] = ["chmod", "chown", "sudo", "doas", "systemctl", "launchctl"];

/// Refusals of the project service whose reason a device is told without the place: what the host
/// says begins to name a directory of its own where `marker` stands, and the device is given the
/// sentence beside it. The sentences say where in terms of the location the device's grant names,
/// which is all of the place the device has.
const KNOWN_REASONS: [(&str, &str); 2] = [
    (
        "a filesystem is mounted at ",
        "a filesystem is mounted inside the location the grant names",
    ),
    (
        " its objects/info/alternates names ",
        "the repository names objects outside the location the grant names",
    ),
];

/// The ends of the three refusals that name where in a message a field is, as a JSON pointer.
///
/// The place is the one part of such a refusal that begins with a slash and names nothing of this
/// host.
const POINTER_ENDS: [&str; 3] = [
    " carries a field it does not declare",
    " names a variant in ",
    " carries a member of an extension that is not negotiated there",
];

/// The error `error` is for a device: itself when it names nothing of this host, and otherwise the
/// error the module note describes.
#[must_use]
pub(crate) fn error_for_a_device(error: &ProtocolError) -> Cow<'_, ProtocolError> {
    match message_for_a_device(error.code, &error.message) {
        None => Cow::Borrowed(error),
        Some(message) => Cow::Owned(with_message(error, message)),
    }
}

/// What a device is told in place of `message`, the text of an error of `code`, or `None` when it
/// is told the message itself.
fn message_for_a_device(code: ErrorCode, message: &str) -> Option<String> {
    let without_commands = without_quoted_commands(message);
    let text = without_commands.as_deref().unwrap_or(message);
    let told = match first_naming(text) {
        None => without_commands?,
        Some(at) => match known_reason(text) {
            Some(reason) => reason.to_owned(),
            None => match clause_before(text, at) {
                Some(clause) => format!("{clause}; {WHY_NOT_SHOWN}"),
                None => sentence_for(code, WHY_NOT_SHOWN),
            },
        },
    };
    // An error never carries more than its limit, so a clause kept from a long message gives way to
    // the sentence of its code.
    Some(if told.len() > LONGEST_MESSAGE {
        sentence_for(code, WHY_NOT_SHOWN)
    } else {
        told
    })
}

/// The sentence a device is given for a refusal whose reason the host's text says beside its place.
fn known_reason(text: &str) -> Option<&'static str> {
    KNOWN_REASONS
        .iter()
        .find(|(marker, _)| text.contains(marker))
        .map(|(_, reason)| *reason)
}

/// `frame` as a device is given it: every error in it as [`error_for_a_device`] gives it, and
/// every closure's account of what it left behind held to the same rule.
///
/// A receipt whose message was replaced says so, with the flag the receipt has for it. A frame
/// that carries nothing to replace is returned as it is.
#[must_use]
pub(crate) fn frame_for_a_device(frame: &ControlFrame) -> Cow<'_, ControlFrame> {
    match frame {
        ControlFrame::Response(response) => match &response.outcome {
            Outcome::Error(error) => match error_for_a_device(error) {
                Cow::Borrowed(_) => Cow::Borrowed(frame),
                Cow::Owned(error) => Cow::Owned(ControlFrame::Response(Response {
                    request_id: response.request_id,
                    outcome: Outcome::Error(error),
                })),
            },
            Outcome::Ok(value) => match shown_value(value.as_value()) {
                None => Cow::Borrowed(frame),
                Some(value) => Cow::Owned(ControlFrame::Response(Response {
                    request_id: response.request_id,
                    outcome: Outcome::Ok(ParamsValue::new(value)),
                })),
            },
        },
        ControlFrame::Receipt(response) => {
            let Some(error) = response.receipt.error.0.as_ref() else {
                return Cow::Borrowed(frame);
            };
            let Cow::Owned(shown) = error_for_a_device(error) else {
                return Cow::Borrowed(frame);
            };
            let mut response = response.as_ref().clone();
            response.receipt.error = Nullable::some(shown);
            response.receipt.error_withheld = true;
            Cow::Owned(ControlFrame::Receipt(Box::new(response)))
        }
        ControlFrame::Notification(notification)
            if notification.event_type.as_str() == kr_protocol::session::SESSION_CLOSED_EVENT =>
        {
            match shown_value(notification.payload.as_value()) {
                None => Cow::Borrowed(frame),
                Some(payload) => Cow::Owned(ControlFrame::Notification(Notification {
                    payload: ParamsValue::new(payload),
                    ..notification.clone()
                })),
            }
        }
        _ => Cow::Borrowed(frame),
    }
}

/// Whether `frame` is at most `limit` bytes as the control stream counts them.
#[must_use]
pub(crate) fn fits(frame: &ControlFrame, limit: usize) -> bool {
    kr_cbor::to_canonical_value(frame).is_ok_and(|value| kr_cbor::encoded_len(&value) <= limit)
}

/// What a device is told of a response that no longer fits its frame once what names the host was
/// taken out of it, or `None` for a frame that answers no request.
///
/// It is refused as a worker refuses an answer larger than the frame the device declared.
#[must_use]
pub(crate) fn too_large_for_the_device(frame: &ControlFrame) -> Option<ControlFrame> {
    let ControlFrame::Response(Response { request_id, .. }) = frame else {
        return None;
    };
    Some(ControlFrame::Response(Response {
        request_id: *request_id,
        outcome: Outcome::Error(ProtocolError::new(
            ErrorCode::InvalidArgument,
            "this answer is larger than the frame this device said it can receive",
        )),
    }))
}

/// The answer to `method` as a device is given it, when the method puts a prompt, a steer, a
/// cancellation, an approval or a plugin's action to the agent a session runs.
///
/// An agent's refusal is the agent's own words about what it was asked, and they quote what it
/// was working on. This host cannot tell them from its own sentences about the request, so a
/// refusal of the argument, of the agent itself, or an end that left the outcome unknown, is
/// replaced by a sentence composed from its code. The code and the retry category stay.
#[must_use]
pub(crate) fn upstream_words(method: Option<Method>, frame: ControlFrame) -> ControlFrame {
    if !method.is_some_and(puts_to_the_agent) {
        return frame;
    }
    match frame {
        ControlFrame::Response(Response {
            request_id,
            outcome: Outcome::Error(error),
        }) if matches!(
            error.code,
            ErrorCode::InvalidArgument | ErrorCode::UpstreamUnavailable | ErrorCode::OutcomeUnknown
        ) =>
        {
            ControlFrame::Response(Response {
                request_id,
                outcome: Outcome::Error(with_message(
                    &error,
                    sentence_for(error.code, WHY_WHATEVER_IT_SAYS),
                )),
            })
        }
        other => other,
    }
}

/// Whether `method` hands words to the agent of a session and takes its refusal back.
const fn puts_to_the_agent(method: Method) -> bool {
    matches!(
        method,
        Method::AgentPromptSubmit
            | Method::AgentPromptQueue
            | Method::AgentTurnSteer
            | Method::AgentTurnCancel
            | Method::AgentApprovalRespond
            | Method::PluginActionInvoke
    )
}

/// The pairing surface a candidate reaches, held to the rule.
///
/// A candidate is not yet paired and has proved nothing but its endpoint, so what the pairing
/// store or the rendezvous service reported of themselves is never shown to it, whatever it says.
#[derive(Debug)]
pub(crate) struct ForACandidate(pub(crate) Arc<dyn PairingSurface>);

impl PairingSurface for ForACandidate {
    fn call(
        &self,
        method: PairingMethod,
        peer: &ConnectionPeer,
        params: &ParamsValue,
    ) -> Result<ParamsValue, ProtocolError> {
        self.0.call(method, peer, params).map_err(|error| {
            if matches!(
                error.code,
                ErrorCode::StorageUnavailable
                    | ErrorCode::RendezvousUnavailable
                    | ErrorCode::RendezvousConfigError
            ) {
                with_message(&error, sentence_for(error.code, WHY_THE_STORE))
            } else {
                error_for_a_device(&error).into_owned()
            }
        })
    }
}

/// The clause of `message` that ends before byte `at`, when one does: what comes before the last
/// colon or semicolon in the part that precedes it.
fn clause_before(message: &str, at: usize) -> Option<&str> {
    let head = &message[..at];
    let end = [head.rfind(": "), head.rfind("; ")]
        .into_iter()
        .flatten()
        .max()?;
    let clause = head[..end].trim();
    (!clause.is_empty()).then_some(clause)
}

/// The sentence a code gets, for a message of which nothing is kept, with `why` it is not shown.
fn sentence_for(code: ErrorCode, why: &str) -> String {
    // An end nobody can establish is not a failure, and a person who reads it as one sends the
    // work twice.
    if code == ErrorCode::OutcomeUnknown {
        return format!("the host cannot say whether this request was carried out; {why}");
    }
    format!(
        "the host could not complete this request ({}); {why}",
        what_failed(code)
    )
}

/// What a code says went wrong, in words that name nothing.
const fn what_failed(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::ResourceUnavailable => {
            "a file, directory, socket or program it needs was unavailable"
        }
        ErrorCode::StorageUnavailable => "its own storage was unavailable",
        ErrorCode::PermissionDenied => "one of its own files or accounts refused this",
        ErrorCode::HostNotConfigured => "it is not set up for this",
        ErrorCode::EnvironmentUnavailable => "the environment's directory could not be used",
        ErrorCode::TerminalUnavailable => "a terminal window could not be opened",
        ErrorCode::UpstreamUnavailable => {
            "a program or service it relies on refused or was out of reach"
        }
        ErrorCode::RendezvousUnavailable => "the rendezvous service was out of reach",
        ErrorCode::RendezvousConfigError => "its rendezvous setting is wrong",
        ErrorCode::ClockUntrusted => "its clock is not trusted yet",
        ErrorCode::InvalidArgument => "the request was refused",
        _ => "the request failed on the host",
    }
}

/// `error` with `message` in place of its own, and nothing else changed.
fn with_message(error: &ProtocolError, message: String) -> ProtocolError {
    ProtocolError {
        message,
        ..error.clone()
    }
}

/// `value` with every error in it, and every closure's account of what it left, as a device is
/// given them, or `None` when nothing in it changes.
fn shown_value(value: &CanonicalValue) -> Option<CanonicalValue> {
    match value {
        CanonicalValue::Map(map) => {
            if let Some((code, message)) = as_an_error(map) {
                return message_for_a_device(code, message)
                    .map(|shown| with_text(map, "message", shown));
            }
            let shown: Vec<Option<CanonicalValue>> = map
                .entries()
                .iter()
                .map(|(key, child)| {
                    if key == "surviving" {
                        shown_survivors(child)
                    } else {
                        shown_value(child)
                    }
                })
                .collect();
            if shown.iter().all(Option::is_none) {
                return None;
            }
            let error_changed = map
                .entries()
                .iter()
                .zip(&shown)
                .any(|((key, _), shown)| key == "error" && shown.is_some());
            let mut entries: Vec<(String, CanonicalValue)> = map
                .entries()
                .iter()
                .zip(shown)
                .map(|((key, child), shown)| (key.clone(), shown.unwrap_or_else(|| child.clone())))
                .collect();
            // A receipt whose error was replaced says so.
            if error_changed && map.get("payload_digest").is_some() {
                entries.retain(|(key, _)| key != "error_withheld");
                entries.push(("error_withheld".to_owned(), CanonicalValue::Bool(true)));
            }
            Some(rebuilt(entries))
        }
        CanonicalValue::Array(items) => {
            let shown: Vec<Option<CanonicalValue>> = items.iter().map(shown_value).collect();
            if shown.iter().all(Option::is_none) {
                return None;
            }
            Some(CanonicalValue::Array(
                items
                    .iter()
                    .zip(shown)
                    .map(|(item, shown)| shown.unwrap_or_else(|| item.clone()))
                    .collect(),
            ))
        }
        _ => None,
    }
}

/// The code and the message of `map`, when it is exactly the shape of a protocol error: the three
/// members every error has, the two it may have, nothing else, and a code this build defines.
fn as_an_error(map: &CanonicalMap) -> Option<(ErrorCode, &str)> {
    let text = |key: &str| match map.get(key) {
        Some(CanonicalValue::Text(text)) => Some(text.as_str()),
        _ => None,
    };
    let (code, message, _) = (text("code")?, text("message")?, text("retry")?);
    if !map.entries().iter().all(|(key, _)| {
        matches!(
            key.as_str(),
            "code" | "message" | "retry" | "diagnostic_id" | "link_fenced"
        )
    }) {
        return None;
    }
    Some((ErrorCode::from_wire(code)?, message))
}

/// `map` with the text under `key` replaced by `text`.
fn with_text(map: &CanonicalMap, key: &str, text: String) -> CanonicalValue {
    let mut text = Some(text);
    rebuilt(
        map.entries()
            .iter()
            .map(|(name, value)| match text.take_if(|_| name == key) {
                Some(text) => (name.clone(), CanonicalValue::Text(text)),
                None => (name.clone(), value.clone()),
            })
            .collect(),
    )
}

/// A map of `entries`. Entries taken from a map and changed in place cannot repeat a key, so
/// failing to build one is not reached; it is answered with a null rather than with what was to
/// be replaced.
fn rebuilt(entries: Vec<(String, CanonicalValue)>) -> CanonicalValue {
    CanonicalMap::from_entries(entries).map_or(CanonicalValue::Null, CanonicalValue::Map)
}

/// A closure's list of what it left behind, with every detail that names the host replaced by what
/// kind of thing it was, or `None` when nothing in it changes or it is not such a list.
fn shown_survivors(value: &CanonicalValue) -> Option<CanonicalValue> {
    let CanonicalValue::Array(items) = value else {
        return shown_value(value);
    };
    let mut changed = false;
    let mut shown = Vec::with_capacity(items.len());
    for item in items {
        let replaced = match item {
            CanonicalValue::Map(map) => survivor(map),
            _ => None,
        };
        changed |= replaced.is_some();
        shown.push(replaced.unwrap_or_else(|| item.clone()));
    }
    changed.then_some(CanonicalValue::Array(shown))
}

/// One resource a closure left, as a device is given it, when its detail names the host.
fn survivor(map: &CanonicalMap) -> Option<CanonicalValue> {
    let (Some(CanonicalValue::Text(kind)), Some(CanonicalValue::Text(detail))) =
        (map.get("kind"), map.get("detail"))
    else {
        return None;
    };
    if map.entries().len() != 2 {
        return None;
    }
    first_naming(detail)?;
    Some(rebuilt(vec![
        ("kind".to_owned(), CanonicalValue::Text(kind.clone())),
        (
            "detail".to_owned(),
            CanonicalValue::Text(format!("{kind}: {WHY_NOT_SHOWN}")),
        ),
    ]))
}

/// Where in `text` the first thing that names this host begins, as a byte offset, when anything
/// does.
fn first_naming(text: &str) -> Option<usize> {
    let place = pointer_place(text);
    let outside = |at: usize| place.as_ref().is_none_or(|place| !place.contains(&at));
    let mut found: Option<usize> = None;
    let mut note = |at: usize| {
        if outside(at) {
            found = Some(found.map_or(at, |earlier| earlier.min(at)));
        }
    };
    let all = words(text);
    for (index, (at, word)) in all.iter().enumerate() {
        let program_run = *word == "kr" && index + 1 < all.len();
        if names_a_place(word) || is_command_word(word) || program_run {
            note(*at);
        }
    }
    if let Some(at) = account_number(text) {
        note(at);
    }
    found
}

/// Whether a device is told something other than `text`.
#[cfg(test)]
pub(crate) fn names_the_host(text: &str) -> bool {
    message_for_a_device(ErrorCode::InvalidArgument, text).is_some()
}

/// The words of `text`, each with the byte offset it begins at.
fn words(text: &str) -> Vec<(usize, &str)> {
    let mut found = Vec::new();
    let mut start = None;
    for (at, character) in text.char_indices() {
        if character.is_whitespace() {
            if let Some(begun) = start.take() {
                found.push((begun, &text[begun..at]));
            }
        } else if start.is_none() {
            start = Some(at);
        }
    }
    if let Some(begun) = start {
        found.push((begun, &text[begun..]));
    }
    found
}

/// The bytes of a message that are a field's place in another message, when it is one of the
/// three refusals that name one: `Terminal at /terminal carries a field it does not declare`.
fn pointer_place(text: &str) -> Option<std::ops::Range<usize>> {
    POINTER_ENDS.iter().find_map(|end| {
        let ends = text.find(end)?;
        let begins = text[..ends].rfind(" at ")? + " at ".len();
        let place = &text[begins..ends];
        (place.starts_with('/') && !place.contains("//")).then_some(begins..ends)
    })
}

/// Whether `word` is a path, as one is written on a platform this host runs on.
///
/// A backslash, or a slash that does not sit between two letters, digits or hyphens, which is what
/// `src/main.rs` and `and/or` are and a path from a root, a drive, a home or the current directory
/// is not. A web address is set aside unless it carries an account or a query; an address of any
/// other scheme (`file`, `unix`) is read as a path.
fn names_a_place(word: &str) -> bool {
    if let Some(scheme_end) = word.find("://") {
        let scheme_start = word[..scheme_end]
            .char_indices()
            .rev()
            .find(|(_, character)| {
                !(character.is_ascii_alphanumeric() || "+.-".contains(*character))
            })
            .map_or(0, |(at, character)| at + character.len_utf8());
        let scheme = &word[scheme_start..scheme_end];
        if WEB_SCHEMES
            .iter()
            .any(|web| scheme.eq_ignore_ascii_case(web))
        {
            let rest = &word[scheme_end + 3..];
            let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
            return rest[..authority_end].contains('@') || rest[authority_end..].contains('?');
        }
        // A scheme that is not the web's names a file, a socket or an account, and is read as a
        // path below.
    }
    if word.contains('\\') {
        return true;
    }
    word.char_indices().any(|(at, character)| {
        character == '/'
            && word[..at]
                .chars()
                .next_back()
                .is_none_or(|before| !(before.is_alphanumeric() || before == '_' || before == '-'))
    })
}

/// Whether `word` is the name of a program that changes who owns or may use a file.
fn is_command_word(word: &str) -> bool {
    let word = word.trim_matches(|character: char| !character.is_alphanumeric());
    COMMAND_WORDS
        .iter()
        .any(|command| word.eq_ignore_ascii_case(command))
}

/// Where in `text` an account's number begins to be named: a word for an account (or a service
/// manager's domain for one) and then digits, with at most one of a space, `=`, `:`, `@`, `/` or
/// `-` between, or a Windows security identifier.
///
/// The digits are a number when no letter or hyphen follows them: `user 501` and `user-1000.slice`
/// are, and `group 0193abcd-...`, the start of an identifier, is not.
fn account_number(text: &str) -> Option<usize> {
    let lower = text.to_ascii_lowercase();
    let boundary = |at: usize| {
        text[..at]
            .chars()
            .next_back()
            .is_none_or(|before| !before.is_alphanumeric())
    };
    // The text after `from` begins with digits that end at a place no identifier continues.
    let ends_as_a_number = |from: usize| {
        let digits = lower[from..]
            .find(|character: char| !character.is_ascii_digit())
            .unwrap_or(lower.len() - from);
        digits > 0
            && lower[from + digits..]
                .chars()
                .next()
                .is_none_or(|after| !(after.is_alphanumeric() || after == '-'))
    };
    let digits_after = |from: usize, separated: bool| {
        let mut rest = lower[from..].chars();
        match rest.next() {
            Some(digit) if digit.is_ascii_digit() => ends_as_a_number(from),
            Some(separator) if separated && " =:@/-".contains(separator) => {
                lower[from + separator.len_utf8()..]
                    .starts_with(|digit: char| digit.is_ascii_digit())
                    && ends_as_a_number(from + separator.len_utf8())
            }
            _ => false,
        }
    };
    ACCOUNT_WORDS
        .iter()
        .flat_map(|word| {
            lower
                .match_indices(word)
                .filter(|(at, _)| boundary(*at) && digits_after(at + word.len(), true))
                .map(|(at, _)| at)
                .collect::<Vec<_>>()
        })
        .chain(
            lower
                .match_indices("s-1-")
                .filter(|(at, _)| {
                    boundary(*at)
                        && lower[at + "s-1-".len()..]
                            .starts_with(|digit: char| digit.is_ascii_digit())
                })
                .map(|(at, _)| at),
        )
        .min()
}

/// `text` with every command quoted in backticks (more than one word between a pair of them)
/// replaced by `a command`, or `None` when it quotes none.
fn without_quoted_commands(text: &str) -> Option<String> {
    let mut shown = String::new();
    let mut rest = text;
    let mut replaced = false;
    while let Some(opening) = rest.find('`') {
        let Some(length) = rest[opening + 1..].find('`') else {
            break;
        };
        let closing = opening + 1 + length;
        let quoted = &rest[opening + 1..closing];
        shown.push_str(&rest[..opening]);
        if quoted.chars().any(char::is_whitespace) {
            shown.push_str("a command");
            replaced = true;
        } else {
            shown.push_str(&rest[opening..=closing]);
        }
        rest = &rest[closing + 1..];
    }
    shown.push_str(rest);
    replaced.then_some(shown)
}

#[cfg(test)]
mod tests {
    use super::*;

    use kr_protocol::envelope::Notification;
    use kr_protocol::ids::{DiagnosticId, EventType, RequestId, SessionId, StreamId};
    use kr_protocol::scalars::U64;
    use kr_protocol::session::{
        ClosureReason, ClosureRecord, Durability, OwnershipCoverage, SurvivingResource,
    };

    /// Everything a path, an account or a command can look like in the text of a failure.
    const NAMES_THE_HOST: [&str; 27] = [
        "create /Users/marguerite/Library/Application Support/KalaReach/workers/1: denied",
        "create '/home/marguerite/.local/state/kr': denied",
        "could not read (/var/lib/kr/registry) at all",
        "C:\\Users\\marguerite\\AppData\\Local\\KalaReach is not private",
        "C:/Users/marguerite/KalaReach is not private",
        "\\\\?\\C:\\Users\\marguerite\\x could not be opened",
        "\\\\.\\pipe\\kr-1 is taken",
        "the store is at ~/kr",
        "the store is at ./kr",
        "the store is at ../kr",
        "found file:///Users/marguerite/x",
        "/x must be owned by user 501 with mode 0700, found owner 502 and mode 0755",
        "peer user 501 may not use an endpoint owned by user 502",
        "the unit user-1000.slice could not be inspected",
        "the unit user@1000.service could not be inspected",
        "uid=501 may not do this",
        "launchctl bootout gui/501/label answered 5",
        "the account S-1-5-21-1-2-3-1001 owns it",
        "make it yours alone with: chmod 700 'x'",
        "run sudo kr for this",
        "run `kr host clock --establish` at the host",
        "a `chmod 700 /x` was run",
        "see https://marguerite:secret@example.com/x",
        "connect unix:///Users/marguerite/socket: refused",
        "ssh://marguerite@example.com/x was refused",
        "the environment has no task to start workers: run kr host startup --set standalone",
        "the unit group 20 is not private",
    ];

    /// Text that is the host's own sentence, or the device's own words back, and names nothing.
    const NAMES_NOTHING: [&str; 19] = [
        "the invitation expired",
        "session 0193 has closed",
        "src/main.rs is not tracked",
        "read and/or write",
        "the input lease has moved on",
        "the page read 3 of 5 users",
        "the username was refused",
        "the group was refused",
        "this host cannot start another session, short of storage: 2 of 3 GiB",
        "see https://example.com/docs/x for the limits",
        "see https://example.com:8443/docs/x#part for the limits",
        "Terminal at /terminal carries a field it does not declare",
        "Params at /terminal/[entry 0]/x names a variant in \"kind\" that its schema does not have",
        "the `session.open` method is not served",
        "a window of 10/30 seconds",
        "the relay at https://relay.example.com answered 503",
        "this environment is already in machine group 0193abcd-1111-4222-8333-444455556666",
        "this environment is already in machine group 01234567-89ab-4cde-8f01-234567890abc",
        "the page read 42 users and 7 groups",
    ];

    fn error(code: ErrorCode, message: &str) -> ProtocolError {
        ProtocolError::new(code, message)
    }

    #[test]
    fn what_names_the_host_is_found_in_any_form() {
        for text in NAMES_THE_HOST {
            assert!(names_the_host(text), "not found: {text}");
        }
    }

    #[test]
    fn a_command_quoted_in_backticks_is_replaced_and_the_sentence_around_it_is_kept() {
        let said = "this host found the policy it holds restored from an earlier state, so it \
                    refuses remote access until the person at this machine has confirmed it with \
                    `kr host policy --confirm`, which removes the record";
        let shown = error_for_a_device(&error(ErrorCode::PermissionDenied, said)).into_owned();
        assert!(
            shown
                .message
                .contains("confirmed it with a command, which removes the record")
                && !shown.message.contains("kr host"),
            "{shown:?}"
        );
        // One word between backticks is a name and not a command, and stays.
        assert!(!names_the_host("the `session.open` method is not served"));
    }

    #[test]
    fn a_refusal_of_the_project_service_gives_its_reason_without_its_place() {
        let mount = error(
            ErrorCode::UpstreamUnavailable,
            "a filesystem is mounted at /srv/marguerite/repos/src/mounted, beneath \
             /srv/marguerite/repos/src, which this invocation would be granted; an invocation for \
             a caller bounded by a grant is not run over a directory with another filesystem \
             inside it",
        );
        let alternates = error(
            ErrorCode::PermissionDenied,
            "the repository at /srv/marguerite/repos/borrowing is not reached through a location: \
             its objects/info/alternates names /srv/marguerite/other/.git/objects, which is not \
             beneath the directory it is relative to (outside)",
        );
        assert_eq!(
            error_for_a_device(&mount).message,
            "a filesystem is mounted inside the location the grant names"
        );
        assert_eq!(
            error_for_a_device(&alternates).message,
            "the repository names objects outside the location the grant names"
        );
        assert_eq!(
            error_for_a_device(&mount).code,
            ErrorCode::UpstreamUnavailable
        );
    }

    #[test]
    fn a_message_a_device_is_given_is_never_longer_than_an_error_may_be() {
        // Short enough to be an error, with a clause that cannot take the reason after it.
        let long = format!(
            "{}: create /x",
            "the host could not make something ".repeat(29)
        );
        let told = error(ErrorCode::ResourceUnavailable, &long);
        assert!(told.is_consistent(), "{}", long.len());
        let shown = error_for_a_device(&told).into_owned();
        assert!(shown.is_consistent(), "{}", shown.message.len());
        assert!(
            !shown
                .message
                .starts_with("the host could not make something"),
            "the clause gave way to the sentence of the code"
        );
    }

    #[test]
    fn what_names_nothing_is_left_alone() {
        for text in NAMES_NOTHING {
            assert!(!names_the_host(text), "found in: {text}");
        }
    }

    #[test]
    fn a_device_keeps_the_clause_that_comes_before_what_names_the_host() {
        let told = error(
            ErrorCode::ResourceUnavailable,
            "the host could not make the session's directory: create /Users/marguerite/x: \
             exists and is not a directory",
        );
        let shown = error_for_a_device(&told).into_owned();
        assert_eq!(
            shown.message,
            "the host could not make the session's directory; the detail names the host and is \
             not sent to a paired device"
        );
        assert_eq!((shown.code, shown.retry), (told.code, told.retry));
    }

    #[test]
    fn a_device_is_given_the_sentence_for_the_code_when_no_clause_comes_before() {
        for (code, message, said) in [
            (
                ErrorCode::ResourceUnavailable,
                "create /Users/marguerite/x: denied",
                "a file, directory, socket or program it needs was unavailable",
            ),
            (
                ErrorCode::PermissionDenied,
                "/x must be owned by user 501 with mode 0700; make it yours alone with: chmod 700 '/x'",
                "one of its own files or accounts refused this",
            ),
            (
                ErrorCode::StorageUnavailable,
                "/var/kr/registry.sqlite3 is locked",
                "its own storage was unavailable",
            ),
        ] {
            let shown = error_for_a_device(&error(code, message)).into_owned();
            assert!(
                shown.message.contains(said) && shown.message.ends_with(WHY_NOT_SHOWN),
                "{shown:?}"
            );
            assert_eq!(shown.code, code);
        }
    }

    #[test]
    fn an_error_keeps_everything_but_its_message() {
        let diagnostic = DiagnosticId::new("d-1").expect("an identifier");
        let told = error(ErrorCode::HostNotConfigured, "/etc/kr is missing")
            .with_diagnostic_id(diagnostic)
            .for_a_fenced_link();
        let shown = error_for_a_device(&told).into_owned();
        assert_eq!(
            ProtocolError {
                message: told.message.clone(),
                ..shown
            },
            told
        );
    }

    #[test]
    fn an_error_that_names_nothing_is_passed_as_it_is() {
        let told = error(ErrorCode::SessionClosed, "session 0193 has closed");
        assert!(matches!(error_for_a_device(&told), Cow::Borrowed(_)));
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    struct Answer {
        session: u8,
        presentation_error: Nullable<ProtocolError>,
    }

    #[test]
    fn an_error_inside_a_result_is_shown_as_an_error_is() {
        let answer = Answer {
            session: 1,
            presentation_error: Nullable::some(error(
                ErrorCode::TerminalUnavailable,
                "Terminal is installed and did not open a window: /usr/local/bin/kr attach 0193 \
                 --environment e",
            )),
        };
        let frame = ControlFrame::Response(Response {
            request_id: RequestId::new(3),
            outcome: Outcome::Ok(ParamsValue::from_typed(&answer).expect("encodes")),
        });
        let Cow::Owned(ControlFrame::Response(Response {
            outcome: Outcome::Ok(value),
            ..
        })) = frame_for_a_device(&frame)
        else {
            panic!("an error in a result was passed as it was");
        };
        let shown: Answer = kr_cbor::from_canonical_value(value.as_value()).expect("decodes");
        let told = shown.presentation_error.0.expect("the error is kept");
        assert_eq!(told.code, ErrorCode::TerminalUnavailable);
        assert!(!told.message.contains("/usr/local"), "{told:?}");
        assert!(
            told.message
                .starts_with("Terminal is installed and did not open a window"),
            "{told:?}"
        );
        assert_eq!(shown.session, 1);
    }

    #[test]
    fn a_result_with_no_error_in_it_is_passed_as_it_is() {
        let frame = ControlFrame::Response(Response {
            request_id: RequestId::new(3),
            outcome: Outcome::Ok(
                ParamsValue::from_typed(&Answer {
                    session: 1,
                    presentation_error: Nullable::null(),
                })
                .expect("encodes"),
            ),
        });
        assert!(matches!(frame_for_a_device(&frame), Cow::Borrowed(_)));
    }

    fn receipt_with(error: ProtocolError) -> kr_protocol::receipt::Receipt {
        use kr_protocol::ids::{ActionId, ActorId};
        use kr_protocol::receipt::{Receipt, ReceiptState};
        use kr_protocol::scalars::{Digest256, TimestampMs};

        Receipt {
            action_id: ActionId::new(kr_ipc::new_uuid()),
            actor_id: ActorId::new("device:test").expect("a principal"),
            method: Method::PluginInstall.into(),
            method_version: kr_protocol::method::MethodVersion::V1,
            revision: U64::new(2),
            state: ReceiptState::Rejected,
            reason: Nullable::null(),
            payload_digest: Digest256::from_bytes([7; 32]),
            accepted_deadline_ms: Nullable::null(),
            error: Nullable::some(error),
            error_withheld: false,
            updated_at_ms: TimestampMs::new(1),
        }
    }

    #[test]
    fn a_receipt_whose_message_was_replaced_says_so() {
        let receipt = receipt_with(error(
            ErrorCode::StorageUnavailable,
            "/Users/marguerite/catalogue.sqlite3 is locked",
        ));
        let frame = ControlFrame::Receipt(Box::new(kr_protocol::receipt::ReceiptResponse {
            request_id: RequestId::new(4),
            receipt: receipt.clone(),
        }));
        let Cow::Owned(ControlFrame::Receipt(shown)) = frame_for_a_device(&frame) else {
            panic!("a receipt that names the host was passed as it was");
        };
        assert!(shown.receipt.error_withheld);
        let shown_error = shown.receipt.error.0.expect("the error is kept");
        assert_eq!(shown_error.code, ErrorCode::StorageUnavailable);
        assert!(!shown_error.message.contains("marguerite"));

        // The same receipt inside the result of `action.read`.
        let read = kr_protocol::receipt::ActionReadResult {
            receipt,
            result: Nullable::null(),
        };
        let frame = ControlFrame::Response(Response {
            request_id: RequestId::new(5),
            outcome: Outcome::Ok(ParamsValue::from_typed(&read).expect("encodes")),
        });
        let Cow::Owned(ControlFrame::Response(Response {
            outcome: Outcome::Ok(value),
            ..
        })) = frame_for_a_device(&frame)
        else {
            panic!("a receipt in a result that names the host was passed as it was");
        };
        let shown: kr_protocol::receipt::ActionReadResult = value.to_typed().expect("decodes");
        assert!(shown.receipt.error_withheld);
        assert!(
            !shown
                .receipt
                .error
                .0
                .expect("kept")
                .message
                .contains("marguerite")
        );
    }

    fn closure_leaving(details: &[(&str, &str)]) -> ClosureRecord {
        ClosureRecord {
            session_id: SessionId::new(kr_ipc::new_uuid()),
            session_epoch: kr_protocol::ids::SessionEpoch::V1,
            reason: ClosureReason::RootExit,
            root_exit_code: Nullable::null(),
            root_signal: Nullable::null(),
            terminated: Vec::new(),
            surviving: details
                .iter()
                .map(|(kind, detail)| SurvivingResource {
                    kind: (*kind).to_owned(),
                    detail: (*detail).to_owned(),
                })
                .collect(),
            ownership_coverage: OwnershipCoverage::Incomplete,
            durability: Durability::Durable,
            closed_at_ms: kr_protocol::scalars::TimestampMs::new(1),
        }
    }

    fn closed(record: &ClosureRecord) -> ControlFrame {
        ControlFrame::Notification(Notification {
            stream_id: StreamId::new("s").expect("a stream"),
            sequence: kr_protocol::ids::EventSequence::new(1),
            event_type: EventType::new(kr_protocol::session::SESSION_CLOSED_EVENT)
                .expect("an event type"),
            payload: ParamsValue::from_typed(record).expect("encodes"),
        })
    }

    #[test]
    fn what_a_closure_left_behind_is_shown_by_its_kind_when_it_names_the_host() {
        let record = closure_leaving(&[
            (
                "unestablished",
                "the control group /sys/fs/cgroup/user.slice/user-1000.slice could not be read",
            ),
            ("process", "process 4521 is still running"),
        ]);
        let Cow::Owned(ControlFrame::Notification(shown)) = frame_for_a_device(&closed(&record))
        else {
            panic!("a closure that names the host was passed as it was");
        };
        let shown: ClosureRecord = shown.payload.to_typed().expect("decodes");
        assert!(
            shown.surviving[0].detail.starts_with("unestablished")
                && !shown.surviving[0].detail.contains("/sys"),
            "{:?}",
            shown.surviving
        );
        assert_eq!(shown.surviving[0].kind, "unestablished");
        assert_eq!(shown.surviving[1], record.surviving[1]);
        assert_eq!(shown.session_id, record.session_id);
    }

    #[test]
    fn a_closure_in_a_result_is_held_to_the_same_rule() {
        let record = closure_leaving(&[("unestablished", "cannot read /proc/1/cgroup")]);
        let frame = ControlFrame::Response(Response {
            request_id: RequestId::new(6),
            outcome: Outcome::Ok(ParamsValue::from_typed(&record).expect("encodes")),
        });
        assert!(matches!(frame_for_a_device(&frame), Cow::Owned(_)));
    }

    #[test]
    fn an_event_other_than_a_closure_is_passed_as_it_is() {
        let record = closure_leaving(&[("unestablished", "cannot read /proc/1/cgroup")]);
        let ControlFrame::Notification(closed) = closed(&record) else {
            unreachable!("a notification");
        };
        let output = ControlFrame::Notification(Notification {
            event_type: EventType::new("session.output").expect("an event type"),
            ..closed
        });
        assert!(matches!(frame_for_a_device(&output), Cow::Borrowed(_)));
    }

    #[test]
    fn only_what_puts_words_to_the_agent_has_its_refusal_replaced() {
        let refused = |code, message: &str| {
            ControlFrame::Response(Response {
                request_id: RequestId::new(8),
                outcome: Outcome::Error(error(code, message)),
            })
        };
        let said = "account marguerite cannot run git status";
        let ControlFrame::Response(Response {
            outcome: Outcome::Error(shown),
            ..
        }) = upstream_words(
            Some(Method::AgentPromptSubmit),
            refused(ErrorCode::InvalidArgument, said),
        )
        else {
            panic!("an error");
        };
        assert!(!shown.message.contains("marguerite"), "{shown:?}");
        assert_eq!(shown.code, ErrorCode::InvalidArgument);

        for (method, code) in [
            (Some(Method::PluginActionInvoke), ErrorCode::InvalidArgument),
            (Some(Method::AgentTurnSteer), ErrorCode::OutcomeUnknown),
        ] {
            let ControlFrame::Response(Response {
                outcome: Outcome::Error(shown),
                ..
            }) = upstream_words(method, refused(code, said))
            else {
                panic!("an error");
            };
            assert!(
                !shown.message.contains("marguerite"),
                "{method:?} {shown:?}"
            );
            assert_eq!(shown.code, code);
            assert_eq!(shown.retry, code.retry_category());
            if code == ErrorCode::OutcomeUnknown {
                assert!(
                    !shown.message.contains("could not complete"),
                    "an unknown outcome is not told as a failure: {shown:?}"
                );
            }
        }

        for (method, code) in [
            (Some(Method::AgentPromptSubmit), ErrorCode::DraftConflict),
            (Some(Method::AgentSnapshot), ErrorCode::InvalidArgument),
            (Some(Method::SessionCreate), ErrorCode::InvalidArgument),
            (None, ErrorCode::InvalidArgument),
        ] {
            let frame = refused(code, said);
            assert_eq!(upstream_words(method, frame.clone()), frame, "{method:?}");
        }
    }

    /// A surface that answers every call with one failure.
    #[derive(Debug)]
    struct Failing(ProtocolError);

    impl PairingSurface for Failing {
        fn call(
            &self,
            _: PairingMethod,
            _: &ConnectionPeer,
            _: &ParamsValue,
        ) -> Result<ParamsValue, ProtocolError> {
            Err(self.0.clone())
        }
    }

    #[test]
    fn a_candidate_is_not_shown_what_the_store_or_the_rendezvous_service_reported() {
        let peer = ConnectionPeer::new(
            kr_protocol::scalars::EndpointKey::from_bytes([1; 32]),
            false,
            kr_protocol::ids::ConnectionId::new(kr_ipc::new_uuid()),
        );
        let shown = |error: ProtocolError| {
            ForACandidate(Arc::new(Failing(error)))
                .call(PairingMethod::Status, &peer, &ParamsValue::empty())
                .expect_err("the surface fails")
        };
        // Nothing in this text looks like the host, and the store's words are still not shown.
        let store = shown(error(
            ErrorCode::StorageUnavailable,
            "the pairing store failed: database disk image is malformed",
        ));
        assert!(!store.message.contains("malformed"), "{store:?}");
        let rendezvous = shown(error(
            ErrorCode::RendezvousUnavailable,
            "the rendezvous service is unavailable: connection refused",
        ));
        assert!(!rendezvous.message.contains("refused"), "{rendezvous:?}");
        // The rest is held to the rule as everything else is.
        let expired = error(ErrorCode::PairingExpired, "the invitation expired");
        assert_eq!(shown(expired.clone()), expired);
        let named = shown(error(ErrorCode::InvalidArgument, "bad /Users/marguerite/x"));
        assert!(!named.message.contains("marguerite"), "{named:?}");
    }
}

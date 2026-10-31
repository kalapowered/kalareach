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
//! identifier. Its message is kept when it names nothing of this host, unless the refusal is one
//! this module knows by its wording ([`KNOWN_REASONS`]), which is told by its reason. A command
//! quoted in backticks is a quotation with an end, so it is replaced by `a command` and the
//! sentence it was in is kept. Anything else that names the host (a path of any kind, the number
//! of an account, the name of a program that changes who may use a file) has no end this module
//! can find, so the device is given the part of the message that comes before the first such name,
//! if that is a clause of its own, and otherwise a sentence composed here from the code.
//!
//! The same rule reaches an error wherever it is, because the text of an error that has already
//! been made (a worker's, one a store kept, one a catalogue receipt holds) cannot be made again:
//! an error in a response, a receipt, or anywhere inside a result or an announcement. The places
//! where this host's failures are written as plain text and not as an error are held to the same
//! rule: a closure's list of what it left behind, and the members of the records in
//! [`FAILURE_TEXTS`]. The places that hold a place on this host and no failure ([`HOST_PATHS`])
//! are withheld as a path is, and the name of the desktop a session is bound to is told as the
//! capability answers tell it ([`withheld_desktop_name`]). The reason an agent instance's rich
//! mutations wait is told by what it says of the wait ([`suspension_for_a_device`]), in a result
//! and in the refusal of a rich mutation.

use std::borrow::Cow;
use std::sync::Arc;

use kr_cbor::{CanonicalMap, CanonicalValue};
use kr_protocol::envelope::{ControlFrame, Notification, Outcome, ParamsValue, Response};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::method::Method;
use kr_protocol::scalars::Nullable;
use kr_transport::preauth::{ConnectionPeer, PairingMethod, PairingSurface};

use crate::catalogue::admissions::UNRECORDABLE_CLAUSE;
use crate::supervision::windows::{
    A_TASK_NAMED, COULD_NOT_LIST, DID_NOT_REGISTER, DID_NOT_REMOVE, DID_NOT_RUN, IS_REGISTERED,
    NOT_THE_ONE_REGISTERED, READS_BACK_DIFFERENTLY,
};

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

/// Refusals whose reason a device is told without the place or the account: a text that holds every
/// one of the markers is told as the sentence beside them. The first two are refusals of the
/// project service, in terms of the location the device's grant names, which is all of the place
/// the device has. The third is the refusal to start a worker over a scheduled task under the
/// environment's name that is not this installation's own, whose text can name the account it is
/// registered for, or quote what the Task Scheduler said. The next four are the Task Scheduler's own
/// refusals of a command this host gave it, each of which carries what the scheduler printed after
/// it: that is a program's output, which can hold an account's name in a form the rule cannot find.
/// The last two quote what a task holds, which was written by whoever registered it, where it
/// differs from the one this installation registers.
///
/// The markers of the last seven are the wording the code that writes those refusals uses
/// ([`crate::supervision::windows`]), so a change to a refusal there is a change to its marker here,
/// and not a refusal the rule below would read as a message that names nothing.
const KNOWN_REASONS: [(&[&str], &str); 9] = [
    (
        &["a filesystem is mounted at "],
        "a filesystem is mounted inside the location the grant names",
    ),
    (
        &[" its objects/info/alternates names "],
        "the repository names objects outside the location the grant names",
    ),
    (
        &[A_TASK_NAMED, IS_REGISTERED],
        "a task under this environment's name is not this installation's own, so the host left it \
         as it is",
    ),
    (
        &[DID_NOT_REGISTER],
        "the Task Scheduler did not register the environment's task; what it reported is not sent \
         to a paired device",
    ),
    (
        &[DID_NOT_REMOVE],
        "the Task Scheduler did not remove the environment's task; what it reported is not sent \
         to a paired device",
    ),
    (
        &[COULD_NOT_LIST],
        "the Task Scheduler could not list the environment's task; what it reported is not sent \
         to a paired device",
    ),
    (
        &[DID_NOT_RUN],
        "the Task Scheduler did not run the environment's task; what it reported is not sent to a \
         paired device",
    ),
    (
        &[NOT_THE_ONE_REGISTERED],
        "the environment's task is not the one this installation registers; what it holds is not \
         sent to a paired device",
    ),
    (
        &[READS_BACK_DIFFERENTLY],
        "the environment's task was changed and reads back differently; what it holds is not sent \
         to a paired device",
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

/// Why rich mutations wait while a request of the terminal's that selects or leaves a conversation
/// has not been answered, as the worker writes it.
const SELECTION_IN_FLIGHT: &str = "the terminal has asked to change its conversation and the \
                                   server has not answered, so which conversation it is in is \
                                   unknown";

/// Why rich mutations wait after such a request ended in a way that does not say what became of it,
/// as the worker writes it.
const SELECTION_UNKNOWN: &str = "what became of the terminal's last request to change its \
                                 conversation is unknown, so which conversation it is in is \
                                 unknown";

/// What the worker says before why rich mutations wait, in the refusal of one: the wording the
/// worker writes it with, so a change there is a change here.
const RICH_MUTATIONS_SUSPENDED: &str = kr_worker::broker::error::MUTATIONS_SUSPENDED_REFUSAL;

/// What a device is told of a reason for the wait that the host does not know, before why it is not
/// sent.
const SUSPENDED_BY: &str = "rich mutations are suspended";

/// What the worker says before why it could not take the conversation the terminal selected.
const CONVERSATION_NOT_BOUND: &str = "the conversation the terminal selected cannot be bound here";

/// What the worker says after the method of a request that its connector's table does not
/// classify, and what a device is told in place of the method and those words.
const UNCLASSIFIED_METHODS: [(&str, &str); 2] = [
    (
        " is not classified by this connector's table, so what the terminal asked for is unknown",
        "a request of a method this connector's table does not classify was made, so what the \
         terminal asked for is unknown",
    ),
    (
        " is not classified by this connector's table, so what it changed is unknown",
        "a request of a method this connector's table does not classify was made, so what it \
         changed is unknown",
    ),
];

/// A member of a protocol record that holds a failure as plain text, found by its key.
struct FailureText {
    /// The member's key.
    key: &'static str,
    /// The members beside it that say which record it belongs to: each key, and the text it must
    /// hold when the record is one of several under a tag.
    beside: &'static [(&'static str, Option<&'static str>)],
    /// What the text says, for the sentence a device is given when none of it can be kept.
    of: &'static str,
    /// What is done with the text.
    how: How,
}

/// What is done with the text of a member of [`FAILURE_TEXTS`].
enum How {
    /// The text is held to the rule an error's message is.
    Rule,
    /// The host's own clauses end where words that are not the host's begin, and the text is cut
    /// at the end of the one of these that begins first in it: the host's clause comes before any
    /// words of another's, which can quote a clause of the host's own. A text that holds none is
    /// held to the rule.
    CutAfter(&'static [&'static str]),
    /// The text can be an upstream's own words or a quotation of them, whose names the rule cannot
    /// find, so none of it is sent.
    Whole,
}

/// The records whose members hold a failure as plain text, which no error carries: the reason a
/// privacy step could not answer, what a workspace or a repository operation records of its own
/// state, and why an agent instance's bridges are refused. A device reads them in results and in
/// announcements, so they are held to the rule as an error's message is.
const FAILURE_TEXTS: [FailureText; 9] = [
    FailureText {
        key: "reason",
        beside: &[("subsystem", None)],
        of: "what the subsystem's store reported",
        how: How::Rule,
    },
    FailureText {
        key: "reason",
        beside: &[("state", Some("unavailable"))],
        of: "why the session's cleanup is unavailable",
        how: How::Rule,
    },
    FailureText {
        key: "detail",
        beside: &[("kind", None), ("change_set_id", None)],
        of: "what the workspace holds",
        how: How::Rule,
    },
    FailureText {
        key: "detail",
        beside: &[("display_path", None)],
        of: "why the workspace is in this state",
        how: How::Rule,
    },
    FailureText {
        key: "detail",
        beside: &[("retained_staging_paths", None)],
        of: "why the operation ended",
        how: How::Rule,
    },
    FailureText {
        key: "refusal",
        beside: &[("application_instance_id", None)],
        of: "why the instance's bridges are refused",
        how: How::Rule,
    },
    FailureText {
        key: "failure",
        beside: &[("download", Some("failed"))],
        of: "why the fetch of the description model failed",
        how: How::Rule,
    },
    FailureText {
        key: "detail",
        beside: &[("state", Some("left_out")), ("reason", None)],
        of: "why the admissions leave the installation out",
        how: How::CutAfter(&LEFT_OUT_CLAUSES),
    },
    FailureText {
        key: "failure_detail",
        beside: &[("handle", None), ("insertion_method", None)],
        of: "why the attachment was not offered",
        how: How::Whole,
    },
];

/// The clauses of the host's own wording for an installation the admissions leave out that are
/// followed, after a colon, by words that are not the host's: a repository's statement of why it
/// revoked a package, what was wrong with a package in the store, which limit it is past, and why
/// it cannot be handed to a worker. The subject of each is the package and its hash.
///
/// Each is the wording of the code that writes the detail, so a change to a clause there is a
/// change to the clause here.
const LEFT_OUT_CLAUSES: [&str; 4] = [
    kr_plugin_catalogue::admission::REVOKED_CLAUSE,
    kr_plugin_catalogue::admission::INCOMPLETE_CLAUSE,
    kr_plugin_catalogue::admission::PAST_A_LIMIT_CLAUSE,
    UNRECORDABLE_CLAUSE,
];

/// A member of a protocol record that holds a place on this host as plain text, found by its key.
struct HostPath {
    /// The member's key. Its value is a text, or a list of texts.
    key: &'static str,
    /// The members beside it that say which record it belongs to: each key, and the text it must
    /// hold when the record is one of several under a tag.
    beside: &'static [(&'static str, Option<&'static str>)],
}

/// The members that hold a place on this host and no failure: where a repository or a working copy
/// is, the staging paths an operation kept or removed, the repository a clone was made from, the
/// socket of a session's worker. A session's own working directory and shell, and the executable a
/// question's source runs, are not among them: the specification shows them to the person on
/// purpose, as part of how a session or a question is described, and a device that may see the
/// session sees its terminal. A path under a home directory names the account, and a device cannot
/// use one, so a device is given each as the withheld record of a path (the form the directory of a
/// materialisation has), with the list of paths as long as it was.
const HOST_PATHS: [HostPath; 5] = [
    HostPath {
        key: "display_path",
        beside: &[("project_repository_id", None), ("environment_id", None)],
    },
    HostPath {
        key: "retained_staging_paths",
        beside: &[("action_id", None), ("destination_state", None)],
    },
    HostPath {
        key: "removed_staging_paths",
        beside: &[("action_id", None), ("destination_state", None)],
    },
    // A clone from a location names the repository it was made from by its place on this host. The
    // address of a remote on the web is the owner's, and is not held.
    HostPath {
        key: "url",
        beside: &[("remote_name", None), ("transport", Some("local_path"))],
    },
    // The path of the socket a session's worker listens on, which a device cannot use and which
    // names the account on a platform that puts it under the account's runtime directory.
    HostPath {
        key: "endpoint",
        beside: &[("session", None)],
    },
];

/// The host's own reasons for refusing the argument of a call that reaches the agent of a session,
/// by the shape of their wording, and the sentence a device is told of each.
///
/// The worker puts the upstream's words under the same code with nothing before them, so the
/// host's own reasons are told apart from them by their wording, and a message that is not one of
/// these is the upstream's. A shape does not show where its words came from: a `{}` stands for any
/// one word, which the upstream could have written, and so could the digits of a size. So no word
/// or number of a message reaches a device. The device is given the sentence beside the shape, a
/// closed set of this host's own text, or the shape itself where it has no slot and so is one
/// fixed sentence already.
const OWN_ARGUMENT_REASONS: [(&str, Option<&str>); 13] = [
    ("a prompt names either a draft or inline text", None),
    ("a prompt names a draft or inline text, not both", None),
    (
        "the package accepts {} bytes of an attachment and this one is {}",
        Some("the attachment is larger than the package accepts"),
    ),
    (
        "{} does not declare a parameter named {}",
        Some("the action does not declare a parameter that was sent"),
    ),
    (
        "the parameter {} of {} does not accept this value",
        Some("the action does not accept the value given for a parameter"),
    ),
    // A media type carries parameters, which hold spaces (`text/plain; charset=utf-8`), so the
    // type is the rest of the message up to the end of the sentence.
    (
        "the package does not accept {..} as an attachment",
        Some("the package does not accept this kind of attachment"),
    ),
    (
        "{}'s parameters: the required parameter {} is absent",
        Some("a parameter the action requires is absent"),
    ),
    (
        "{}'s parameters: the value of {} is outside its declared bound",
        Some("the value given for a parameter is outside the bound the action declares"),
    ),
    (
        "{}'s parameters: the parameter {} is supplied more than once",
        Some("a parameter is supplied more than once"),
    ),
    (
        "{}'s parameters: the parameter {} does not accept this value",
        Some("the action does not accept the value given for a parameter"),
    ),
    (
        "{}'s parameters name a member more than once, and two readers of them could disagree",
        Some("the parameters of the action name a member more than once"),
    ),
    (
        "{} names no attachment to offer",
        Some("the action names no attachment to offer"),
    ),
    (
        "{} is not prepared by a component",
        Some("the action is not prepared by a component"),
    ),
];

/// The refusal of a call that a component answers for when the component has had its rich
/// capabilities disabled, by its beginning, and the sentence a device is told of each. The worker
/// adds why after it, and that is a fault or a revocation in the component's or the runtime's
/// words. The beginnings are the wording the worker writes the refusals with, so a change there is
/// a change here.
const DISABLED_COMPONENT_REASONS: [(&str, &str); 2] = [
    (
        kr_worker::broker::error::BINDING_DISABLED_REFUSAL,
        "this binding's rich capabilities are disabled",
    ),
    (
        kr_worker::broker::error::COMPONENT_DISABLED_REFUSAL,
        "the component answerable for this operation has had its rich capabilities disabled",
    ),
];

/// The refusals of a plugin's action under the codes the plugin runtime's words come under, by
/// their wording, and the sentence a device is told of each. Most are the host's own and say what
/// kind of thing stopped the action; the worker writes the runtime's own words, or the component's,
/// after the colon of several of them, and those are another program's. A `{..}` stands for the
/// rest of the message, whatever it says, up to the end of the shape. A sentence with no slot at
/// all is the host's own text and is sent as it is. The refusals of a component with its rich
/// capabilities disabled are told too ([`DISABLED_COMPONENT_REASONS`]).
const PLUGIN_ACTION_REASONS: [(&str, Option<&str>); 16] = [
    ("the plugin runtime is not connected", None),
    (
        "the component is disabled; the runtime's words are withheld for privacy mode",
        None,
    ),
    (
        "the plugin runtime refused to ask the component to prepare the action; its words are \
         withheld for privacy mode",
        None,
    ),
    (
        "this worker has no control daemon to read a draft from",
        None,
    ),
    (
        "reports of earlier offers are still waiting for the control daemon",
        None,
    ),
    ("preparations are no longer accepted", None),
    (
        "the time to prepare this action ran out before the component was asked",
        None,
    ),
    (
        "{} declares no single parameter that names its attachment",
        Some("the action declares no single parameter that names its attachment"),
    ),
    (
        "{} offers an attachment and its package declares no attachments",
        Some("the action offers an attachment and its package declares no attachments"),
    ),
    (
        "{}'s package inserts an attachment by {}, and a worker offers one only by an upload to the \
         upstream",
        Some("the action's package inserts an attachment in a way a worker does not offer"),
    ),
    (
        "{} actions are being prepared already, and this one was not reached in time",
        Some("other actions are being prepared already, and this one was not reached in time"),
    ),
    (
        "{}'s component is not registered with the plugin runtime yet",
        Some("the action's component is not registered with the plugin runtime yet"),
    ),
    (
        "{}'s component is not registered with the plugin runtime yet: {..}",
        Some("the action's component is not registered with the plugin runtime yet"),
    ),
    (
        "{}'s component cannot be prepared: {..}",
        Some("the action's component cannot be prepared"),
    ),
    (
        "the component is disabled: {..}",
        Some("the component is disabled"),
    ),
    (
        "the component could not be asked to prepare the action: {..}",
        Some("the component could not be asked to prepare the action"),
    ),
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
    // The refusal of a rich mutation says why they wait in the words of that reason, which are
    // told as the reason is.
    if let Some(reason) = message.strip_prefix(RICH_MUTATIONS_SUSPENDED) {
        return refusal_while_mutations_wait(reason);
    }
    told_in_place(message, || sentence_for(code, WHY_NOT_SHOWN))
}

/// What a device is told in place of `text`, or `None` when it is told the text itself. `fixed` is
/// what stands where nothing of the text can be kept.
fn told_in_place(text: &str, fixed: impl Fn() -> String) -> Option<String> {
    let without_commands = without_quoted_commands(text);
    let text = without_commands.as_deref().unwrap_or(text);
    // A refusal that is known by its wording is told by its reason whether or not the rule finds a
    // name in it: it can name an account that has no form the rule can find.
    let told = match known_reason(text) {
        Some(reason) => reason.to_owned(),
        None => match first_naming(text) {
            None => without_commands?,
            Some(at) => match clause_before(text, at) {
                Some(clause) => format!("{clause}; {WHY_NOT_SHOWN}"),
                None => fixed(),
            },
        },
    };
    // A text never carries more than an error's limit, so a clause kept from a long one gives way
    // to what stands for it.
    Some(if told.len() > LONGEST_MESSAGE {
        fixed()
    } else {
        told
    })
}

/// The sentence a device is given for a refusal whose reason the host's text says beside its place.
fn known_reason(text: &str) -> Option<&'static str> {
    KNOWN_REASONS
        .iter()
        .find(|(markers, _)| markers.iter().all(|marker| text.contains(marker)))
        .map(|(_, reason)| *reason)
}

/// `frame` as a device is given it: every error in it as [`error_for_a_device`] gives it, and
/// every closure's account of what it left behind and every failure a record holds as plain text
/// ([`FAILURE_TEXTS`]) held to the same rule, in a result and in an announcement.
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
        ControlFrame::Notification(notification) => {
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

/// The worker's answer to `method` as a device is given it, when the method puts a prompt, a steer,
/// a cancellation, an approval or a plugin's action to the agent a session runs.
///
/// An agent's refusal is the agent's own words about what it was asked, and they quote what it
/// was working on. The worker gives them under the same code as its own refusals of the argument,
/// so a refusal of the argument is told as it is, or by its kind, when it is one of the host's own
/// reasons ([`OWN_ARGUMENT_REASONS`]), which a device needs to correct what it sent, and every
/// other refusal of the argument, of the agent itself, or an end that left the outcome unknown,
/// is replaced by a sentence composed from its code. A plugin's action also meets the plugin
/// runtime, whose words come under two more codes and are told the same way
/// ([`PLUGIN_ACTION_REASONS`]), and the answer to an approval meets a component that was disabled
/// for a fault ([`DISABLED_COMPONENT_REASONS`]). The code and the retry category stay.
///
/// This is for what a worker answered. The daemon's own refusals of the same call are its own
/// sentences, made before any worker is asked, and are not given to it.
#[must_use]
pub(crate) fn upstream_words(method: Method, frame: ControlFrame) -> ControlFrame {
    if !puts_to_the_agent(method) {
        return frame;
    }
    let ControlFrame::Response(Response {
        request_id,
        outcome: Outcome::Error(error),
    }) = frame
    else {
        return frame;
    };
    let error = match told_in_place_of_the_upstreams(method, &error) {
        Some(message) => with_message(&error, message),
        None => error,
    };
    ControlFrame::Response(Response {
        request_id,
        outcome: Outcome::Error(error),
    })
}

/// What a device is told in place of the message of `error`, the worker's refusal of a call of
/// `method` that reaches the agent of a session, or `None` when it is told the message itself.
fn told_in_place_of_the_upstreams(method: Method, error: &ProtocolError) -> Option<String> {
    let from_the_code = || sentence_for(error.code, WHY_WHATEVER_IT_SAYS);
    let of_the_hosts = |reasons: &[(&str, Option<&str>)]| {
        match reasons
            .iter()
            .find(|(shape, _)| fits_shape(shape, &error.message))
        {
            None => Some(from_the_code()),
            // A shape with no `{}` is its own sentence, and the message is that sentence.
            Some((_, Some(sentence))) => Some((*sentence).to_owned()),
            Some((_, None)) => None,
        }
    };
    match error.code {
        ErrorCode::UpstreamUnavailable | ErrorCode::OutcomeUnknown => Some(from_the_code()),
        ErrorCode::InvalidArgument => of_the_hosts(&OWN_ARGUMENT_REASONS),
        // The plugin runtime is another program, and what it says comes under these two codes.
        ErrorCode::ResourceUnavailable | ErrorCode::UnsupportedCapability
            if method == Method::PluginActionInvoke =>
        {
            match disabled_component(&error.message) {
                Some(kind) => Some(kind.to_owned()),
                None => of_the_hosts(&PLUGIN_ACTION_REASONS),
            }
        }
        // The component that read an approval can have been disabled for a fault it had, and the
        // worker says which after the colon.
        ErrorCode::UnsupportedCapability if method == Method::AgentApprovalRespond => {
            disabled_component(&error.message).map(str::to_owned)
        }
        _ => None,
    }
}

/// The sentence a device is told when `message` is the refusal of a component that has had its rich
/// capabilities disabled, which begins as [`DISABLED_COMPONENT_REASONS`] says and gives why after
/// it. A refusal that gives no why is the host's other sentence and is not this one.
fn disabled_component(message: &str) -> Option<&'static str> {
    DISABLED_COMPONENT_REASONS
        .iter()
        .find(|(beginning, _)| {
            message
                .strip_prefix(beginning)
                .is_some_and(|why| !why.is_empty())
        })
        .map(|(_, kind)| *kind)
}

/// Whether `message` is `shape` with one word of the argument, up to the next space, apostrophe or
/// comma, in place of each `{}`, and the rest of the message, if it is not empty, in place of a
/// closing `{..}`, which the end of the shape may follow (`accept {..} as an attachment`). An
/// apostrophe or a comma ends a word so that a shape can say `{}'s` or `{},`; no name of an action
/// or a parameter holds either.
fn fits_shape(shape: &str, message: &str) -> bool {
    let (mut shape, mut rest) = (shape, message);
    while let Some(open) = shape.find("{}") {
        let Some(after) = rest.strip_prefix(&shape[..open]) else {
            return false;
        };
        let word = after
            .find(|character: char| character.is_whitespace() || matches!(character, '\'' | ','))
            .unwrap_or(after.len());
        if word == 0 {
            return false;
        }
        rest = &after[word..];
        shape = &shape[open + "{}".len()..];
    }
    match shape.split_once("{..}") {
        Some((literal, end)) => rest
            .strip_prefix(literal)
            .and_then(|more| more.strip_suffix(end))
            .is_some_and(|more| !more.is_empty()),
        None => rest == shape,
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

/// `value` with every error in it, every closure's account of what it left and every failure a
/// record holds as plain text ([`FAILURE_TEXTS`]), as a device is given them, or `None` when
/// nothing in it changes.
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
                .map(|(key, child)| shown_member(map, key, child))
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

/// One member of `map` as a device is given it, or `None` when it is given as it is.
fn shown_member(map: &CanonicalMap, key: &str, child: &CanonicalValue) -> Option<CanonicalValue> {
    if key == "surviving" {
        return shown_survivors(child);
    }
    if let CanonicalValue::Text(text) = child
        && let Some(field) = failure_field(map, key)
    {
        let fixed = || format!("{}; {WHY_NOT_SHOWN}", field.of);
        let told = match field.how {
            How::Rule => told_in_place(text, fixed),
            How::CutAfter(clauses) => match clauses
                .iter()
                .filter_map(|clause| text.find(clause).map(|at| (at, at + clause.len())))
                .min()
            {
                Some((_, end)) => (end < text.len()).then(|| text[..end].to_owned()),
                None => told_in_place(text, fixed),
            },
            How::Whole => Some(format!("{}; {WHY_WHATEVER_IT_SAYS}", field.of)),
        };
        return told.map(CanonicalValue::Text);
    }
    if let CanonicalValue::Text(text) = child
        && is_why_mutations_wait(map, key)
    {
        return suspension_for_a_device(text).map(CanonicalValue::Text);
    }
    if let CanonicalValue::Text(name) = child
        && is_a_desktop_name(map, key)
    {
        return withheld_desktop_name(name).map(CanonicalValue::Text);
    }
    if is_a_host_path(map, key) {
        return withheld_paths(child);
    }
    shown_value(child)
}

/// Whether the text under `key` in `map` is the name of the desktop a session is bound to: the
/// `desktop_session_id` of a binding, which has the generation it was taken at beside it.
fn is_a_desktop_name(map: &CanonicalMap, key: &str) -> bool {
    key == "desktop_session_id" && map.get("login_generation").is_some()
}

/// What a device is told in place of the name of a desktop, or `None` when it is told it already.
///
/// The name spells out the kind of login, the account's name and number, the platform's session,
/// the generation and the boot. The device is told what the capability answers tell it, a marker
/// that says the session is bound to a desktop and not which one, so a session that is bound to
/// none is still told apart from one that is.
fn withheld_desktop_name(name: &str) -> Option<String> {
    let marker = kr_protocol::hostinfo::export::withheld_identity().to_string();
    (name != marker).then_some(marker)
}

/// Whether the text under `key` in `map` is why an agent instance's rich mutations wait: the
/// `suspension_reason` of a binding state, which also says whether they do.
fn is_why_mutations_wait(map: &CanonicalMap, key: &str) -> bool {
    key == "suspension_reason"
        && map.get("rich_mutations_suspended").is_some()
        && map.get("binding_revision").is_some()
}

/// Whether the member under `key` in `map` holds a place on this host ([`HOST_PATHS`]).
fn is_a_host_path(map: &CanonicalMap, key: &str) -> bool {
    HOST_PATHS
        .iter()
        .any(|path| path.key == key && beside_holds(map, path.beside))
}

/// Whether `map` holds every member of `beside`, with the text it must hold where one is given.
fn beside_holds(map: &CanonicalMap, beside: &[(&str, Option<&str>)]) -> bool {
    beside
        .iter()
        .all(|(name, value)| match (map.get(name), value) {
            (Some(CanonicalValue::Text(found)), Some(wanted)) => found == wanted,
            (Some(_), None) => true,
            _ => false,
        })
}

/// `value`, a text or a list of texts that are places on this host, with each of them withheld as
/// the directory of a materialisation is, or `None` when it holds none.
fn withheld_paths(value: &CanonicalValue) -> Option<CanonicalValue> {
    let withheld = |text: &str| {
        kr_protocol::hostinfo::export::withheld(
            kr_protocol::hostinfo::export::ContentClass::Path,
            text,
        )
    };
    match value {
        CanonicalValue::Text(text) => Some(CanonicalValue::Text(withheld(text))),
        CanonicalValue::Array(items) => {
            let mut changed = false;
            let shown = items
                .iter()
                .map(|item| match item {
                    CanonicalValue::Text(text) => {
                        changed = true;
                        CanonicalValue::Text(withheld(text))
                    }
                    other => other.clone(),
                })
                .collect();
            changed.then_some(CanonicalValue::Array(shown))
        }
        _ => None,
    }
}

/// How a device is told why an agent instance's rich mutations wait.
enum Wait {
    /// The host's own sentence says it and names nothing, so it is told as it is.
    AsWritten,
    /// A sentence for the kind of wait, with none of the words the reason held.
    Kind(String),
    /// A reason the host does not know, of which nothing is told.
    Unknown,
}

/// Why an agent instance's rich mutations wait, with nothing of this host or of the application's
/// upstream in it.
///
/// The worker writes the reason from the host's own sentences, and from two things it did not
/// make: the method of a request that its connector's table does not classify, which is the
/// upstream's, and what stopped it taking a conversation, which can quote a lock file under a home
/// directory. A device is told which of those it was and not the words. A reason the host does not
/// know is not sent.
fn why_mutations_wait(reason: &str) -> Wait {
    if [
        kr_worker::broker::THREAD_NOT_READ,
        kr_worker::broker::bridge::UNVERIFIED_THREAD,
        SELECTION_IN_FLIGHT,
        SELECTION_UNKNOWN,
    ]
    .contains(&reason)
    {
        return Wait::AsWritten;
    }
    if let Some(why) = reason
        .strip_prefix(CONVERSATION_NOT_BOUND)
        .and_then(|rest| rest.strip_prefix(": "))
    {
        // The one reason of those that names nothing is the conversation being held elsewhere.
        return if why == kr_worker::broker::BrokerError::ConversationHeldElsewhere.to_string() {
            Wait::AsWritten
        } else {
            Wait::Kind(format!("{CONVERSATION_NOT_BOUND}; {WHY_NOT_SHOWN}"))
        };
    }
    UNCLASSIFIED_METHODS
        .iter()
        .find(|(end, _)| reason.ends_with(end))
        .map_or(Wait::Unknown, |(_, told)| Wait::Kind((*told).to_owned()))
}

/// What a device is told in place of `reason`, the `suspension_reason` of a binding state, or
/// `None` when it is told the reason itself.
fn suspension_for_a_device(reason: &str) -> Option<String> {
    match why_mutations_wait(reason) {
        Wait::AsWritten => None,
        Wait::Kind(told) => Some(told),
        Wait::Unknown => Some(format!("{SUSPENDED_BY}; {WHY_WHATEVER_IT_SAYS}")),
    }
}

/// What a device is told in place of the message of a refusal of a rich mutation, where `reason`
/// is what follows [`RICH_MUTATIONS_SUSPENDED`], or `None` when it is told the message itself.
fn refusal_while_mutations_wait(reason: &str) -> Option<String> {
    match why_mutations_wait(reason) {
        Wait::AsWritten => None,
        Wait::Kind(told) => Some(format!("{RICH_MUTATIONS_SUSPENDED}{told}")),
        Wait::Unknown => Some(format!("{SUSPENDED_BY}; {WHY_WHATEVER_IT_SAYS}")),
    }
}

/// The row of [`FAILURE_TEXTS`] for the text under `key` in `map`, when it is a failure a record
/// holds as plain text.
fn failure_field(map: &CanonicalMap, key: &str) -> Option<&'static FailureText> {
    FAILURE_TEXTS
        .iter()
        .find(|field| field.key == key && beside_holds(map, field.beside))
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
    const NAMES_NOTHING: [&str; 21] = [
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
        // Holds one marker of a refusal this module knows by its wording, and not the others.
        "a task named backup was not run",
        "this device is registered with the relay",
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
    fn an_event_that_carries_no_failure_that_names_the_host_is_passed_as_it_is() {
        let record = closure_leaving(&[("process", "process 4521 is still running")]);
        let ControlFrame::Notification(closed) = closed(&record) else {
            unreachable!("a notification");
        };
        assert!(matches!(
            frame_for_a_device(&ControlFrame::Notification(closed)),
            Cow::Borrowed(_)
        ));
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
            Method::AgentPromptSubmit,
            refused(ErrorCode::InvalidArgument, said),
        )
        else {
            panic!("an error");
        };
        assert!(!shown.message.contains("marguerite"), "{shown:?}");
        assert_eq!(shown.code, ErrorCode::InvalidArgument);

        for (method, code) in [
            (Method::PluginActionInvoke, ErrorCode::InvalidArgument),
            (Method::AgentTurnSteer, ErrorCode::OutcomeUnknown),
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
            (Method::AgentPromptSubmit, ErrorCode::DraftConflict),
            (Method::AgentSnapshot, ErrorCode::InvalidArgument),
            (Method::SessionCreate, ErrorCode::InvalidArgument),
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

    /// What the privacy record writes of a step it could not take: a clause, the place and the
    /// accounts that own it, and the command that would mend it.
    const AN_OWNERSHIP_FAILURE: &str = "the recovery directory could not be used: \
         /Users/marguerite/.local/state/kr/recoveries must be owned by user 501 with mode 0700, \
         found owner 502; make it yours alone with: chmod 700 \
         '/Users/marguerite/.local/state/kr/recoveries'";

    /// A failure that begins with the place it is about.
    const A_FAILURE_AT_A_PATH: &str =
        "/Users/marguerite/.nvm/versions/node/v22/bin/codex cannot be read: permission denied";

    /// Whether `text` holds something only the owner at this machine is told.
    fn tells_the_owner_alone(text: &str) -> bool {
        ["marguerite", "501", "502", "chmod", "/"]
            .iter()
            .any(|name| text.contains(name))
    }

    /// `carrier` as a device is given it in the result of a call.
    fn written_in_a_result<T: serde::Serialize + serde::de::DeserializeOwned>(carrier: &T) -> T {
        let frame = ControlFrame::Response(Response {
            request_id: RequestId::new(9),
            outcome: Outcome::Ok(ParamsValue::from_typed(carrier).expect("encodes")),
        });
        let Cow::Owned(ControlFrame::Response(Response {
            outcome: Outcome::Ok(value),
            ..
        })) = frame_for_a_device(&frame)
        else {
            panic!("a result with a failure that names the host was passed as it was");
        };
        kr_cbor::from_canonical_value(value.as_value()).expect("decodes")
    }

    fn privacy_report(reason: &str) -> kr_protocol::privacy::PrivacyReport {
        use kr_protocol::privacy::{
            PrivacyCompletion, PrivacyReport, PrivacySession, PrivacySessionStanding,
            PrivacyUnavailable,
        };
        let unavailable = || PrivacyUnavailable {
            subsystem: "archive".to_owned(),
            reason: reason.to_owned(),
        };
        PrivacyReport {
            generation: U64::new(3),
            enabled: true,
            changed_at_ms: kr_protocol::scalars::TimestampMs::new(1),
            completion: PrivacyCompletion::Unavailable {
                unavailable: vec![unavailable()],
                outstanding: Vec::new(),
            },
            sessions: vec![PrivacySession {
                session_id: SessionId::new(kr_protocol::scalars::Uuid::from_bytes([6; 16])),
                generation: U64::new(3),
                standing: PrivacySessionStanding::Unavailable {
                    reason: reason.to_owned(),
                },
            }],
            disabled: Vec::new(),
            kept: Vec::new(),
            exported: Vec::new(),
            unlisted: vec![unavailable()],
        }
    }

    fn workspace(detail: &str, retained: &str) -> kr_protocol::project::WorkspaceSummary {
        use kr_protocol::ids::{ChangeSetId, EnvironmentId, ProjectRepositoryId, WorkspaceId};
        use kr_protocol::project::{
            InclusionPolicy, IsolationMechanism, RetainedItem, RetainedKind, WorkspaceKind,
            WorkspaceState, WorkspaceSummary,
        };
        use kr_protocol::scalars::{TimestampMs, Uuid};
        WorkspaceSummary {
            workspace_id: WorkspaceId::new(Uuid::from_bytes([1; 16])),
            project_repository_id: ProjectRepositoryId::new(Uuid::from_bytes([2; 16])),
            environment_id: EnvironmentId::new(Uuid::from_bytes([3; 16])),
            label: "a label the caller chose".to_owned(),
            kind: WorkspaceKind::Isolated,
            isolation: Nullable::some(IsolationMechanism::GitWorktree),
            policy: InclusionPolicy::base_only(),
            state: WorkspaceState::RemovalPending,
            base_revision: "a".repeat(40),
            base_change_set_id: Nullable::null(),
            filesystem_identity: Nullable::null(),
            display_path: "/work/a-tree".to_owned(),
            detail: Nullable::some(detail.to_owned()),
            bound_sessions: Vec::new(),
            bound_runs: Vec::new(),
            retained: vec![RetainedItem {
                kind: RetainedKind::PinnedChangeSet,
                detail: retained.to_owned(),
                change_set_id: Nullable::some(ChangeSetId::new(Uuid::from_bytes([4; 16]))),
            }],
            created_at_ms: TimestampMs::new(1),
        }
    }

    fn operation(detail: &str) -> kr_protocol::project::OperationRecord {
        use kr_protocol::ids::{ActionId, EnvironmentId, ProjectRepositoryId};
        use kr_protocol::project::{DestinationState, OperationRecord, OperationState};
        use kr_protocol::scalars::{TimestampMs, Uuid};
        OperationRecord {
            action_id: ActionId::new(Uuid::from_bytes([5; 16])),
            environment_id: EnvironmentId::new(Uuid::from_bytes([3; 16])),
            project_repository_id: ProjectRepositoryId::new(Uuid::from_bytes([2; 16])),
            method: "project.clone".to_owned(),
            state: OperationState::Failed,
            remote: Nullable::null(),
            destination_state: DestinationState::Absent,
            retained_staging_paths: Vec::new(),
            removed_staging_paths: Vec::new(),
            detail: Nullable::some(detail.to_owned()),
            started_at_ms: TimestampMs::new(1),
            ended_at_ms: Nullable::null(),
        }
    }

    fn instance(refusal: &str) -> kr_protocol::projection::AgentInstanceSummary {
        kr_protocol::projection::AgentInstanceSummary {
            application_instance_id: kr_protocol::ids::ApplicationInstanceId::new(
                kr_ipc::new_uuid(),
            ),
            plugin_id: Nullable::null(),
            profile_id: Nullable::null(),
            mode: kr_protocol::broker::IntegrationMode::NativeTerminal,
            bypass: Nullable::null(),
            started_at: kr_protocol::scalars::TimestampMs::new(1),
            ended_at: Nullable::null(),
            refusal: Nullable::some(refusal.to_owned()),
        }
    }

    #[test]
    fn the_failure_of_a_privacy_step_is_held_to_the_rule_by_its_key() {
        use kr_protocol::privacy::{PrivacyCompletion, PrivacySessionStanding};
        let owner = privacy_report(AN_OWNERSHIP_FAILURE);
        let device = written_in_a_result(&owner);
        let PrivacyCompletion::Unavailable { unavailable, .. } = &device.completion else {
            panic!("{:?}", device.completion);
        };
        let PrivacySessionStanding::Unavailable { reason } = &device.sessions[0].standing else {
            panic!("{:?}", device.sessions);
        };
        for told in [&unavailable[0].reason, reason, &device.unlisted[0].reason] {
            assert!(!tells_the_owner_alone(told), "{told}");
            assert!(
                told.starts_with("the recovery directory could not be used"),
                "the clause before the place is kept: {told}"
            );
        }
        // Nothing else in the report changed.
        assert_eq!(device, privacy_report(&device.unlisted[0].reason));
    }

    #[test]
    fn the_detail_of_a_project_or_a_workspace_is_held_to_the_rule_by_its_key() {
        use kr_protocol::project::{
            ProjectOperationCancelResult, RetainedItem, RetainedKind, WorkspaceRemoveResult,
        };
        let removed = WorkspaceRemoveResult {
            workspace: workspace(
                "the staging directory /Users/marguerite/work/.kr-staging-1 is still there",
                A_FAILURE_AT_A_PATH,
            ),
            working_files_removed: false,
            retained: vec![RetainedItem {
                kind: RetainedKind::DirtyContent,
                detail: "the repository could not be inspected: open \
                         /Users/marguerite/work/.git: permission denied"
                    .to_owned(),
                change_set_id: Nullable::null(),
            }],
        };
        let device = written_in_a_result(&removed);
        for told in [
            device.workspace.detail.0.as_deref().expect("kept"),
            &device.workspace.retained[0].detail,
            &device.retained[0].detail,
        ] {
            assert!(!tells_the_owner_alone(told), "{told}");
        }
        assert!(
            device.retained[0]
                .detail
                .starts_with("the repository could not be inspected"),
            "{:?}",
            device.retained
        );
        // What is not a failure is as it was, and the workspace's place is withheld as a path is.
        assert_eq!(
            device.workspace.display_path,
            withheld_path(&removed.workspace.display_path)
        );
        assert_eq!(device.workspace.state, removed.workspace.state);

        let cancelled = ProjectOperationCancelResult {
            operation: operation(
                "removing the staging path stopped: /Users/marguerite/p/.kr-stage-7: denied",
            ),
            stopped_processes: U64::new(0),
        };
        let device = written_in_a_result(&cancelled);
        let told = device.operation.detail.0.as_deref().expect("kept");
        assert!(!tells_the_owner_alone(told), "{told}");
        assert!(
            told.starts_with("removing the staging path stopped"),
            "{told}"
        );
    }

    #[test]
    fn the_refusal_of_an_agent_instance_is_held_to_the_rule_in_a_result_and_in_an_event() {
        use kr_protocol::projection::{AgentInstanceEvent, AgentInstanceList};
        let list = AgentInstanceList {
            sequence: U64::new(2),
            instances: vec![
                instance(A_FAILURE_AT_A_PATH),
                instance("no bridge is offered"),
            ],
        };
        let device = written_in_a_result(&list);
        let told = device.instances[0].refusal.0.as_deref().expect("kept");
        assert!(!tells_the_owner_alone(told), "{told}");
        assert_eq!(device.instances[1], list.instances[1]);

        let event = AgentInstanceEvent {
            session_id: SessionId::new(kr_ipc::new_uuid()),
            sequence: U64::new(3),
            instance: instance(A_FAILURE_AT_A_PATH),
        };
        let announced = ControlFrame::Notification(Notification {
            stream_id: StreamId::new("s").expect("a stream"),
            sequence: kr_protocol::ids::EventSequence::new(1),
            event_type: EventType::new(kr_protocol::projection::AGENT_INSTANCE_EVENT)
                .expect("an event type"),
            payload: ParamsValue::from_typed(&event).expect("encodes"),
        });
        let Cow::Owned(ControlFrame::Notification(written)) = frame_for_a_device(&announced) else {
            panic!("an announcement that names the host was passed as it was");
        };
        let written: AgentInstanceEvent = written.payload.to_typed().expect("decodes");
        let told = written.instance.refusal.0.as_deref().expect("kept");
        assert!(!tells_the_owner_alone(told), "{told}");
        assert_eq!(
            written.instance.application_instance_id,
            event.instance.application_instance_id
        );
    }

    #[test]
    fn a_task_the_scheduler_holds_that_is_not_the_environments_own_is_told_to_a_device_without_the_account()
     {
        use crate::supervision::windows::{Foreign, ForeignReason, task_name};
        let environment_id = kr_protocol::ids::EnvironmentId::new(kr_ipc::new_uuid());
        let described = "KalaReach environment".to_owned();
        let reasons = [
            "marguerite",
            "marguerite@example.com",
            "DESKTOP-4F2\\marguerite",
        ]
        .map(|user| ForeignReason::Account {
            user: user.to_owned(),
            description: described.clone(),
        })
        .into_iter()
        .chain([
            ForeignReason::Unreadable {
                said: "Access is denied for marguerite".to_owned(),
            },
            ForeignReason::Environment {
                description: described.clone(),
            },
        ]);
        for reason in reasons {
            let foreign = Foreign {
                name: task_name(environment_id),
                environment_id,
                reason,
            };
            // The create route's text: the supervisor's refusal, then the command that mends it.
            // The refusal is told the same without the command, which is not what holds it.
            for said in [
                format!(
                    "could not start a worker: {foreign}: run kr host startup --set standalone \
                     for this environment"
                ),
                format!("could not start a worker: {foreign}"),
            ] {
                let shown =
                    error_for_a_device(&error(ErrorCode::ResourceUnavailable, &said)).into_owned();
                assert_eq!(shown.code, ErrorCode::ResourceUnavailable);
                assert!(
                    shown.message.contains("not this installation's own")
                        && !shown.message.contains("marguerite")
                        && !shown.message.contains("kr host"),
                    "{said}: {shown:?}"
                );
            }
        }
    }

    /// What a device is told when `method` is answered with `message` under `code`.
    fn told_on(method: Method, code: ErrorCode, message: &str) -> ProtocolError {
        let answer = ControlFrame::Response(Response {
            request_id: RequestId::new(8),
            outcome: Outcome::Error(error(code, message)),
        });
        let ControlFrame::Response(Response {
            outcome: Outcome::Error(told),
            ..
        }) = frame_for_a_device(&upstream_words(method, answer)).into_owned()
        else {
            panic!("an error");
        };
        told
    }

    #[test]
    fn the_hosts_own_reasons_for_refusing_a_devices_argument_reach_it_on_the_agent_methods() {
        use kr_protocol::agent::{
            AgentMutationTarget, AgentPromptParams, AgentSubject, PromptText,
        };
        let target = AgentMutationTarget {
            subject: AgentSubject {
                session_id: SessionId::new(kr_ipc::new_uuid()),
                application_instance_id: kr_protocol::ids::ApplicationInstanceId::new(
                    kr_ipc::new_uuid(),
                ),
            },
            binding_revision: kr_protocol::ids::AgentBindingRevision::new(1),
        };
        let prompt = |draft: bool, text: bool| AgentPromptParams {
            target,
            draft_id: if draft {
                Nullable::some(kr_protocol::ids::DraftId::new(kr_ipc::new_uuid()))
            } else {
                Nullable::null()
            },
            text: if text {
                Nullable::some(PromptText::new("go").expect("a prompt"))
            } else {
                Nullable::null()
            },
        };
        let neither = prompt(false, false).validate().expect_err("no prompt");
        let both = prompt(true, true).validate().expect_err("two prompts");
        // A reason with no word of the argument in it is sent as the host wrote it.
        for (method, message) in [
            (Method::AgentPromptSubmit, neither),
            (Method::AgentPromptQueue, both),
        ] {
            let told = told_on(method, ErrorCode::InvalidArgument, message);
            assert_eq!(told.message, message, "{method:?}");
            assert_eq!(told.code, ErrorCode::InvalidArgument);
        }
        // The worker's refusals that quote a word or a number of the argument are told by what they
        // refuse, without it.
        for (message, kind, quoted) in [
            (
                "summarise does not declare a parameter named depth",
                "does not declare a parameter",
                "depth",
            ),
            (
                "the parameter depth of summarise does not accept this value",
                "does not accept the value",
                "summarise",
            ),
            (
                "the package does not accept application/zip as an attachment",
                "does not accept this kind of attachment",
                "zip",
            ),
            (
                "the package accepts 1048576 bytes of an attachment and this one is 2097152",
                "larger than the package accepts",
                "1048576",
            ),
        ] {
            let told = told_on(
                Method::PluginActionInvoke,
                ErrorCode::InvalidArgument,
                message,
            );
            assert_eq!(told.code, ErrorCode::InvalidArgument);
            assert!(
                told.message.contains(kind) && !told.message.contains(quoted),
                "{message}: {told:?}"
            );
        }
    }

    #[test]
    fn what_the_upstream_said_is_withheld_from_a_device_on_the_agent_methods() {
        // The upstream's own words come back under the same code as the host's own reasons.
        let upstream = |said: &str| {
            kr_worker::broker::BrokerError::UpstreamRefused {
                detail: said.to_owned(),
            }
            .to_protocol_error()
        };
        for said in [
            "account marguerite cannot run git status",
            "invalid params: cwd must be inside the project",
            // The words of a reason of the host's, with more after them.
            "the package does not accept application/zip as an attachment, said marguerite",
            // The words of a reason of the host's with the account in the place of a word of the
            // argument, which the shape cannot tell from the argument's own word.
            "the parameter marguerite of summarise does not accept this value",
            "marguerite@example.com does not declare a parameter named depth",
            "the package does not accept marguerite as an attachment",
            "the package accepts marguerite bytes of an attachment and this one is 20",
            // And a number that is an account's, in the place of a size.
            "the package accepts 501 bytes of an attachment and this one is 2097152",
            "the package accepts 1048576 bytes of an attachment and this one is 502",
        ] {
            let refused = upstream(said);
            assert_eq!(refused.code, ErrorCode::InvalidArgument);
            let told = told_on(Method::AgentPromptSubmit, refused.code, &refused.message);
            assert_eq!(told.code, ErrorCode::InvalidArgument);
            assert!(
                !["marguerite", "cwd", "501", "502"]
                    .iter()
                    .any(|word| told.message.contains(word)),
                "{told:?}"
            );
        }
        // A reason of the host's that quotes a place is told by its kind, without the place.
        let told = told_on(
            Method::PluginActionInvoke,
            ErrorCode::InvalidArgument,
            "the package does not accept /Users/marguerite/x.zip as an attachment",
        );
        assert!(
            !told.message.contains("marguerite") && !told.message.contains('/'),
            "{told:?}"
        );
    }

    /// What `text` becomes when this host withholds a path, as the materialisation's directory is.
    fn withheld_path(text: &str) -> String {
        kr_protocol::hostinfo::export::withheld(
            kr_protocol::hostinfo::export::ContentClass::Path,
            text,
        )
    }

    /// `carrier` as a device is given it in the result of a call, whether or not that changes it.
    fn read_by_a_device<T: serde::Serialize + serde::de::DeserializeOwned>(carrier: &T) -> T {
        let frame = ControlFrame::Response(Response {
            request_id: RequestId::new(9),
            outcome: Outcome::Ok(ParamsValue::from_typed(carrier).expect("encodes")),
        });
        let ControlFrame::Response(Response {
            outcome: Outcome::Ok(value),
            ..
        }) = frame_for_a_device(&frame).into_owned()
        else {
            panic!("a result");
        };
        kr_cbor::from_canonical_value(value.as_value()).expect("decodes")
    }

    fn binding(reason: Option<&str>) -> kr_protocol::agent::AgentBindingState {
        kr_protocol::agent::AgentBindingState {
            binding_revision: kr_protocol::ids::AgentBindingRevision::new(3),
            thread_id: Nullable::null(),
            turn_id: Nullable::null(),
            profile_id: Nullable::null(),
            mode: kr_protocol::broker::IntegrationMode::Gateway,
            rich_mutations_suspended: reason.is_some(),
            suspension_reason: Nullable::from(reason.map(str::to_owned)),
        }
    }

    /// `binding` as a device reads it in each of the three answers that carry one:
    /// `agent.capabilities`, `agent.commands` and `agent.snapshot`.
    fn bindings_a_device_reads(
        binding: &kr_protocol::agent::AgentBindingState,
    ) -> [kr_protocol::agent::AgentBindingState; 3] {
        use kr_protocol::agent::{
            AgentCapabilitiesResult, AgentCommandsResult, AgentSnapshotResult,
        };
        [
            read_by_a_device(&AgentCapabilitiesResult {
                binding: binding.clone(),
                capabilities: kr_protocol::broker::CapabilityMap {
                    records: Vec::new(),
                },
            })
            .binding,
            read_by_a_device(&AgentCommandsResult {
                binding: binding.clone(),
                commands: Vec::new(),
            })
            .binding,
            read_by_a_device(&AgentSnapshotResult {
                binding: binding.clone(),
                entries: Vec::new(),
                continuation: Nullable::null(),
                history_gap: false,
                withheld_entries: U64::ZERO,
            })
            .binding,
        ]
    }

    /// A failed conversation lock, as the worker words it: the place of the lock file under the
    /// home directory of an account.
    const A_CONVERSATION_LOCK_THAT_FAILED: &str = "the conversation the terminal selected cannot be \
         bound here: the claim on the saved conversation could not be made: \
         /Users/marguerite/.local/state/kr/claims/9f2c41.lock: Permission denied (os error 13)";

    #[test]
    fn why_rich_mutations_wait_is_told_to_a_device_without_what_the_host_or_the_upstream_put_in_it()
    {
        for (reason, kind) in [
            (
                A_CONVERSATION_LOCK_THAT_FAILED.to_owned(),
                "the conversation the terminal selected cannot be bound here",
            ),
            // An upstream's method, quoted whole: a bare name, an address, a command.
            (
                "marguerite is not classified by this connector's table, so what the terminal \
                 asked for is unknown"
                    .to_owned(),
                "does not classify",
            ),
            (
                "marguerite@example.com is not classified by this connector's table, so what it \
                 changed is unknown"
                    .to_owned(),
                "does not classify",
            ),
            (
                "net user marguerite is not classified by this connector's table, so what it \
                 changed is unknown"
                    .to_owned(),
                "does not classify",
            ),
            // A reason of nobody's that this host knows.
            ("marguerite asked for this".to_owned(), "suspended"),
        ] {
            let owner = binding(Some(&reason));
            for device in bindings_a_device_reads(&owner) {
                let told = device.suspension_reason.0.as_deref().expect("a reason");
                assert!(!tells_the_owner_alone(told), "{reason}: {told}");
                assert!(!told.contains("example.com"), "{reason}: {told}");
                assert!(!told.contains("net user"), "{reason}: {told}");
                assert!(told.contains(kind), "{reason}: {told}");
                // Nothing else of the binding changes.
                assert!(device.rich_mutations_suspended);
                assert_eq!(
                    kr_protocol::agent::AgentBindingState {
                        suspension_reason: owner.suspension_reason.clone(),
                        ..device
                    },
                    owner
                );
            }
        }
    }

    #[test]
    fn why_rich_mutations_wait_is_told_as_it_is_when_the_host_wrote_it_and_it_names_nothing() {
        let held_elsewhere = format!(
            "the conversation the terminal selected cannot be bound here: {}",
            kr_worker::broker::BrokerError::ConversationHeldElsewhere
        );
        for reason in [
            kr_worker::broker::THREAD_NOT_READ,
            kr_worker::broker::bridge::UNVERIFIED_THREAD,
            "the terminal has asked to change its conversation and the server has not answered, \
             so which conversation it is in is unknown",
            "what became of the terminal's last request to change its conversation is unknown, \
             so which conversation it is in is unknown",
            held_elsewhere.as_str(),
        ] {
            let owner = binding(Some(reason));
            for device in bindings_a_device_reads(&owner) {
                assert_eq!(device, owner, "{reason}");
            }
        }
        let free = binding(None);
        for device in bindings_a_device_reads(&free) {
            assert_eq!(device, free);
        }
    }

    #[test]
    fn what_the_task_scheduler_said_is_not_told_to_a_device() {
        use crate::supervision::windows::{Asked, Outcome as Ran, ReadBack, TaskError, task_name};
        let name = task_name(kr_protocol::ids::EnvironmentId::new(kr_ipc::new_uuid()));
        // What each command of the Task Scheduler's failure begins with, and what it was doing.
        let failures = [
            (format!("{DID_NOT_REGISTER}{name}"), "register"),
            (format!("{DID_NOT_REMOVE}{name}"), "remove"),
            (format!("{COULD_NOT_LIST}its tasks"), "list"),
            (format!("{COULD_NOT_LIST}{name}"), "list"),
            (format!("{DID_NOT_RUN}{name}"), "run"),
        ];
        // What it may say after: a bare account, an address, a line of an identity, a command.
        let said = [
            "ERROR: Access is denied for marguerite",
            "ERROR: the user marguerite@example.com has no right to this task",
            "uid: 501\ngid: 20",
            "the account is not known; list it with net user marguerite",
        ];
        for (what, verb) in &failures {
            for said in said {
                let scheduler = TaskError::Scheduler {
                    asked: Asked::Register,
                    outcome: Ran::Ended(Some(1)),
                    detail: format!("{what}: {said}"),
                };
                // The create route's text, and the text of a task that could not be read back.
                let texts = [
                    scheduler.to_string(),
                    format!("could not start a worker: {scheduler}"),
                    TaskError::ReadBack {
                        name: name.clone(),
                        found: ReadBack::Unread(scheduler.to_string()),
                        undone: true,
                    }
                    .to_string(),
                ];
                for text in texts {
                    // The owner is told the whole of it.
                    assert!(text.contains(said), "{text}");
                    let shown = error_for_a_device(&error(ErrorCode::ResourceUnavailable, &text))
                        .into_owned();
                    assert_eq!(shown.code, ErrorCode::ResourceUnavailable);
                    assert!(
                        ["marguerite", "example.com", "501", "uid", "net user"]
                            .iter()
                            .all(|local| !shown.message.contains(local)),
                        "{text}: {shown:?}"
                    );
                    assert!(
                        shown.message.starts_with("the Task Scheduler did not")
                            || shown.message.starts_with("the Task Scheduler could not"),
                        "{text}: {shown:?}"
                    );
                    assert!(shown.message.contains(verb), "{text}: {shown:?}");
                }
            }
        }
    }

    fn project(display_path: &str) -> kr_protocol::project::ProjectSummary {
        use kr_protocol::ids::{EnvironmentId, ProjectRepositoryId};
        use kr_protocol::project::{
            FilesystemIdentity, ProjectOrigin, ProjectState, ProjectSummary,
        };
        use kr_protocol::scalars::{TimestampMs, Uuid};
        ProjectSummary {
            project_repository_id: ProjectRepositoryId::new(Uuid::from_bytes([2; 16])),
            environment_id: EnvironmentId::new(Uuid::from_bytes([3; 16])),
            label: "a label the caller chose".to_owned(),
            origin: ProjectOrigin::Adopted,
            state: ProjectState::Ready,
            filesystem_identity: FilesystemIdentity {
                device: U64::new(1),
                file_id: U64::new(2),
            },
            display_path: display_path.to_owned(),
            remote: Nullable::null(),
            created_at_ms: TimestampMs::new(1),
            workspace_count: U64::new(1),
        }
    }

    fn project_read(
        project: kr_protocol::project::ProjectSummary,
        workspace: kr_protocol::project::WorkspaceSummary,
        operation: kr_protocol::project::OperationRecord,
    ) -> kr_protocol::project::ProjectReadResult {
        kr_protocol::project::ProjectReadResult {
            project,
            workspaces: vec![workspace],
            operation: Nullable::some(operation),
        }
    }

    #[test]
    fn the_place_of_a_repository_is_withheld_from_a_device() {
        let place = "/Users/marguerite/work/repo";
        let owner = project_read(
            project(place),
            workspace("it is ready", "nothing held"),
            operation("it ended"),
        );
        let device = read_by_a_device(&owner);
        assert_eq!(device.project.display_path, withheld_path(place));
        // Nothing else of the repository changes.
        assert_eq!(
            device.project,
            kr_protocol::project::ProjectSummary {
                display_path: withheld_path(place),
                ..owner.project.clone()
            }
        );
    }

    #[test]
    fn the_place_of_a_working_copy_is_withheld_from_a_device() {
        let place = "/Users/marguerite/work/tree";
        let mut tree = workspace("it is ready", "nothing held");
        tree.display_path = place.to_owned();
        let owner = project_read(project("a repository"), tree, operation("it ended"));
        let device = read_by_a_device(&owner);
        assert_eq!(device.workspaces[0].display_path, withheld_path(place));
        assert_eq!(
            device.workspaces[0],
            kr_protocol::project::WorkspaceSummary {
                display_path: withheld_path(place),
                ..owner.workspaces[0].clone()
            }
        );
    }

    #[test]
    fn the_staging_paths_an_operation_kept_are_withheld_from_a_device() {
        let kept = [
            "/Users/marguerite/work/.kr-stage-1",
            "/Users/marguerite/work/.kr-stage-2",
        ];
        let mut recorded = operation("it ended");
        recorded.retained_staging_paths = kept.map(str::to_owned).to_vec();
        let owner = kr_protocol::project::ProjectOperationCancelResult {
            operation: recorded,
            stopped_processes: U64::new(0),
        };
        let device = read_by_a_device(&owner);
        // The list keeps its length, and each entry is withheld as a path is.
        assert_eq!(
            device.operation.retained_staging_paths,
            kept.map(withheld_path).to_vec()
        );
        assert_eq!(
            device.operation,
            kr_protocol::project::OperationRecord {
                retained_staging_paths: kept.map(withheld_path).to_vec(),
                ..owner.operation.clone()
            }
        );
    }

    #[test]
    fn the_staging_paths_an_operation_removed_are_withheld_from_a_device() {
        let removed = ["/Users/marguerite/work/.kr-stage-0"];
        let mut recorded = operation("it ended");
        recorded.removed_staging_paths = removed.map(str::to_owned).to_vec();
        let owner = kr_protocol::project::ProjectOperationCancelResult {
            operation: recorded,
            stopped_processes: U64::new(0),
        };
        let device = read_by_a_device(&owner);
        assert_eq!(
            device.operation.removed_staging_paths,
            removed.map(withheld_path).to_vec()
        );
    }

    #[test]
    fn why_a_fetch_of_the_description_model_failed_is_held_to_the_rule_by_its_key() {
        use kr_protocol::describe::{DescriptionDownload, DescriptionSetup, DescriptionState};
        let setup = |failure: &str| DescriptionSetup {
            offered: true,
            enabled: true,
            on_battery: false,
            profile_id: Nullable::some("small".to_owned()),
            asset_bytes: U64::new(10),
            sources: vec!["models.example.com".to_owned()],
            download: DescriptionDownload::Failed,
            fetched_bytes: U64::new(0),
            failure: Nullable::some(failure.to_owned()),
            can_cancel: false,
            can_disable: true,
            needs_hosted_account: false,
            unavailable: Nullable::null(),
            state: DescriptionState::ResourcePaused,
            paused: Nullable::null(),
        };
        let owner = setup(
            "the folder for the model's files could not be made: create \
             /Users/marguerite/.local/share/kr/models/small: Permission denied (os error 13)",
        );
        let device = written_in_a_result(&owner);
        let told = device.failure.0.as_deref().expect("a failure");
        assert!(!tells_the_owner_alone(told), "{told}");
        assert!(
            told.starts_with("the folder for the model's files could not be made"),
            "{told}"
        );
        assert_eq!(
            device,
            DescriptionSetup {
                failure: device.failure.clone(),
                ..owner
            }
        );
        // A failure that names nothing is told as it was.
        let plain = setup("the disk is full");
        assert_eq!(read_by_a_device(&plain), plain);
    }

    #[test]
    fn a_failure_with_nothing_to_keep_is_told_by_what_it_is_about() {
        use kr_protocol::describe::{DescriptionDownload, DescriptionSetup, DescriptionState};
        use kr_protocol::privacy::{PrivacyCompletion, PrivacySessionStanding};
        let told = |of: &str| format!("{of}; {WHY_NOT_SHOWN}");

        let privacy = read_by_a_device(&privacy_report(A_FAILURE_AT_A_PATH));
        let PrivacyCompletion::Unavailable { unavailable, .. } = &privacy.completion else {
            panic!("{:?}", privacy.completion);
        };
        let PrivacySessionStanding::Unavailable { reason } = &privacy.sessions[0].standing else {
            panic!("{:?}", privacy.sessions);
        };
        assert_eq!(
            unavailable[0].reason,
            told("what the subsystem's store reported")
        );
        assert_eq!(reason, &told("why the session's cleanup is unavailable"));

        let tree = read_by_a_device(&workspace(A_FAILURE_AT_A_PATH, A_FAILURE_AT_A_PATH));
        assert_eq!(
            tree.detail.0.as_deref(),
            Some(told("why the workspace is in this state").as_str())
        );
        assert_eq!(tree.retained[0].detail, told("what the workspace holds"));

        let recorded = operation(A_FAILURE_AT_A_PATH);
        let recorded = read_by_a_device(&kr_protocol::project::ProjectOperationCancelResult {
            operation: recorded,
            stopped_processes: U64::new(0),
        });
        assert_eq!(
            recorded.operation.detail.0.as_deref(),
            Some(told("why the operation ended").as_str())
        );

        let refused = read_by_a_device(&kr_protocol::projection::AgentInstanceList {
            sequence: U64::new(2),
            instances: vec![instance(A_FAILURE_AT_A_PATH)],
        });
        assert_eq!(
            refused.instances[0].refusal.0.as_deref(),
            Some(told("why the instance's bridges are refused").as_str())
        );

        let fetch = read_by_a_device(&DescriptionSetup {
            offered: true,
            enabled: true,
            on_battery: false,
            profile_id: Nullable::null(),
            asset_bytes: U64::new(0),
            sources: Vec::new(),
            download: DescriptionDownload::Failed,
            fetched_bytes: U64::new(0),
            failure: Nullable::some(A_FAILURE_AT_A_PATH.to_owned()),
            can_cancel: false,
            can_disable: true,
            needs_hosted_account: false,
            unavailable: Nullable::null(),
            state: DescriptionState::ResourcePaused,
            paused: Nullable::null(),
        });
        assert_eq!(
            fetch.failure.0.as_deref(),
            Some(told("why the fetch of the description model failed").as_str())
        );
    }

    #[test]
    fn a_member_that_shares_the_key_of_a_failure_but_not_its_record_is_left_alone() {
        use kr_protocol::privacy::PrivacySessionStanding;
        // A standing that is not the unavailable one carries no reason to hold.
        let other = kr_cbor::to_canonical_value(&PrivacySessionStanding::Unavailable {
            reason: A_FAILURE_AT_A_PATH.to_owned(),
        })
        .expect("encodes");
        let CanonicalValue::Map(map) = other else {
            panic!("a record");
        };
        let relabelled = rebuilt(
            map.entries()
                .iter()
                .map(|(key, value)| match (key.as_str(), value) {
                    ("state", CanonicalValue::Text(_)) => {
                        (key.clone(), CanonicalValue::Text("ready".to_owned()))
                    }
                    _ => (key.clone(), value.clone()),
                })
                .collect(),
        );
        assert_eq!(shown_value(&relabelled), None);
    }

    /// The six methods that put words to the agent of a session.
    const THE_AGENT_METHODS: [Method; 6] = [
        Method::AgentPromptSubmit,
        Method::AgentPromptQueue,
        Method::AgentTurnSteer,
        Method::AgentTurnCancel,
        Method::AgentApprovalRespond,
        Method::PluginActionInvoke,
    ];

    #[test]
    fn what_the_agent_said_is_withheld_on_each_of_the_methods_that_put_words_to_it() {
        let mut leaked = Vec::new();
        for method in THE_AGENT_METHODS {
            for code in [
                ErrorCode::InvalidArgument,
                ErrorCode::UpstreamUnavailable,
                ErrorCode::OutcomeUnknown,
            ] {
                // A bare name is not a path, a number or a command, so only the rule for the
                // agent's words holds it.
                let told = told_on(method, code, "marguerite refused this request");
                assert_eq!(told.code, code, "{method:?}");
                if told.message.contains("marguerite") {
                    leaked.push(format!("{method:?} {code:?}"));
                }
            }
        }
        assert!(
            leaked.is_empty(),
            "the agent's words reach a device: {leaked:?}"
        );
    }

    #[test]
    fn a_reason_of_the_hosts_is_told_only_when_the_whole_message_is_that_reason() {
        for method in [Method::AgentPromptSubmit, Method::PluginActionInvoke] {
            for said in [
                "a prompt names either a draft or inline text, said marguerite",
                "marguerite: a prompt names a draft or inline text, not both",
                "a prompt names either a draft or inline text a prompt names either a draft or \
                 inline text",
            ] {
                let told = told_on(method, ErrorCode::InvalidArgument, said);
                assert!(!told.message.contains("marguerite"), "{said}: {told:?}");
                assert_ne!(told.message, said);
            }
        }
    }

    #[test]
    fn a_slot_of_a_shape_holds_a_word_and_not_nothing() {
        let shape = "{} does not declare a parameter named {}";
        assert!(fits_shape(
            shape,
            "summarise does not declare a parameter named depth"
        ));
        assert!(!fits_shape(
            shape,
            " does not declare a parameter named depth"
        ));
        assert!(!fits_shape(
            shape,
            "summarise does not declare a parameter named "
        ));
        // An apostrophe ends a word, so a name that holds one fits no shape that says `{}'s`.
        assert!(fits_shape(
            "{}'s parameters are bad",
            "summarise's parameters are bad"
        ));
        assert!(!fits_shape("{} is bad", "marguerite's is bad"));
        assert!(fits_shape("{}, and more", "word, and more"));
        assert!(!fits_shape("{} and more", "word, and more"));
        // The rest of a message is more than nothing.
        assert!(fits_shape(
            "the component is disabled: {..}",
            "the component is disabled: off"
        ));
        assert!(!fits_shape(
            "the component is disabled: {..}",
            "the component is disabled: "
        ));
    }

    #[test]
    fn what_the_plugin_runtime_said_is_withheld_from_a_device_whatever_the_code() {
        for (code, said, kind) in [
            (
                ErrorCode::ResourceUnavailable,
                "summarise's component is not registered with the plugin runtime yet: the \
                 runtime said marguerite may not",
                "is not registered with the plugin runtime yet",
            ),
            (
                ErrorCode::ResourceUnavailable,
                "summarise's component is not registered with the plugin runtime yet",
                "is not registered with the plugin runtime yet",
            ),
            (
                ErrorCode::UnsupportedCapability,
                "summarise's component cannot be prepared: the component of marguerite is not \
                 signed",
                "cannot be prepared",
            ),
            (
                ErrorCode::UnsupportedCapability,
                "the component is disabled: marguerite turned it off",
                "is disabled",
            ),
            (
                ErrorCode::ResourceUnavailable,
                "the component could not be asked to prepare the action: permission denied for \
                 marguerite",
                "could not be asked to prepare the action",
            ),
            (
                ErrorCode::UnsupportedCapability,
                "this binding's rich capabilities are disabled: marguerite turned them off",
                "rich capabilities are disabled",
            ),
            (
                ErrorCode::UnsupportedCapability,
                "the component answerable for this operation has had its rich capabilities \
                 disabled: marguerite's decoder faulted",
                "answerable for this operation",
            ),
            (
                ErrorCode::ResourceUnavailable,
                "12 actions are being prepared already, and this one was not reached in time",
                "are being prepared already",
            ),
            (
                ErrorCode::UnsupportedCapability,
                "summarise offers an attachment and its package declares no attachments",
                "package declares no attachments",
            ),
            (
                ErrorCode::UnsupportedCapability,
                "summarise's package inserts an attachment by Paste, and a worker offers one \
                 only by an upload to the upstream",
                "inserts an attachment in a way a worker does not offer",
            ),
        ] {
            let told = told_on(Method::PluginActionInvoke, code, said);
            assert_eq!(told.code, code, "{said}");
            assert!(told.message.contains(kind), "{said}: {told:?}");
            assert!(
                !told.message.contains("marguerite") && !told.message.contains("summarise"),
                "{said}: {told:?}"
            );
        }
        // The host's own sentences, which say nothing of the runtime's words, are told as they are.
        for (code, said) in [
            (
                ErrorCode::ResourceUnavailable,
                "the plugin runtime is not connected",
            ),
            (
                ErrorCode::UnsupportedCapability,
                "the component is disabled; the runtime's words are withheld for privacy mode",
            ),
            (
                ErrorCode::ResourceUnavailable,
                "the plugin runtime refused to ask the component to prepare the action; its \
                 words are withheld for privacy mode",
            ),
            (
                ErrorCode::UnsupportedCapability,
                "this worker has no control daemon to read a draft from",
            ),
            (
                ErrorCode::ResourceUnavailable,
                "reports of earlier offers are still waiting for the control daemon",
            ),
            (
                ErrorCode::ResourceUnavailable,
                "preparations are no longer accepted",
            ),
            (
                ErrorCode::ResourceUnavailable,
                "the time to prepare this action ran out before the component was asked",
            ),
        ] {
            assert_eq!(
                told_on(Method::PluginActionInvoke, code, said).message,
                said
            );
        }
    }

    #[test]
    fn the_useful_reasons_for_refusing_the_arguments_of_an_action_are_told_without_the_arguments() {
        for (said, kind) in [
            (
                "summarise's parameters: the required parameter depth is absent",
                "requires is absent",
            ),
            (
                "summarise's parameters: the value of depth is outside its declared bound",
                "outside the bound",
            ),
            (
                "summarise's parameters: the parameter depth is supplied more than once",
                "supplied more than once",
            ),
            (
                "summarise's parameters name a member more than once, and two readers of them \
                 could disagree",
                "name a member more than once",
            ),
            (
                "summarise's parameters: the parameter depth does not accept this value",
                "does not accept the value",
            ),
            (
                "summarise names no attachment to offer",
                "names no attachment",
            ),
            (
                "summarise is not prepared by a component",
                "not prepared by a component",
            ),
        ] {
            let told = told_on(Method::PluginActionInvoke, ErrorCode::InvalidArgument, said);
            assert_eq!(told.code, ErrorCode::InvalidArgument, "{said}");
            assert!(told.message.contains(kind), "{said}: {told:?}");
            assert!(
                !told.message.contains("depth") && !told.message.contains("summarise"),
                "{said}: {told:?}"
            );
        }
    }

    #[test]
    fn a_candidate_is_told_nothing_of_the_rendezvous_setting_either() {
        let peer = ConnectionPeer::new(
            kr_protocol::scalars::EndpointKey::from_bytes([1; 32]),
            false,
            kr_protocol::ids::ConnectionId::new(kr_ipc::new_uuid()),
        );
        let refused = ForACandidate(Arc::new(Failing(error(
            ErrorCode::RendezvousConfigError,
            "the rendezvous setting is malformed",
        ))))
        .call(PairingMethod::Status, &peer, &ParamsValue::empty())
        .expect_err("the surface fails");
        assert!(!refused.message.contains("malformed"), "{refused:?}");
        assert_eq!(refused.code, ErrorCode::RendezvousConfigError);
    }

    #[test]
    fn the_refusal_of_a_rich_mutation_says_why_they_wait_without_the_words_of_the_reason() {
        let mut leaked = Vec::new();
        for method in THE_AGENT_METHODS {
            for (reason, kind) in [
                (A_CONVERSATION_LOCK_THAT_FAILED, "cannot be bound here"),
                // The method of a request that the connector's table does not classify is the
                // upstream's: a bare name, an address, a command.
                (
                    "marguerite is not classified by this connector's table, so what it changed \
                     is unknown",
                    "does not classify",
                ),
                (
                    "marguerite@example.com is not classified by this connector's table, so what \
                     the terminal asked for is unknown",
                    "does not classify",
                ),
                (
                    "net user marguerite is not classified by this connector's table, so what it \
                     changed is unknown",
                    "does not classify",
                ),
                ("marguerite asked for this", "the detail is not sent"),
            ] {
                // The refusal as the worker writes it.
                let said = kr_worker::broker::BrokerError::mutations_suspended(reason)
                    .to_protocol_error()
                    .message;
                let told = told_on(method, ErrorCode::DraftConflict, &said);
                assert_eq!(told.code, ErrorCode::DraftConflict, "{method:?}");
                if tells_the_owner_alone(&told.message)
                    || told.message.contains("example.com")
                    || told.message.contains("net user")
                    || !told.message.contains("rich mutations are suspended")
                    || !told.message.contains(kind)
                {
                    leaked.push(format!("{method:?}: {told:?}"));
                }
            }
            // The host's own reason is told as it is written.
            let own = kr_worker::broker::BrokerError::mutations_suspended(
                kr_worker::broker::THREAD_NOT_READ,
            )
            .to_protocol_error()
            .message;
            assert_eq!(
                told_on(method, ErrorCode::DraftConflict, &own).message,
                own,
                "{method:?}"
            );
        }
        assert!(
            leaked.is_empty(),
            "the reason reaches a device in a refusal: {leaked:#?}"
        );
    }

    fn remote(
        transport: kr_protocol::project::RemoteTransport,
        url: &str,
    ) -> kr_protocol::project::RemoteSpecification {
        kr_protocol::project::RemoteSpecification {
            remote_name: "origin".to_owned(),
            transport,
            url: url.to_owned(),
            provider: String::new(),
            credential_broker: String::new(),
        }
    }

    #[test]
    fn the_place_of_the_repository_a_clone_was_made_from_is_withheld_from_a_device() {
        use kr_protocol::project::RemoteTransport;
        let source = "/Users/marguerite/work/source";
        let mut cloned = project("a repository");
        cloned.remote = Nullable::some(remote(RemoteTransport::LocalPath, source));
        let mut made = operation("it ended");
        made.remote = Nullable::some(remote(RemoteTransport::LocalPath, source));
        let owner = project_read(cloned, workspace("it is ready", "nothing held"), made);
        let device = read_by_a_device(&owner);
        let withheld_remote = |remote: &Nullable<kr_protocol::project::RemoteSpecification>| {
            remote.0.as_ref().expect("a remote").url.clone()
        };
        assert_eq!(
            withheld_remote(&device.project.remote),
            withheld_path(source)
        );
        assert_eq!(
            withheld_remote(&device.operation.0.as_ref().expect("an operation").remote),
            withheld_path(source)
        );
        // The rest of the remote is as it was.
        let kept = device.project.remote.0.as_ref().expect("a remote");
        assert_eq!(kept.transport, RemoteTransport::LocalPath);
        assert_eq!(kept.remote_name, "origin");

        // The address of a remote on the web is the owner's to share and is not held.
        let mut web = project("a repository");
        web.remote = Nullable::some(remote(
            RemoteTransport::Https,
            "https://example.com/org/repo.git",
        ));
        let web = project_read(
            web,
            workspace("it is ready", "nothing held"),
            operation("it ended"),
        );
        assert_eq!(
            withheld_remote(&read_by_a_device(&web).project.remote),
            "https://example.com/org/repo.git"
        );
    }

    #[test]
    fn why_the_admissions_leave_an_installation_out_is_told_without_the_words_after_the_hosts_clause()
     {
        use crate::catalogue::admissions::unrecordable_detail;
        use kr_plugin_catalogue::admission::{NotAdmitted, NotAdmittedReason};
        use kr_plugin_catalogue::{Resource, ResourceLimit, Stage};
        use kr_plugin_sdk::catalogue::{RevocationReason, RevocationRecord};
        use kr_plugin_sdk::text::Summary;
        use kr_protocol::catalogue::{PluginAdmission, PluginLeftOutReason};
        let plugin_id = kr_protocol::ids::PluginId::new("kalareach/claude-code").expect("an id");
        let package_digest = kr_plugin_sdk::digest::PayloadDigest::of(b"a package");
        let subject = format!("{plugin_id} at {package_digest}");
        let left_out = |reason, detail: &str| PluginAdmission::LeftOut {
            reason,
            detail: detail.to_owned(),
        };
        let real = |reason: NotAdmittedReason| {
            NotAdmitted {
                plugin_id: plugin_id.clone(),
                package_digest,
                reason,
            }
            .detail()
        };
        // The clause of the host's own wording is kept and what follows the colon is not. Each
        // detail is written by the code that writes it for a person.
        let revoked = RevocationRecord {
            reason: RevocationReason::Withdrawn,
            revoked_at: kr_protocol::scalars::TimestampMs::new(1),
            statement: Summary::new("net user marguerite").expect("a statement"),
        };
        let past_a_limit = ResourceLimit {
            resource: Resource::PackageFiles,
            limit: 4096,
            requested: 5000,
            stage: Stage::Declared,
            subject: "marguerite's package".to_owned(),
        };
        let unrecordable = unrecordable_detail(
            &plugin_id,
            package_digest,
            "/Users/marguerite/x is too long",
        );
        for (reason, said, kept) in [
            (
                PluginLeftOutReason::Incomplete,
                real(NotAdmittedReason::Incomplete(
                    "/Users/marguerite/.local/share/kr/plugins/9f2c/manifest.json does not parse"
                        .to_owned(),
                )),
                format!("{subject} is not whole in this host's store"),
            ),
            (
                PluginLeftOutReason::Revoked,
                real(NotAdmittedReason::Revoked(revoked)),
                format!("{subject} was revoked by its repository"),
            ),
            (
                PluginLeftOutReason::PastALimit,
                real(NotAdmittedReason::PastALimit(past_a_limit)),
                format!("{subject} is past a package limit in force"),
            ),
            (
                PluginLeftOutReason::Unrecordable,
                unrecordable,
                format!("{subject} cannot be handed to a worker"),
            ),
        ] {
            assert!(
                said.len() > kept.len(),
                "the detail goes on after the clause: {said}"
            );
            let told = read_by_a_device(&left_out(reason, &said));
            assert_eq!(told, left_out(reason, &kept), "{said}");
        }
        // The host's own sentences that carry no words of another's are told as they were.
        for (reason, said) in [
            (
                PluginLeftOutReason::Disabled,
                real(NotAdmittedReason::Disabled),
            ),
            (
                PluginLeftOutReason::NotAllowed,
                real(NotAdmittedReason::NotAllowed),
            ),
        ] {
            let plain = left_out(reason, &said);
            assert_eq!(read_by_a_device(&plain), plain);
        }
        // A text of no wording the host knows is held to the rule.
        let told = read_by_a_device(&left_out(
            PluginLeftOutReason::Unsupported,
            "/Users/marguerite/x does not parse",
        ));
        let PluginAdmission::LeftOut { detail, .. } = told else {
            panic!("a plugin left out");
        };
        assert!(!tells_the_owner_alone(&detail), "{detail}");
    }

    #[test]
    fn a_task_that_differs_from_the_environments_own_is_told_to_a_device_without_what_it_holds() {
        use crate::supervision::windows::{Difference, ReadBack, TaskError, task_name};
        let name = task_name(kr_protocol::ids::EnvironmentId::new(kr_ipc::new_uuid()));
        let differences = vec![
            Difference::Arguments {
                found: "net user marguerite; echo ready".to_owned(),
                expected: "-NoProfile".to_owned(),
            },
            Difference::Program {
                found: "marguerite.exe".to_owned(),
                expected: std::path::PathBuf::from("starter.exe"),
            },
            Difference::RunLevel("uid: 501".to_owned()),
        ];
        let joined = differences
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ");
        for said in [
            // The launch refusal, then the command that mends it.
            format!(
                "the environment's task {name}{NOT_THE_ONE_REGISTERED}{joined}): run kr host \
                 startup --set standalone to repair it"
            ),
            // A change that read back differently.
            TaskError::ReadBack {
                name: name.clone(),
                found: ReadBack::Differs(differences.clone()),
                undone: true,
            }
            .to_string(),
        ] {
            assert!(said.contains("net user marguerite"), "{said}");
            let shown =
                error_for_a_device(&error(ErrorCode::ResourceUnavailable, &said)).into_owned();
            assert!(
                ["marguerite", "net user", "echo", "501", "kr host"]
                    .iter()
                    .all(|local| !shown.message.contains(local)),
                "{said}: {shown:?}"
            );
            assert!(
                shown.message.contains("the environment's task"),
                "{said}: {shown:?}"
            );
        }
    }

    #[test]
    fn what_disabled_the_component_of_an_approval_is_withheld_from_a_device() {
        use kr_worker::broker::BrokerError;
        // The refusals as the worker writes them.
        for refused in [
            BrokerError::component_disabled("marguerite's decoder faulted"),
            BrokerError::binding_disabled("revoked by marguerite@example.com"),
        ] {
            let said = refused.to_protocol_error().message;
            let said = said.as_str();
            let told = told_on(
                Method::AgentApprovalRespond,
                ErrorCode::UnsupportedCapability,
                said,
            );
            assert_eq!(told.code, ErrorCode::UnsupportedCapability);
            assert!(
                told.message.contains("rich capabilities")
                    && !told.message.contains("marguerite")
                    && !told.message.contains("example.com"),
                "{said}: {told:?}"
            );
        }
        // The host's own sentence under that code, which names no component's words, is as it was.
        let own = "every component bound to 0193abcd has had its rich capabilities disabled";
        assert_eq!(
            told_on(
                Method::AgentApprovalRespond,
                ErrorCode::UnsupportedCapability,
                own
            )
            .message,
            own
        );
    }

    #[test]
    fn the_plugin_runtime_rule_holds_for_a_plugins_action_and_for_no_other_method() {
        let said = "the session journal is busy";
        let replaced = told_on(
            Method::PluginActionInvoke,
            ErrorCode::ResourceUnavailable,
            said,
        );
        assert!(
            replaced.message.contains("could not complete this request"),
            "{replaced:?}"
        );
        // Elsewhere the host's own words under that code are what they were.
        for method in [Method::AgentTurnCancel, Method::AgentPromptSubmit] {
            assert_eq!(
                told_on(method, ErrorCode::ResourceUnavailable, said).message,
                said,
                "{method:?}"
            );
        }
        // A message of no shape the host knows is told by its code, whoever it names.
        for code in [
            ErrorCode::ResourceUnavailable,
            ErrorCode::UnsupportedCapability,
        ] {
            let told = told_on(
                Method::PluginActionInvoke,
                code,
                "marguerite is out of reach",
            );
            assert_eq!(told.code, code);
            assert!(
                !told.message.contains("marguerite")
                    && told.message.contains("could not complete this request"),
                "{told:?}"
            );
        }
        // And the row that says an action names no single parameter for its attachment.
        let told = told_on(
            Method::PluginActionInvoke,
            ErrorCode::UnsupportedCapability,
            "summarise declares no single parameter that names its attachment",
        );
        assert!(
            told.message.contains("declares no single parameter")
                && !told.message.contains("summarise"),
            "{told:?}"
        );
    }

    #[test]
    fn a_member_without_the_record_around_it_is_left_alone() {
        let text = |text: &str| CanonicalValue::Text(text.to_owned());
        let record = |members: &[(&str, CanonicalValue)]| {
            rebuilt(
                members
                    .iter()
                    .map(|(key, value)| ((*key).to_owned(), value.clone()))
                    .collect(),
            )
        };
        let path = "/Users/marguerite/work/x";
        let mut changed = Vec::new();
        for (what, carried) in [
            (
                "a place with no repository around it",
                record(&[("display_path", text(path))]),
            ),
            (
                "staging paths with no operation around them",
                record(&[(
                    "retained_staging_paths",
                    CanonicalValue::Array(vec![text(path)]),
                )]),
            ),
            (
                "an address on the web",
                record(&[
                    ("remote_name", text("origin")),
                    ("transport", text("https")),
                    ("url", text("https://example.com/x")),
                ]),
            ),
            (
                "an address with no remote around it",
                record(&[("transport", text("local_path")), ("url", text(path))]),
            ),
            (
                "a reason with no binding around it",
                record(&[("suspension_reason", text(A_CONVERSATION_LOCK_THAT_FAILED))]),
            ),
            (
                "a detail of an admission that admits",
                record(&[
                    ("state", text("admitted")),
                    ("reason", text("disabled")),
                    ("detail", text(path)),
                ]),
            ),
            (
                "a detail of a left-out state with no reason beside it",
                record(&[("state", text("left_out")), ("detail", text(path))]),
            ),
            (
                "a socket with no session around it",
                record(&[("endpoint", text(path))]),
            ),
            (
                "an attachment's failure with no attachment around it",
                record(&[("failure_detail", text(path))]),
            ),
            (
                "a failure of a fetch that is running",
                record(&[("download", text("running")), ("failure", text(path))]),
            ),
        ] {
            if shown_value(&carried).is_some() {
                changed.push(what);
            }
        }
        assert!(changed.is_empty(), "left alone, but held: {changed:?}");
    }

    fn session_summary() -> kr_protocol::session::SessionSummary {
        use kr_protocol::ids::{EnvironmentId, SessionEpoch};
        use kr_protocol::scalars::{TimestampMs, Uuid};
        use kr_protocol::session::{
            Dimensions, DisplayNumber, SessionState, SessionSummary, ShellMode,
        };
        SessionSummary {
            session_id: SessionId::new(Uuid::from_bytes([7; 16])),
            session_epoch: SessionEpoch::V1,
            environment_id: EnvironmentId::new(Uuid::from_bytes([3; 16])),
            display_number: DisplayNumber::new(1),
            state: SessionState::Live,
            shell_mode: ShellMode::NativeCompat,
            shell_path: "/bin/zsh".to_owned(),
            cwd: "/Users/marguerite/work".to_owned(),
            worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
            desktop: kr_protocol::identity::DesktopBinding::none(),
            created_at_ms: TimestampMs::new(1),
            dimensions: Dimensions::new(100, 30),
            attachment_count: U64::ZERO,
            application_state: Nullable::null(),
            root_process: Nullable::null(),
            closure: Nullable::null(),
            environment_sources: None,
            root: None,
            application: None,
        }
    }

    #[test]
    fn the_socket_of_a_sessions_worker_is_withheld_from_a_device() {
        let socket = "/run/user/1000/kalareach/workers/0193abcd.sock";
        let read = |endpoint: Option<&str>| kr_protocol::session::SessionReadResult {
            session: session_summary(),
            endpoint: Nullable::from(endpoint.map(str::to_owned)),
            launch_profile: Nullable::null(),
            last_command_block: Nullable::null(),
            outstanding_launches: Nullable::null(),
            metrics: None,
        };
        let owner = read(Some(socket));
        let device = read_by_a_device(&owner);
        assert_eq!(device.endpoint.0, Some(withheld_path(socket)));
        // The session is shown as it is, its working directory and its shell with it: they are how
        // a person is told what the session is.
        assert_eq!(device.session, owner.session);
        // A session that has closed has none, and none is what a device is told.
        assert_eq!(read_by_a_device(&read(None)), read(None));
        // The create's answer carries it the same way.
        let created = kr_protocol::session::SessionCreateResult {
            session: session_summary(),
            endpoint: Nullable::some(socket.to_owned()),
            deduplicated: false,
            presentation_error: Nullable::null(),
        };
        assert_eq!(
            read_by_a_device(&created).endpoint.0,
            Some(withheld_path(socket))
        );
    }

    #[test]
    fn the_program_a_questions_source_runs_reaches_a_device_as_it_is() {
        use kr_protocol::ids::{ApplicationInstanceId, ConnectionId};
        use kr_protocol::question::QuestionSource;
        use kr_protocol::scalars::Uuid;
        let program = "/Users/marguerite/.local/bin/release-agent";
        let source = |executable: Option<&str>| QuestionSource {
            application_instance_id: ApplicationInstanceId::new(Uuid::from_bytes([3; 16])),
            process: kr_protocol::identity::ProcessStartIdentity::new(
                7,
                kr_protocol::identity::ProcessStartSource::LinuxProcStat,
                11,
            ),
            executable: Nullable::from(executable.map(str::to_owned)),
            agent_label: Nullable::some("the release agent".to_owned()),
            connection_id: ConnectionId::new(Uuid::from_bytes([4; 16])),
            launch_channel: false,
            session_member: true,
            ancestry: true,
            agent_binding_revision: Nullable::null(),
        };
        // The person is shown the program the host verified, and its full path, on purpose.
        assert_eq!(
            read_by_a_device(&source(Some(program))),
            source(Some(program))
        );
        assert_eq!(read_by_a_device(&source(None)), source(None));
    }

    fn draft_attachment(failure: Option<&str>) -> kr_protocol::transfer::DraftAttachment {
        use kr_protocol::ids::{EnvironmentId, GrantId, TransferId};
        use kr_protocol::scalars::{Digest256, TimestampMs, Uuid};
        use kr_protocol::transfer::{
            AttachmentHandle, AttachmentReadGrant, DraftAttachment, InsertionMethod, InsertionState,
        };
        let environment_id = EnvironmentId::new(Uuid::from_bytes([3; 16]));
        let transfer_id = TransferId::new(Uuid::from_bytes([9; 16]));
        DraftAttachment {
            handle: AttachmentHandle {
                environment_id,
                transfer_id,
                session_id: Nullable::null(),
                byte_len: U64::new(10),
                content_digest: Digest256::from_bytes([1; 32]),
                declared_media_type: "text/plain".to_owned(),
                original_file_name: "notes.txt".to_owned(),
                preview: Nullable::null(),
                presented_as_image: false,
                published_at_ms: TimestampMs::new(1),
                expires_at_ms: TimestampMs::new(2),
                submitted: false,
            },
            insertion_method: InsertionMethod::ManualTerminalWorkflow,
            state: InsertionState::Failed,
            upstream_evidence: Nullable::null(),
            failure_detail: Nullable::from(failure.map(str::to_owned)),
            read_grant: Nullable::some(AttachmentReadGrant {
                grant_id: GrantId::new(Uuid::from_bytes([8; 16])),
                environment_id,
                transfer_id,
                insertion_method: InsertionMethod::ManualTerminalWorkflow,
                host_path: "/Users/marguerite/.local/state/kr/staging/notes.txt".to_owned(),
                expires_at_ms: TimestampMs::new(2),
            }),
            external_destination: Nullable::null(),
        }
    }

    #[test]
    fn why_an_attachment_was_not_offered_is_not_told_to_a_device_in_the_upstreams_words() {
        // The worker writes the upstream's own refusal there, or a quotation of it: a bare name
        // is not a path, a number or a command, so the rule for an error's message does not find it.
        let owner = draft_attachment(Some(
            "the upstream refused: marguerite@example.com may not attach net user marguerite",
        ));
        let device = read_by_a_device(&owner);
        assert_eq!(
            device.failure_detail.0.as_deref(),
            Some("why the attachment was not offered; the detail is not sent to a paired device")
        );
        // The rest of the record is as it was. The staged file's path, which the person is shown
        // to use in a terminal on purpose, is among it.
        assert_eq!(
            kr_protocol::transfer::DraftAttachment {
                failure_detail: owner.failure_detail.clone(),
                ..device
            },
            owner
        );
        // An attachment that did not fail has no failure to withhold.
        let sound = draft_attachment(None);
        assert_eq!(read_by_a_device(&sound), sound);
    }

    /// The name of the desktop a session is bound to, as this host derives it: the login kind, the
    /// account's name and number, the platform session, the generation and the boot.
    const A_DESKTOP_NAME: &str =
        "macos_security_session:user=marguerite:uid=501:session=100019:generation=42:boot=5a17c309";

    fn bound_session() -> kr_protocol::session::SessionSummary {
        let mut summary = session_summary();
        summary.worker_profile = kr_protocol::identity::WorkerProfile::DesktopBound;
        summary.desktop = kr_protocol::identity::DesktopBinding {
            desktop_session_id: Nullable::some(
                kr_protocol::ids::DesktopSessionId::new(A_DESKTOP_NAME).expect("a desktop name"),
            ),
            login_generation: Nullable::some(U64::new(42)),
        };
        summary
    }

    #[test]
    fn the_desktop_a_session_is_bound_to_is_not_named_to_a_device() {
        let owner = bound_session();
        let read = kr_protocol::session::SessionReadResult {
            session: owner.clone(),
            endpoint: Nullable::null(),
            launch_profile: Nullable::null(),
            last_command_block: Nullable::null(),
            outstanding_launches: Nullable::null(),
            metrics: None,
        };
        let created = kr_protocol::session::SessionCreateResult {
            session: owner.clone(),
            endpoint: Nullable::null(),
            deduplicated: false,
            presentation_error: Nullable::null(),
        };
        let listed = kr_protocol::session::SessionListResult {
            sessions: vec![owner.clone()],
        };
        for device in [
            read_by_a_device(&read).session,
            read_by_a_device(&created).session,
            read_by_a_device(&listed).sessions.remove(0),
        ] {
            // The session is still bound to a desktop, which is not a secret; what the desktop is
            // called is.
            let told = device
                .desktop
                .desktop_session_id
                .0
                .as_ref()
                .expect("the session is still bound to a desktop")
                .to_string();
            assert!(
                !["marguerite", "501", "100019", "5a17c309"]
                    .iter()
                    .any(|name| told.contains(name)),
                "{told}"
            );
            // The generation the binding was taken at is told as it is, and nothing else of the
            // session changes.
            assert_eq!(
                device.desktop.login_generation,
                owner.desktop.login_generation
            );
            assert_eq!(
                kr_protocol::session::SessionSummary {
                    desktop: owner.desktop.clone(),
                    ..device
                },
                owner
            );
        }
        // A session that is bound to none has none to withhold.
        let free = session_summary();
        assert_eq!(read_by_a_device(&free), free);
    }

    #[test]
    fn the_admission_cut_is_made_at_the_earliest_clause_in_the_text() {
        use kr_protocol::catalogue::{PluginAdmission, PluginLeftOutReason};
        let subject = "kalareach/claude-code at 9f2c41";
        let left_out = |reason, detail: &str| PluginAdmission::LeftOut {
            reason,
            detail: detail.to_owned(),
        };
        for (reason, said, kept) in [
            // A store's own words after the colon quote a clause that comes later in the table.
            (
                PluginLeftOutReason::Incomplete,
                format!(
                    "{subject} is not whole in this host's store: \
                     /Users/marguerite/.local/share/kr/plugins/9f2c41/manifest.json: unknown \
                     field ` was revoked by its repository`"
                ),
                format!("{subject} is not whole in this host's store"),
            ),
            // A state directory named with the words of a later clause.
            (
                PluginLeftOutReason::Incomplete,
                format!(
                    "{subject} is not whole in this host's store: /Users/marguerite/state was \
                     revoked by its repository/plugins/9f2c41/manifest.json does not parse"
                ),
                format!("{subject} is not whole in this host's store"),
            ),
            // A repository's statement that quotes a clause that comes earlier in the table.
            (
                PluginLeftOutReason::Revoked,
                format!(
                    "{subject} was revoked by its repository: marguerite wrote that it is not \
                     whole in this host's store"
                ),
                format!("{subject} was revoked by its repository"),
            ),
            (
                PluginLeftOutReason::PastALimit,
                format!(
                    "{subject} is past a package limit in force: marguerite's package cannot be \
                     handed to a worker"
                ),
                format!("{subject} is past a package limit in force"),
            ),
        ] {
            let told = read_by_a_device(&left_out(reason, &said));
            assert_eq!(told, left_out(reason, &kept), "{said}");
        }
    }

    #[test]
    fn a_media_type_with_parameters_is_refused_as_a_kind_of_attachment() {
        for said in [
            "the package does not accept text/plain; charset=utf-8 as an attachment",
            "the package does not accept text/plain; name=marguerite as an attachment",
            "the package does not accept text/plain;charset=\"utf 8\" as an attachment",
        ] {
            let told = told_on(Method::PluginActionInvoke, ErrorCode::InvalidArgument, said);
            assert_eq!(told.code, ErrorCode::InvalidArgument);
            assert!(
                told.message
                    .contains("does not accept this kind of attachment")
                    && !told.message.contains("charset")
                    && !told.message.contains("marguerite"),
                "{said}: {told:?}"
            );
        }
        // A message that names no type is not the reason.
        let told = told_on(
            Method::PluginActionInvoke,
            ErrorCode::InvalidArgument,
            "the package does not accept  as an attachment",
        );
        assert!(!told.message.contains("kind of attachment"), "{told:?}");
    }

    /// The owner is told the whole text because the owner's route never meets this module: only
    /// the door a paired device uses calls it.
    #[test]
    fn only_the_door_of_a_paired_device_calls_this_module() {
        fn sources(directory: &std::path::Path, found: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(directory).expect("a source directory") {
                let path = entry.expect("a directory entry").path();
                if path.is_dir() {
                    sources(&path, found);
                } else if path.extension().is_some_and(|extension| extension == "rs") {
                    found.push(path);
                }
            }
        }
        let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let door = source.join("net");
        let mut found = Vec::new();
        sources(&source, &mut found);
        assert!(found.len() > 100, "{} sources read", found.len());
        let outside: Vec<_> = found
            .iter()
            .filter(|path| !path.starts_with(&door))
            .filter(|path| {
                std::fs::read_to_string(path).is_ok_and(|text| text.contains("device_errors"))
            })
            .collect();
        assert!(
            outside.is_empty(),
            "the owner's route reaches the device rule: {outside:?}"
        );
    }

    /// A member's key, the text it holds, and the members that make the record it is in.
    type Record = (
        &'static str,
        &'static str,
        &'static [(&'static str, &'static str)],
    );

    /// A member is held by the record around it, and a record with one of its members missing, or
    /// with a member that names another record, is not that record.
    ///
    /// The members that make each record are written out here, and not read from the rules, so a
    /// rule that stops asking for one of them is a case that fails.
    #[test]
    fn a_member_is_held_only_beside_every_member_that_names_its_record() {
        let text = |text: &str| CanonicalValue::Text(text.to_owned());
        let place = "/Users/marguerite/work/x";
        // The key, what it holds, and the members that make the record it is in.
        let records: [Record; 15] = [
            ("reason", place, &[("subsystem", "privacy")]),
            ("reason", place, &[("state", "unavailable")]),
            (
                "detail",
                place,
                &[("kind", "workspace"), ("change_set_id", "c-1")],
            ),
            ("detail", place, &[("display_path", "/x")]),
            ("detail", place, &[("retained_staging_paths", "[]")]),
            ("refusal", place, &[("application_instance_id", "i-1")]),
            ("failure", place, &[("download", "failed")]),
            (
                "detail",
                place,
                &[("state", "left_out"), ("reason", "revoked")],
            ),
            (
                "failure_detail",
                place,
                &[("handle", "h-1"), ("insertion_method", "paste")],
            ),
            (
                "display_path",
                place,
                &[("project_repository_id", "p-1"), ("environment_id", "e-1")],
            ),
            (
                "retained_staging_paths",
                place,
                &[("action_id", "a-1"), ("destination_state", "kept")],
            ),
            (
                "removed_staging_paths",
                place,
                &[("action_id", "a-1"), ("destination_state", "kept")],
            ),
            (
                "url",
                place,
                &[("remote_name", "origin"), ("transport", "local_path")],
            ),
            ("endpoint", place, &[("session", "s-1")]),
            (
                "suspension_reason",
                A_CONVERSATION_LOCK_THAT_FAILED,
                &[
                    ("rich_mutations_suspended", "true"),
                    ("binding_revision", "3"),
                ],
            ),
        ];
        // The members that must hold one text, and no other, for the record to be that one.
        let only_as = [
            ("state", "unavailable"),
            ("state", "left_out"),
            ("transport", "local_path"),
            ("download", "failed"),
        ];
        let record = |key: &str, held: &str, members: &[(&str, &str)]| {
            let mut entries = vec![(key.to_owned(), text(held))];
            entries.extend(
                members
                    .iter()
                    .map(|(name, value)| ((*name).to_owned(), text(value))),
            );
            rebuilt(entries)
        };
        let mut wrong = Vec::new();
        for (key, held, members) in records {
            if shown_value(&record(key, held, members)).is_none() {
                wrong.push(format!("{key} is not held beside {members:?}"));
            }
            for left_out in 0..members.len() {
                let without: Vec<_> = members
                    .iter()
                    .copied()
                    .enumerate()
                    .filter_map(|(at, member)| (at != left_out).then_some(member))
                    .collect();
                if shown_value(&record(key, held, &without)).is_some() {
                    wrong.push(format!("{key} is held without {}", members[left_out].0));
                }
                let (name, value) = members[left_out];
                if only_as.contains(&(name, value)) {
                    let mut other = without;
                    other.push((name, "another text"));
                    if shown_value(&record(key, held, &other)).is_some() {
                        wrong.push(format!("{key} is held with {name} other than {value}"));
                    }
                }
            }
        }
        assert!(wrong.is_empty(), "{wrong:#?}");
    }
}

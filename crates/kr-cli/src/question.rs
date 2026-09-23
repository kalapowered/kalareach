//! `kr question`: reading and answering an agent's questions from the terminal.
//!
//! The companion app is the primary place to answer a question: it shows the verified application
//! identity, the context and the form, and it reaches every host a person is paired with. This is
//! the same surface for the machine the session is on, for when the app is not to hand.
//!
//! Two properties matter more than the shape of the output.
//!
//! * **The identity header is the host's.** Every listing leads with the executable the broker
//!   verified. The `agent_name` a caller supplied is shown beside it and labelled unverified,
//!   because a label is not an identity.
//! * **An answer names the revision it answers.** The revision the command read is the revision it
//!   submits, so an answer to a question that moved underneath it is refused rather than applied
//!   to something else.
//!
//! Questions belong to the session, so this reaches the session's worker directly, the way
//! attaching does. It therefore keeps working while the control daemon is restarting, and the
//! authority behind it is the operating-system owner the worker's socket authenticates.

use kr_ipc::client::LocalClient;
use kr_ipc::paths::HostPaths;
use kr_protocol::ids::{BuildId, QuestionId};
use kr_protocol::method::Method;
use kr_protocol::question::{
    Question, QuestionAnswer, QuestionAnswerParams, QuestionCancelParams, QuestionReadParams,
    QuestionReadResult, QuestionResolveResult, QuestionState, SOMETHING_ELSE_CHOICE,
};
use kr_protocol::scalars::Nullable;
use kr_protocol::worker::WorkerDescriptor;
use serde_json::{Value, json};

use crate::error::{CliError, Result};
use crate::resolve::{KnownEnvironment, SessionSelector, environments, find, open_worker};

/// Which sessions a listing covers.
#[derive(Clone, Debug)]
pub enum Scope {
    /// One named session.
    Session(SessionSelector),
    /// Every live session this host has.
    Everything,
}

/// Lists the questions waiting for a person.
///
/// # Errors
///
/// Returns an error when no host is running, or when a named session does not exist.
pub async fn list(
    paths: &HostPaths,
    scope: &Scope,
    include_resolved: bool,
    build_id: BuildId,
) -> Result<Vec<(WorkerDescriptor, Question)>> {
    let mut found = Vec::new();
    for descriptor in descriptors(paths, scope)? {
        let mut client = match open_worker(&descriptor, build_id.clone()).await {
            Ok(client) => client,
            // A worker that cannot be reached is reported by `kr list`, and a listing that stopped
            // at the first one would hide every question after it.
            Err(_) => continue,
        };
        let result: QuestionReadResult = read(
            &mut client,
            &QuestionReadParams {
                session_id: descriptor.session_id,
                question_id: Nullable::null(),
                include_resolved,
            },
        )
        .await?;
        for question in result.questions {
            found.push((descriptor.clone(), question));
        }
    }
    found.sort_by_key(|(_, question)| question.created_at_ms.get());
    Ok(found)
}

/// Reads one question in full.
///
/// # Errors
///
/// Returns an error when no session holds that question.
pub async fn show(
    paths: &HostPaths,
    question_id: QuestionId,
    build_id: BuildId,
) -> Result<(WorkerDescriptor, Question)> {
    locate(paths, question_id, build_id)
        .await
        .map(|(descriptor, question, _)| (descriptor, question))
}

/// Answers one question.
///
/// # Errors
///
/// Returns [`CliError::Refused`] when the question has already been resolved, has expired, or has
/// moved to a revision this command did not read.
pub async fn answer(
    paths: &HostPaths,
    question_id: QuestionId,
    answer: QuestionAnswer,
    build_id: BuildId,
) -> Result<Question> {
    let (descriptor, question, mut client) = locate(paths, question_id, build_id).await?;
    let result: QuestionResolveResult = mutate(
        &mut client,
        &descriptor,
        Method::QuestionAnswer,
        &QuestionAnswerParams {
            session_id: descriptor.session_id,
            question_id,
            // The revision this command read is the revision it answers. A question that moved
            // while the person was reading it is refused rather than answered as though it had not.
            expected_revision: question.revision,
            answer,
        },
    )
    .await?;
    Ok(result.question)
}

/// Cancels one question.
///
/// # Errors
///
/// As [`answer`].
pub async fn cancel(
    paths: &HostPaths,
    question_id: QuestionId,
    build_id: BuildId,
) -> Result<Question> {
    let (descriptor, question, mut client) = locate(paths, question_id, build_id).await?;
    let result: QuestionResolveResult = mutate(
        &mut client,
        &descriptor,
        Method::QuestionCancel,
        &QuestionCancelParams {
            session_id: descriptor.session_id,
            question_id,
            expected_revision: question.revision,
        },
    )
    .await?;
    Ok(result.question)
}

/// Renders one question for a script.
#[must_use]
pub fn rendered(descriptor: &WorkerDescriptor, question: &Question) -> Value {
    json!({
        "question_id": question.question_id.to_string(),
        "revision": question.revision.get(),
        "state": question.state.as_str(),
        "session_id": question.session_id.to_string(),
        "display_number": descriptor.display_number.get(),
        "type": question.kind.as_str(),
        "context": question.context,
        "question": question.question,
        "choices": question
            .choices
            .iter()
            .map(|choice| json!({"choice_id": choice.choice_id, "label": choice.label}))
            .collect::<Vec<_>>(),
        // The identity the broker verified, and the label the caller supplied, kept apart.
        "verified_source": {
            "executable": question.source.executable.as_ref().cloned(),
            "pid": question.source.process.pid.get(),
            "application_instance_id": question.source.application_instance_id.to_string(),
            "session_member": question.source.session_member,
            "ancestry": question.source.ancestry,
            "launch_channel": question.source.launch_channel,
        },
        "unverified_agent_label": question.source.agent_label.as_ref().cloned(),
        "created_at_ms": question.created_at_ms.get(),
        "expires_at_ms": question.expires_at_ms.get(),
        "answer": question.answer.as_ref().map(|record| json!({
            "kind": record.answer.kind(),
            "text": record.answer.text(),
            "choice_id": match &record.answer {
                QuestionAnswer::Choice { choice_id } => Some(choice_id.clone()),
                _ => None,
            },
            "decided": match &record.answer {
                QuestionAnswer::Decision { decided } => Some(*decided),
                _ => None,
            },
            "actor_id": record.actor_id.to_string(),
            "device_id": record.device_id.as_ref().map(ToString::to_string),
            "question_revision": record.question_revision.get(),
            "answered_at_ms": record.answered_at_ms.get(),
        })),
    })
}

/// Renders one question as a line for a person.
#[must_use]
pub fn line(descriptor: &WorkerDescriptor, question: &Question) -> String {
    format!(
        "{:<36} {:>4}  {:<9} {:<8} {}  [{}]",
        question.question_id.to_string(),
        descriptor.display_number.get(),
        question.state.as_str(),
        question.kind.as_str(),
        first_line(&question.question),
        verified_identity(question),
    )
}

/// Renders one question in full, for a person about to answer it.
#[must_use]
pub fn detail(descriptor: &WorkerDescriptor, question: &Question) -> String {
    let mut text = String::new();
    text.push_str(&format!("question  {}\n", question.question_id));
    text.push_str(&format!(
        "session   {} (display {})\n",
        question.session_id,
        descriptor.display_number.get()
    ));
    text.push_str(&format!(
        "asked by  {}  (verified)\n",
        verified_identity(question)
    ));
    if let Some(label) = question.source.agent_label.as_ref() {
        text.push_str(&format!(
            "label     {label}  (unverified, supplied by the caller)\n"
        ));
    }
    text.push_str(&format!(
        "state     {} at revision {}\n",
        question.state.as_str(),
        question.revision.get()
    ));
    text.push_str(&format!("expires   {}\n", question.expires_at_ms.get()));
    text.push('\n');
    if !question.context.trim().is_empty() {
        text.push_str(&format!("{}\n\n", question.context));
    }
    text.push_str(&format!("{}\n", question.question));
    if !question.choices.is_empty() {
        text.push('\n');
        for choice in &question.choices {
            let note = if choice.choice_id == SOMETHING_ELSE_CHOICE {
                "   (--other \"...\")"
            } else {
                ""
            };
            text.push_str(&format!(
                "  {:<20} {}{note}\n",
                choice.choice_id, choice.label
            ));
        }
    }
    if let Some(record) = question.answer.as_ref() {
        text.push('\n');
        text.push_str(&format!(
            "answered  {} by {}\n",
            match &record.answer {
                QuestionAnswer::Input { text } | QuestionAnswer::Other { text } => text.clone(),
                QuestionAnswer::Choice { choice_id } => choice_id.clone(),
                QuestionAnswer::Decision { decided } =>
                    if *decided {
                        "yes".to_owned()
                    } else {
                        "no".to_owned()
                    },
            },
            record.actor_id
        ));
    }
    text
}

/// Returns the verified application identity a person reads before answering.
fn verified_identity(question: &Question) -> String {
    question.source.executable.as_ref().map_or_else(
        || format!("process {}", question.source.process.pid.get()),
        |executable| format!("{executable} ({})", question.source.process.pid.get()),
    )
}

fn first_line(text: &str) -> String {
    let line = text.lines().next().unwrap_or_default();
    if line.chars().count() > 48 {
        let shortened: String = line.chars().take(47).collect();
        format!("{shortened}…")
    } else {
        line.to_owned()
    }
}

/// Finds the session holding one question, and the connection to it.
async fn locate(
    paths: &HostPaths,
    question_id: QuestionId,
    build_id: BuildId,
) -> Result<(WorkerDescriptor, Question, LocalClient)> {
    for descriptor in descriptors(paths, &Scope::Everything)? {
        let Ok(mut client) = open_worker(&descriptor, build_id.clone()).await else {
            continue;
        };
        let outcome: Result<QuestionReadResult> = read(
            &mut client,
            &QuestionReadParams {
                session_id: descriptor.session_id,
                question_id: Nullable::some(question_id),
                include_resolved: true,
            },
        )
        .await;
        if let Ok(result) = outcome
            && let Some(question) = result.questions.into_iter().next()
        {
            return Ok((descriptor, question, client));
        }
    }
    Err(CliError::Usage(format!(
        "no session on this host has question {question_id}"
    )))
}

fn descriptors(paths: &HostPaths, scope: &Scope) -> Result<Vec<WorkerDescriptor>> {
    match scope {
        Scope::Session(selector) => {
            let (_, descriptor) = find(paths, selector, None)?;
            Ok(vec![descriptor])
        }
        Scope::Everything => {
            let mut found = Vec::new();
            for known in environments(paths)? {
                collect(&known, &mut found);
            }
            found.sort_by_key(|descriptor| descriptor.display_number.get());
            Ok(found)
        }
    }
}

fn collect(known: &KnownEnvironment, found: &mut Vec<WorkerDescriptor>) {
    let Ok(entries) = kr_ipc::descriptor::read_all(&known.paths) else {
        return;
    };
    for entry in entries {
        if let Ok(descriptor) = entry.descriptor {
            found.push(descriptor);
        }
    }
}

async fn read<T: kr_protocol::wire::WireMessage>(
    client: &mut LocalClient,
    params: &QuestionReadParams,
) -> Result<T> {
    let outcome = client.request(Method::QuestionRead, params).await?;
    outcome
        .map_err(CliError::Refused)?
        .to_typed()
        .map_err(|error| CliError::Other(format!("the host's answer could not be read: {error}")))
}

async fn mutate<P, T>(
    client: &mut LocalClient,
    descriptor: &WorkerDescriptor,
    method: Method,
    params: &P,
) -> Result<T>
where
    P: serde::Serialize + ?Sized,
    T: kr_protocol::wire::WireMessage,
{
    let action_id = kr_protocol::ids::ActionId::new(kr_ipc::new_uuid());
    let outcome = client
        .mutate(method, action_id, crate::attach::target(descriptor), params)
        .await?;
    outcome
        .map_err(CliError::Refused)?
        .to_typed()
        .map_err(|error| CliError::Other(format!("the host's answer could not be read: {error}")))
}

/// Returns whether a question is still waiting for somebody.
#[must_use]
pub const fn is_pending(question: &Question) -> bool {
    matches!(question.state, QuestionState::Pending)
}

#[cfg(test)]
mod tests {
    use kr_protocol::identity::{ProcessStartIdentity, ProcessStartSource};
    use kr_protocol::ids::{
        ApplicationInstanceId, ConnectionId, QuestionRevision, SessionEpoch, SessionId,
    };
    use kr_protocol::question::{QuestionKind, QuestionSource};
    use kr_protocol::scalars::{TimestampMs, Uuid};

    use super::*;

    fn descriptor() -> WorkerDescriptor {
        WorkerDescriptor {
            session_id: SessionId::new(Uuid::from_bytes([1; 16])),
            session_epoch: SessionEpoch::V1,
            environment_id: kr_protocol::ids::EnvironmentId::new(Uuid::from_bytes([2; 16])),
            display_number: kr_protocol::session::DisplayNumber::new(3),
            boot_identity: kr_protocol::identity::BootIdentity {
                source: kr_protocol::identity::BootIdentitySource::LinuxBootId,
                value: kr_protocol::scalars::Bytes::new(b"boot".to_vec()),
            },
            process_start_identity: ProcessStartIdentity::new(
                9,
                ProcessStartSource::LinuxProcStat,
                1,
            ),
            endpoint: "/tmp/socket".to_owned(),
            worker_public_key: kr_protocol::scalars::AuthorisationKey::from_bytes([0; 32]),
            worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
            protocol_version: kr_protocol::hello::PROTOCOL_VERSION,
            published_at_ms: TimestampMs::new(1),
        }
    }

    fn question(state: QuestionState) -> Question {
        Question {
            question_id: QuestionId::new(Uuid::from_bytes([4; 16])),
            revision: QuestionRevision::new(1),
            state,
            session_id: SessionId::new(Uuid::from_bytes([1; 16])),
            session_epoch: SessionEpoch::V1,
            kind: QuestionKind::Select,
            context: "two ways".to_owned(),
            question: "which one?".to_owned(),
            choices: vec![
                kr_protocol::question::QuestionChoice {
                    choice_id: "left".to_owned(),
                    label: "Left".to_owned(),
                },
                kr_protocol::question::QuestionChoice::something_else(),
            ],
            source: QuestionSource {
                application_instance_id: ApplicationInstanceId::new(Uuid::from_bytes([5; 16])),
                process: ProcessStartIdentity::new(42, ProcessStartSource::LinuxProcStat, 7),
                executable: Nullable::some("/usr/bin/some-agent".to_owned()),
                agent_label: Nullable::some("Totally The Host".to_owned()),
                connection_id: ConnectionId::new(Uuid::from_bytes([6; 16])),
                launch_channel: false,
                session_member: true,
                ancestry: true,
                agent_binding_revision: Nullable::null(),
            },
            created_at_ms: TimestampMs::new(10),
            expires_at_ms: TimestampMs::new(20),
            answer: Nullable::null(),
            resolved_at_ms: Nullable::null(),
        }
    }

    #[test]
    fn the_verified_identity_leads_and_the_caller_label_is_marked_unverified() {
        let question = question(QuestionState::Pending);
        let text = detail(&descriptor(), &question);
        assert!(text.contains("/usr/bin/some-agent (42)  (verified)"));
        assert!(text.contains("Totally The Host  (unverified, supplied by the caller)"));
        let value = rendered(&descriptor(), &question);
        assert_eq!(
            value["verified_source"]["executable"],
            "/usr/bin/some-agent"
        );
        assert_eq!(value["unverified_agent_label"], "Totally The Host");
    }

    #[test]
    fn the_free_text_option_is_shown_with_the_flag_that_answers_it() {
        let text = detail(&descriptor(), &question(QuestionState::Pending));
        assert!(text.contains("something_else"));
        assert!(text.contains("--other"));
    }

    #[test]
    fn a_listing_line_carries_the_state_and_the_verified_identity() {
        let text = line(&descriptor(), &question(QuestionState::Pending));
        assert!(text.contains("pending"));
        assert!(text.contains("/usr/bin/some-agent"));
    }
}

//! Narrowing an answer to what the device's grant admits.

use kr_protocol::changeset::{
    ChangesetMaterializeParams, ChangesetMaterializeResult, DiffReadParams,
};
use kr_protocol::envelope::{
    ControlFrame, MutationRequest, Outcome, ParamsValue, Request, Response,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ActorId, RequestId};
use kr_protocol::method::Method;
use kr_protocol::session::SessionListResult;

use super::acting::Acting;
use super::{RemoteConnection, failure};
use crate::changeset::{OutOfScope, ScopedEnvironments, VersionScope};

impl RemoteConnection {
    /// Narrows an answer to what this device's grant admits.
    ///
    /// Two things need it. A listing names no session, so the selector has nothing to check and
    /// the narrowing has to happen to the answer: the registry's own words for this method are
    /// "the sessions this actor may observe". And a session read carries the last command block,
    /// which is session content rather than metadata: a command line and the directory it ran in.
    /// The grant's history lower bound decides whether this device sees it.
    pub(super) fn narrow(&self, answer: ControlFrame, acting: &Acting) -> ControlFrame {
        let ControlFrame::Response(Response {
            request_id,
            outcome: Outcome::Ok(value),
        }) = answer
        else {
            return answer;
        };
        if let Ok(listed) = value.to_typed::<SessionListResult>() {
            let selector = &self.device.grant.session_selector;
            let narrowed = SessionListResult {
                sessions: listed
                    .sessions
                    .into_iter()
                    .filter(|summary| selector.admits(summary.session_id))
                    .collect(),
            };
            return match ParamsValue::from_typed(&narrowed) {
                Ok(value) => ControlFrame::Response(Response {
                    request_id,
                    outcome: Outcome::Ok(value),
                }),
                Err(error) => failure(
                    request_id,
                    ProtocolError::new(ErrorCode::InvalidArgument, error.to_string()),
                ),
            };
        }
        if let Ok(listed) = value.to_typed::<kr_protocol::project::ProjectListResult>() {
            let selector = &self.device.grant.environment_selector;
            let narrowed = kr_protocol::project::ProjectListResult {
                projects: listed
                    .projects
                    .into_iter()
                    .filter(|summary| selector.admits(summary.environment_id))
                    .collect(),
            };
            return match ParamsValue::from_typed(&narrowed) {
                Ok(value) => ControlFrame::Response(Response {
                    request_id,
                    outcome: Outcome::Ok(value),
                }),
                Err(error) => failure(
                    request_id,
                    ProtocolError::new(ErrorCode::InvalidArgument, error.to_string()),
                ),
            };
        }
        if let Ok(listed) = value.to_typed::<kr_protocol::project::WorkspaceListResult>() {
            let env_selector = &self.device.grant.environment_selector;
            let session_selector = &self.device.grant.session_selector;
            let narrowed = kr_protocol::project::WorkspaceListResult {
                workspaces: listed
                    .workspaces
                    .into_iter()
                    .filter(|summary| env_selector.admits(summary.environment_id))
                    .map(|mut summary| {
                        summary
                            .bound_sessions
                            .retain(|s| session_selector.admits(*s));
                        summary
                    })
                    .collect(),
            };
            return match ParamsValue::from_typed(&narrowed) {
                Ok(value) => ControlFrame::Response(Response {
                    request_id,
                    outcome: Outcome::Ok(value),
                }),
                Err(error) => failure(
                    request_id,
                    ProtocolError::new(ErrorCode::InvalidArgument, error.to_string()),
                ),
            };
        }
        if let Ok(read) = value.to_typed::<kr_protocol::project::WorkspaceReadResult>() {
            let env_selector = &self.device.grant.environment_selector;
            if !env_selector.admits(read.workspace.environment_id) {
                return failure(request_id, outside_the_grant("working copy"));
            }
            let session_selector = &self.device.grant.session_selector;
            let mut workspace = read.workspace;
            workspace
                .bound_sessions
                .retain(|session| session_selector.admits(*session));
            return encoded(
                request_id,
                &kr_protocol::project::WorkspaceReadResult { workspace },
            );
        }
        if let Ok(read) = value.to_typed::<kr_protocol::project::ProjectReadResult>() {
            let env_selector = &self.device.grant.environment_selector;
            if !env_selector.admits(read.project.environment_id) {
                return failure(request_id, outside_the_grant("repository"));
            }
            let session_selector = &self.device.grant.session_selector;
            let narrowed = kr_protocol::project::ProjectReadResult {
                workspaces: read
                    .workspaces
                    .into_iter()
                    .filter(|summary| env_selector.admits(summary.environment_id))
                    .map(|mut summary| {
                        summary
                            .bound_sessions
                            .retain(|session| session_selector.admits(*session));
                        summary
                    })
                    .collect(),
                ..read
            };
            return encoded(request_id, &narrowed);
        }
        if let Ok(read) = value.to_typed::<kr_protocol::changeset::ChangesetReadResult>() {
            // Retained content, and the grant says how far back it reaches. A grant with no lower
            // bound retains none of it, which is the reading every other retained answer on this
            // path takes.
            let Some(bound) = self.device.grant.history.lower_bound_ms.0 else {
                return failure(
                    request_id,
                    ProtocolError::new(
                        ErrorCode::PermissionDenied,
                        "this device's grant retains no history, so it does not read a recorded \
                         change-set version",
                    ),
                );
            };
            if read.version.captured_at_ms.get() < bound.get() {
                return failure(
                    request_id,
                    ProtocolError::new(
                        ErrorCode::PermissionDenied,
                        "this version was captured before the moment this device's grant reaches \
                         back to",
                    ),
                );
            }
            let narrowed = kr_protocol::changeset::ChangesetReadResult {
                versions: read
                    .versions
                    .into_iter()
                    .filter(|summary| summary.captured_at_ms.get() >= bound.get())
                    .collect(),
                // Where a materialisation is on this host is for a person here, and no answer to a
                // device names it.
                materialisations: read
                    .materialisations
                    .into_iter()
                    .map(crate::changeset::shown_to_a_device)
                    .collect(),
                ..read
            };
            return encoded(request_id, &narrowed);
        }
        self.narrow_read(request_id, value, acting)
    }

    /// Removes from a session read the content this device's grant does not reach.
    ///
    /// The command block the private hooks reported is a command line and a working directory,
    /// which is what the person typed and where it ran. A grant whose history lower bound is after
    /// the command started, or which retains no history at all, does not see it; the rest of the
    /// read is metadata and passes through. Anything that is not a session read passes through
    /// too: it named its session and was already checked against the selector.
    fn narrow_read(
        &self,
        request_id: RequestId,
        value: ParamsValue,
        acting: &Acting,
    ) -> ControlFrame {
        let passed = |value| {
            ControlFrame::Response(Response {
                request_id,
                outcome: Outcome::Ok(value),
            })
        };
        let Ok(read) = value.to_typed::<kr_protocol::session::SessionReadResult>() else {
            return passed(value);
        };
        let bound = acting.grant.history.lower_bound_ms.0;
        let admitted = read.last_command_block.as_ref().is_some_and(|block| {
            bound.is_some_and(|bound| block.started_at_ms.get() >= bound.get())
        });
        if admitted {
            return passed(value);
        }
        let narrowed = kr_protocol::session::SessionReadResult {
            last_command_block: kr_protocol::scalars::Nullable::null(),
            ..read
        };
        match ParamsValue::from_typed(&narrowed) {
            Ok(value) => passed(value),
            Err(error) => failure(
                request_id,
                ProtocolError::new(ErrorCode::InvalidArgument, error.to_string()),
            ),
        }
    }

    /// Checks that the recorded version a device names is one its grant reaches.
    ///
    /// The version has to be in an environment the grant selects, for a session the grant selects
    /// (a grant that names sessions reaches only a version that records one of them), and captured
    /// at or after the moment the grant's history reaches back to. A grant with no lower bound
    /// retains none of it. A version this host cannot read is refused the way one outside the
    /// grant is, so a device learns nothing about which identifiers exist.
    ///
    /// Returns the number of the version it checked, which is the latest one when none was named:
    /// what is then read has to be that version, and not the one that is latest by then.
    ///
    /// # Errors
    ///
    /// Returns the refusal when the grant does not reach the version.
    pub(super) async fn check_version(
        &self,
        change_set_id: kr_protocol::ids::ChangeSetId,
        version: Option<kr_protocol::ids::ChangeSetVersion>,
    ) -> Result<kr_protocol::ids::ChangeSetVersion, ProtocolError> {
        let Some(bound) = self.device.grant.history.lower_bound_ms.0 else {
            return Err(ProtocolError::new(
                ErrorCode::PermissionDenied,
                "this device's grant retains no history, so it does not read a recorded \
                 change-set version",
            ));
        };
        let scope = VersionScope {
            environments: ScopedEnvironments::Selected(
                self.device.grant.environment_selector.clone(),
            ),
            workspace: None,
            sessions: Some(self.device.grant.session_selector.clone()),
            captured_since: Some(bound),
        };
        let service = std::sync::Arc::clone(self.controller.changesets().service());
        let checked = tokio::task::spawn_blocking(move || {
            crate::changeset::version_in_scope(&service, change_set_id, version, &scope)
        })
        .await;
        match checked {
            Ok(Ok(record)) => Ok(record.version),
            Ok(Err(OutOfScope::History)) => Err(ProtocolError::new(
                ErrorCode::PermissionDenied,
                "this version was captured before the moment this device's grant reaches back to",
            )),
            Ok(Err(_)) => Err(ProtocolError::new(
                ErrorCode::PermissionDenied,
                format!("this device's grant does not reach change set {change_set_id}"),
            )),
            Err(_) => Err(ProtocolError::new(
                ErrorCode::OutcomeUnknown,
                "this host could not check the version against this device's grant",
            )),
        }
    }

    /// Checks a device's `changeset.read` and returns the request that reads exactly the version
    /// that was checked.
    ///
    /// # Errors
    ///
    /// Returns the refusal when the parameters are not a change-set read's or the grant does not
    /// reach the version.
    pub(super) async fn pinned_change_set_read(
        &self,
        request: &Request,
    ) -> Result<Request, ProtocolError> {
        let params: kr_protocol::changeset::ChangesetReadParams =
            request.params.to_typed().map_err(|error| {
                ProtocolError::new(
                    ErrorCode::InvalidArgument,
                    kr_project::git::redact(&error.to_string()),
                )
            })?;
        let checked = self
            .check_version(params.change_set_id, params.version.0)
            .await?;
        let pinned = kr_protocol::changeset::ChangesetReadParams {
            version: kr_protocol::scalars::Nullable::some(checked),
            ..params
        };
        Ok(Request {
            params: ParamsValue::from_typed(&pinned).map_err(|error| {
                ProtocolError::new(ErrorCode::InvalidArgument, error.to_string())
            })?,
            ..request.clone()
        })
    }

    /// Answers a device's `diff.read` of a recorded version.
    ///
    /// It reads the version's captured manifest from this host's own store and runs no Git, so it
    /// is served where the version is inside the grant ([`Self::check_version`]).
    pub(super) async fn recorded_diff(
        &self,
        request: &Request,
        params: &DiffReadParams,
    ) -> ControlFrame {
        let version = match crate::changeset::version_of(params) {
            Ok(Some(version)) => version,
            Ok(None) => {
                return failure(
                    request.request_id,
                    ProtocolError::new(
                        ErrorCode::InvalidArgument,
                        "a diff read of a change set names the exact version it reads",
                    ),
                );
            }
            Err(error) => return failure(request.request_id, error),
        };
        if let Err(error) = self
            .check_version(version.change_set_id, Some(version.version))
            .await
        {
            return failure(request.request_id, error);
        }
        without_host_text(self.controller.changesets().read_frame(request).await)
    }

    /// Checks the version a device asks to have materialised.
    ///
    /// # Errors
    ///
    /// Returns the refusal when the parameters are not a materialisation's or the grant does not
    /// reach the version.
    pub(super) async fn check_materialisation(
        &self,
        mutation: &MutationRequest,
    ) -> Result<(), ProtocolError> {
        let params: ChangesetMaterializeParams = mutation.params.to_typed().map_err(|error| {
            ProtocolError::new(
                ErrorCode::InvalidArgument,
                kr_project::git::redact(&error.to_string()),
            )
        })?;
        self.check_version(params.change_set_id, Some(params.version))
            .await
            .map(|_| ())
    }

    /// Answers a repeat of a materialisation this device asked for, from the record the first
    /// attempt left, when there is one.
    ///
    /// The answer is given under what the grant reaches now, and in the form a device is shown.
    ///
    /// # Errors
    ///
    /// Returns the refusal when the grant no longer reaches the version.
    pub(super) async fn retained_materialisation(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
    ) -> Result<Option<ControlFrame>, ProtocolError> {
        let Some(retained) = self
            .controller
            .changesets()
            .retained(actor_id, mutation, Method::ChangesetMaterialize)
            .await
        else {
            return Ok(None);
        };
        self.check_materialisation(mutation).await?;
        Ok(Some(shown_materialisation(retained)))
    }
}

/// Puts a refusal that came out of the change-set service in the form a device is shown.
///
/// Such a refusal carries a store's or a filesystem's own words, which can name the directory a
/// materialisation is in. The code travels, and so does a refusal the daemon decided itself
/// (`PERMISSION_DENIED`: the authority was withdrawn, the version is outside the grant); the text
/// of every other one is replaced by its class and length.
pub(super) fn without_host_text(answer: ControlFrame) -> ControlFrame {
    match answer {
        ControlFrame::Response(Response {
            request_id,
            outcome: Outcome::Error(error),
        }) if error.code != ErrorCode::PermissionDenied => failure(
            request_id,
            ProtocolError::new(
                error.code,
                kr_protocol::hostinfo::export::withheld(
                    kr_protocol::hostinfo::export::ContentClass::Message,
                    &error.message,
                ),
            ),
        ),
        other => other,
    }
}

/// Puts the answer to a materialisation in the form a device is shown: no host path.
pub(super) fn shown_materialisation(answer: ControlFrame) -> ControlFrame {
    let ControlFrame::Response(Response {
        request_id,
        outcome: Outcome::Ok(value),
    }) = answer
    else {
        return without_host_text(answer);
    };
    match value.to_typed::<ChangesetMaterializeResult>() {
        Ok(result) => encoded(
            request_id,
            &ChangesetMaterializeResult {
                materialisation: crate::changeset::shown_to_a_device(result.materialisation),
                ..result
            },
        ),
        // An answer that is not a materialisation's is not passed on as it is: it may carry what
        // this form exists to leave out.
        Err(_) => failure(
            request_id,
            ProtocolError::new(
                ErrorCode::OutcomeUnknown,
                "this host performed the action and could not state its answer to a paired device",
            ),
        ),
    }
}

/// Refuses a read of a subject in an environment this device's grant does not reach.
fn outside_the_grant(subject: &str) -> ProtocolError {
    ProtocolError::new(
        ErrorCode::PermissionDenied,
        format!(
            "this device's grant does not cover this environment, so it does not read that {subject}"
        ),
    )
}

/// Answers with one narrowed result, or with the refusal encoding it produced.
fn encoded<T: serde::Serialize + serde::de::DeserializeOwned>(
    request_id: RequestId,
    value: &T,
) -> ControlFrame {
    match ParamsValue::from_typed(value) {
        Ok(value) => ControlFrame::Response(Response {
            request_id,
            outcome: Outcome::Ok(value),
        }),
        Err(error) => failure(
            request_id,
            ProtocolError::new(ErrorCode::InvalidArgument, error.to_string()),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused(code: ErrorCode, message: &str) -> ControlFrame {
        failure(RequestId::new(7), ProtocolError::new(code, message))
    }

    fn said(frame: &ControlFrame) -> (ErrorCode, String) {
        match frame {
            ControlFrame::Response(Response {
                outcome: Outcome::Error(error),
                ..
            }) => (error.code, error.message.clone()),
            other => panic!("a refusal was expected: {other:?}"),
        }
    }

    /// A refusal that carries a store's own words reaches a device without them, and one the
    /// daemon decided reaches it as it was.
    #[test]
    fn the_text_of_a_refusal_from_the_change_set_service_is_not_shown_to_a_device() {
        let path = "/home/owner/.local/state/kr/changesets/materialisations/0123";
        let from_the_store = refused(
            ErrorCode::StorageUnavailable,
            &format!("could not flush the directory {path}"),
        );
        let (code, message) = said(&shown_materialisation(from_the_store));
        assert_eq!(code, ErrorCode::StorageUnavailable, "the code travels");
        assert!(
            message.starts_with("[message withheld, ") && !message.contains(path),
            "{message}"
        );
        // The control: the daemon's own refusal is not the store's words.
        let withdrawn = refused(
            ErrorCode::PermissionDenied,
            "the authority this connection was admitted under has been withdrawn",
        );
        let (code, message) = said(&shown_materialisation(withdrawn));
        assert_eq!(code, ErrorCode::PermissionDenied);
        assert!(message.contains("withdrawn"), "{message}");
        // And an answer that is not a materialisation's is refused rather than passed on.
        let other = encoded(
            RequestId::new(8),
            &kr_protocol::scalars::Nullable::<u8>::null(),
        );
        let (code, _) = said(&shown_materialisation(other));
        assert_eq!(code, ErrorCode::OutcomeUnknown);
    }
}

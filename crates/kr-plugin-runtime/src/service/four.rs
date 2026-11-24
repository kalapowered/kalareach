//! The fourth plugin host protocol, seen from the host's handlers.
//!
//! The handlers in [`super::host`] answer the requests of `kr-plugin-host/3`. A connection of
//! `kr-plugin-host/4` is read into the same requests, with what only `/4` says kept beside them
//! ([`Extra`]), and the answer the handlers give is written as a `/4` frame with what only `/4`
//! says put back ([`Added`]). Nothing here is read from or written to a `/3` connection.
//!
//! What a host writes beyond `/3` depends on its writer's gate
//! (`kr_protocol::retained::replay_writer_open`). A host with the gate closed reads every member of
//! a request and writes none of the members `/3` has no word for.

use kr_plugin_service::notices::{Beyond, ConsumedReport};
use kr_plugin_service::protocol::{
    CallValue, HostProtocol, Notice, Request, RequestBody, ResponseBody,
};
use kr_plugin_service::protocol4::{
    CallValue4, Checkpointed, Consumed, HostDescriptor4, Notice4, RecordState, Request4,
    RequestBody4, ResponseBody4, Through,
};
use kr_protocol::ids::BuildId;
use kr_protocol::local::LocalBuild;

/// The protocol a connection speaks, which is what the endpoint it arrived on speaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Dialect {
    /// `kr-plugin-host/3`.
    Three,
    /// `kr-plugin-host/4`.
    Four,
}

impl Dialect {
    /// Returns the dialect a protocol is spoken in, or nothing for a protocol this host has no
    /// frames for.
    pub(super) fn of(protocol: HostProtocol) -> Option<Self> {
        if protocol == HostProtocol::V3 {
            Some(Self::Three)
        } else if protocol == HostProtocol::V4 {
            Some(Self::Four)
        } else {
            None
        }
    }
}

/// Returns the build of this program, as its `/4` hello states it: `kr-plugin-host` and the release
/// it runs, which is the release it was installed as when it runs from a release store.
///
/// Never an error: the name is fixed and a release was checked when it was read.
pub(super) fn own_build() -> LocalBuild {
    let release = kr_ipc::install::this_process().map_or(env!("CARGO_PKG_VERSION"), |running| {
        running.stated_release(env!("CARGO_PKG_VERSION"))
    });
    LocalBuild::this(
        BuildId::new(format!("kr-plugin-host/{release}"))
            .expect("a fixed name and a release are a well-formed build identifier"),
    )
}

/// What a request of `/4` says that the request the handlers read does not.
#[derive(Clone, Debug, Default)]
pub(super) struct Extra {
    /// The number the worker gave this registration, for a request to register and for a restore.
    pub registration: Option<u64>,
    /// The events a restored state covers.
    pub through: Option<Through>,
}

/// A request, in the form the handlers read.
pub(super) struct Incoming {
    /// The number the answer echoes.
    pub request_id: u64,
    /// What is asked.
    pub body: RequestBody,
    /// What `/4` says of it beyond that.
    pub extra: Extra,
}

impl Incoming {
    /// Reads a request of `/3`.
    pub(super) fn three(request: Request) -> Self {
        Self {
            request_id: request.request_id,
            body: request.body,
            extra: Extra::default(),
        }
    }

    /// Reads a request of `/4`.
    pub(super) fn four(request: Request4) -> Self {
        let Request4 { request_id, body } = request;
        let mut extra = Extra::default();
        let body = match body {
            RequestBody4::Hello { protocol } => RequestBody::Hello { protocol },
            RequestBody4::Verify { nonce } => RequestBody::Verify { nonce },
            RequestBody4::RegisterBinding(registration) => {
                extra.registration = Some(registration.registration);
                RequestBody::RegisterBinding(Box::new(registration.binding))
            }
            RequestBody4::Event { binding_id, event } => RequestBody::Event { binding_id, event },
            RequestBody4::Snapshot {
                binding_id,
                deadline_ms,
            } => RequestBody::Snapshot {
                binding_id,
                deadline_ms,
            },
            RequestBody4::PrepareAction(call) => RequestBody::PrepareAction(call),
            RequestBody4::Checkpoint {
                binding_id,
                deadline_ms,
            } => RequestBody::Checkpoint {
                binding_id,
                deadline_ms,
            },
            RequestBody4::Restore {
                binding_id,
                registration,
                state,
                through,
                deadline_ms,
            } => {
                extra.registration = Some(registration);
                extra.through = through;
                RequestBody::Restore {
                    binding_id,
                    state,
                    deadline_ms,
                }
            }
            RequestBody4::Unbind { binding_id } => RequestBody::Unbind { binding_id },
            RequestBody4::Health => RequestBody::Health,
            RequestBody4::Decode(call) => RequestBody::Decode(call),
            RequestBody4::Encode(call) => RequestBody::Encode(call),
            RequestBody4::ReviseFacts { binding_id, facts } => {
                RequestBody::ReviseFacts { binding_id, facts }
            }
            RequestBody4::ReviseAttachments {
                binding_id,
                attachments,
            } => RequestBody::ReviseAttachments {
                binding_id,
                attachments,
            },
            RequestBody4::Privacy { private } => RequestBody::Privacy { private },
        };
        Self {
            request_id,
            body,
            extra,
        }
    }
}

/// What an answer says on `/4` that the answer the handlers give does not.
#[derive(Debug, Default)]
pub(super) struct Added {
    /// For the answer to a registration: the number the worker gave it.
    pub registration: Option<u64>,
    /// For the answer to an observation: the room the queue has left.
    pub free_bytes: Option<u64>,
    /// For the answer to a checkpoint: what the instance has consumed, where the writer is open.
    pub consumed: Option<Consumed>,
    /// For the answer to a restore: whether the host set its record.
    pub record: Option<RecordState>,
}

/// An answer, before it is written.
pub(super) enum Answered {
    /// An answer both protocols give, with what `/4` says beside it.
    Shared(ResponseBody, Added),
    /// The answer to a `/4` hello, which `/3` has no form for.
    Hello4(Box<HostDescriptor4>),
}

impl From<ResponseBody> for Answered {
    fn from(body: ResponseBody) -> Self {
        Self::Shared(body, Added::default())
    }
}

impl Answered {
    /// Returns the answer with the presentation of a decoded request left out, which is what a
    /// connection that withholds documents gives.
    pub(super) fn without_presentation(self) -> Self {
        match self {
            Self::Shared(body, added) => {
                Self::Shared(super::host::without_presentation(body), added)
            }
            hello @ Self::Hello4(_) => hello,
        }
    }

    /// Returns the answer as a `/4` response.
    pub(super) fn into_four(self, protocol: &str) -> ResponseBody4 {
        match self {
            Self::Shared(body, added) => response4_of(body, added),
            Self::Hello4(descriptor) => ResponseBody4::Hello {
                protocol: protocol.to_owned(),
                descriptor,
            },
        }
    }
}

/// Returns the `/4` form of an answer of the handlers.
fn response4_of(body: ResponseBody, added: Added) -> ResponseBody4 {
    let Added {
        registration,
        free_bytes,
        consumed,
        record,
    } = added;
    match body {
        // The handlers answer a hello with the `/3` descriptor only on a `/3` connection.
        ResponseBody::Hello { protocol, .. } => ResponseBody4::Refused {
            request: "hello".to_owned(),
            detail: format!("this connection does not speak {protocol}"),
            disabled: false,
        },
        ResponseBody::Verified(proof) => ResponseBody4::Verified(proof),
        ResponseBody::Registered { origin, elapsed_ms } => ResponseBody4::Registered {
            registration: registration.unwrap_or_default(),
            origin,
            elapsed_ms,
        },
        ResponseBody::Admitted {
            admission,
            lost_events,
            lost_bytes,
        } => ResponseBody4::Admitted {
            admission,
            lost_events,
            lost_bytes,
            free_bytes: free_bytes.unwrap_or_default(),
        },
        ResponseBody::Called {
            value,
            fault,
            document,
        } => ResponseBody4::Called {
            value: value.map(|value| call_value4_of(value, consumed)),
            fault,
            document,
            record,
        },
        ResponseBody::Unbound { existed } => ResponseBody4::Unbound { existed },
        ResponseBody::Revised => ResponseBody4::Revised,
        ResponseBody::PrivacySet { private } => ResponseBody4::PrivacySet { private },
        ResponseBody::Health(health) => ResponseBody4::Health(health),
        ResponseBody::Refused {
            request,
            detail,
            disabled,
        } => ResponseBody4::Refused {
            request,
            detail,
            disabled,
        },
    }
}

fn call_value4_of(value: CallValue, consumed: Option<Consumed>) -> CallValue4 {
    match value {
        CallValue::Document => CallValue4::Document,
        CallValue::Plan(plan) => CallValue4::Plan(plan),
        CallValue::State(state) => {
            CallValue4::Checkpointed(Box::new(Checkpointed { state, consumed }))
        }
        CallValue::Decoded(decoded) => CallValue4::Decoded(decoded),
        CallValue::Encoded(encoded) => CallValue4::Encoded(encoded),
    }
}

/// Returns the `/4` form of a notice the queue delivered.
///
/// `registration` is the number the worker gave the registration the notice is about.
pub(super) fn notice4_of(notice: Notice, beyond: Beyond, registration: u64) -> Notice4 {
    match notice {
        Notice::Document {
            binding_id,
            call,
            document,
            last,
            nodes,
        } => Notice4::Document {
            binding_id,
            registration,
            call,
            document,
            last,
            nodes,
        },
        Notice::Gap {
            binding_id,
            events,
            bytes,
            documents,
        } => Notice4::Gap {
            binding_id,
            registration,
            events,
            bytes,
            documents,
            first: beyond.first,
            last: beyond.last,
        },
        Notice::Fault {
            binding_id,
            call,
            detail,
            faults_in_window,
        } => Notice4::Fault {
            binding_id,
            registration,
            call,
            detail,
            faults_in_window,
            event: beyond.event,
            generation: beyond.generation,
        },
        Notice::Disabled { binding_id, reason } => Notice4::Disabled {
            binding_id,
            registration,
            reason,
        },
    }
}

/// Returns the `/4` notice that reports what an instance has consumed.
pub(super) fn consumed_notice4_of(report: ConsumedReport, registration: u64) -> Notice4 {
    let ConsumedReport {
        binding_id,
        generation,
        clean,
        native,
        terminal,
    } = report;
    Notice4::Consumed {
        binding_id,
        registration,
        generation,
        clean,
        native,
        terminal,
    }
}

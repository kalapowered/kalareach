//! What a client of `kr-plugin-host/4` writes and reads in the words the client already has.
//!
//! The client's own vocabulary is that of `/3`. Over a `/4` connection each request is turned into
//! its `/4` frame as it is written, and each frame into the `/3` frame it comes to as it is read,
//! so everything above the connection reads the same answers and notices whichever protocol the
//! host speaks. A `/4` member the client has no use for is read and dropped: the position a
//! checkpoint states, the report of what an instance consumed, the events a gap lost and the
//! generation of a fault. A notice or an answer that names an older registration of a binding than
//! the one the client gave it last is dropped too, since it belongs to an attempt the client gave
//! up.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use kr_protocol::scalars::Uuid;

use crate::protocol::{CallValue, Frame, Notice, Request, RequestBody, ResponseBody};
use crate::protocol4::{
    BindingRegistration4, CallValue4, Frame4, Notice4, Request4, RequestBody4, ResponseBody4,
};

/// The next registration number. One counter for the life of the process: a registration of a
/// binding never repeats an earlier one, whichever connection made it, so what a connection
/// leaves behind when it ends can never be taken for a later registration's.
static NEXT_REGISTRATION: AtomicU64 = AtomicU64::new(1);

/// The registration each binding of one connection runs under, as the client gave it.
#[derive(Debug, Default)]
pub(crate) struct Registrations(Mutex<HashMap<Uuid, u64>>);

impl Registrations {
    /// Gives a binding a registration number it never had.
    fn begin(&self, binding_id: Uuid) -> u64 {
        let registration = NEXT_REGISTRATION.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut held) = self.0.lock() {
            held.insert(binding_id, registration);
        }
        registration
    }

    /// The registration the binding runs under, where the client gave it one.
    fn of(&self, binding_id: Uuid) -> Option<u64> {
        self.0
            .lock()
            .ok()
            .and_then(|held| held.get(&binding_id).copied())
    }

    /// Whether what carries `registration` belongs to the binding's current registration.
    fn is_current(&self, binding_id: Uuid, registration: u64) -> bool {
        self.of(binding_id) == Some(registration)
    }
}

/// Turns a request into the frame of `/4`.
///
/// A registration is given its number here, as the request is written, so that what the host
/// writes about it can never arrive before the client knows the number. `minting` is false when
/// only the size of the frame is wanted.
pub(crate) fn request_of(
    request: Request,
    registrations: &Registrations,
    minting: bool,
) -> Request4 {
    let Request { request_id, body } = request;
    let body = match body {
        RequestBody::Hello { protocol } => RequestBody4::Hello { protocol },
        RequestBody::Verify { nonce } => RequestBody4::Verify { nonce },
        RequestBody::RegisterBinding(binding) => {
            let registration = if minting {
                registrations.begin(binding.binding_id)
            } else {
                u64::MAX
            };
            RequestBody4::RegisterBinding(Box::new(BindingRegistration4 {
                registration,
                binding: *binding,
            }))
        }
        RequestBody::Event { binding_id, event } => RequestBody4::Event { binding_id, event },
        RequestBody::Snapshot {
            binding_id,
            deadline_ms,
        } => RequestBody4::Snapshot {
            binding_id,
            deadline_ms,
        },
        RequestBody::PrepareAction(call) => RequestBody4::PrepareAction(call),
        RequestBody::Checkpoint {
            binding_id,
            deadline_ms,
        } => RequestBody4::Checkpoint {
            binding_id,
            deadline_ms,
        },
        // The client holds no position for a state it restores, so the host sets no record from it.
        RequestBody::Restore {
            binding_id,
            state,
            deadline_ms,
        } => RequestBody4::Restore {
            binding_id,
            registration: registrations.of(binding_id).unwrap_or(0),
            state,
            through: None,
            deadline_ms,
        },
        RequestBody::Unbind { binding_id } => RequestBody4::Unbind { binding_id },
        RequestBody::Health => RequestBody4::Health,
        RequestBody::Decode(call) => RequestBody4::Decode(call),
        RequestBody::Encode(call) => RequestBody4::Encode(call),
        RequestBody::ReviseFacts { binding_id, facts } => {
            RequestBody4::ReviseFacts { binding_id, facts }
        }
        RequestBody::ReviseAttachments {
            binding_id,
            attachments,
        } => RequestBody4::ReviseAttachments {
            binding_id,
            attachments,
        },
        RequestBody::Privacy { private } => RequestBody4::Privacy { private },
    };
    Request4 { request_id, body }
}

/// Turns a frame of `/4` into the frame of `/3` it comes to, or into nothing when it is a notice
/// the client has no use for or one of a registration it gave up.
pub(crate) fn frame_of(frame: Frame4, registrations: &Registrations) -> Option<Frame> {
    match frame {
        Frame4::Response { reply_to, body } => Some(Frame::Response {
            reply_to,
            body: response_of(body),
        }),
        Frame4::Notice(notice) => notice_of(notice, registrations).map(Frame::Notice),
    }
}

fn response_of(body: ResponseBody4) -> ResponseBody {
    match body {
        ResponseBody4::Hello {
            protocol,
            descriptor,
        } => ResponseBody::Hello {
            protocol,
            descriptor: Box::new(descriptor.proven_members()),
        },
        ResponseBody4::Verified(proof) => ResponseBody::Verified(proof),
        ResponseBody4::Registered {
            origin, elapsed_ms, ..
        } => ResponseBody::Registered { origin, elapsed_ms },
        ResponseBody4::Admitted {
            admission,
            lost_events,
            lost_bytes,
            ..
        } => ResponseBody::Admitted {
            admission,
            lost_events,
            lost_bytes,
        },
        ResponseBody4::Called {
            value,
            fault,
            document,
            ..
        } => ResponseBody::Called {
            value: value.map(|value| match value {
                CallValue4::Document => CallValue::Document,
                CallValue4::Plan(plan) => CallValue::Plan(plan),
                CallValue4::Checkpointed(checkpointed) => CallValue::State(checkpointed.state),
                CallValue4::Decoded(decoded) => CallValue::Decoded(decoded),
                CallValue4::Encoded(encoded) => CallValue::Encoded(encoded),
            }),
            fault,
            document,
        },
        ResponseBody4::Unbound { existed } => ResponseBody::Unbound { existed },
        ResponseBody4::Revised => ResponseBody::Revised,
        ResponseBody4::PrivacySet { private } => ResponseBody::PrivacySet { private },
        ResponseBody4::Health(health) => ResponseBody::Health(health),
        ResponseBody4::Refused {
            request,
            detail,
            disabled,
        } => ResponseBody::Refused {
            request,
            detail,
            disabled,
        },
    }
}

fn notice_of(notice: Notice4, registrations: &Registrations) -> Option<Notice> {
    if !registrations.is_current(notice.binding_id(), notice.registration()) {
        return None;
    }
    match notice {
        Notice4::Document {
            binding_id,
            call,
            document,
            last,
            nodes,
            ..
        } => Some(Notice::Document {
            binding_id,
            call,
            document,
            last,
            nodes,
        }),
        Notice4::Gap {
            binding_id,
            events,
            bytes,
            documents,
            ..
        } => Some(Notice::Gap {
            binding_id,
            events,
            bytes,
            documents,
        }),
        Notice4::Fault {
            binding_id,
            call,
            detail,
            faults_in_window,
            ..
        } => Some(Notice::Fault {
            binding_id,
            call,
            detail,
            faults_in_window,
        }),
        Notice4::Disabled {
            binding_id, reason, ..
        } => Some(Notice::Disabled { binding_id, reason }),
        // What the instance consumed is for a caller that restores by position, which this client is
        // not.
        Notice4::Consumed { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> Uuid {
        Uuid::from_bytes([7; 16])
    }

    fn document(registration: u64) -> Notice4 {
        Notice4::Document {
            binding_id: binding(),
            registration,
            call: "observe".to_owned(),
            document: 1,
            last: true,
            nodes: Vec::new(),
        }
    }

    #[test]
    fn a_registration_never_repeats_an_earlier_one_of_the_binding() {
        let registrations = Registrations::default();
        let first = registrations.begin(binding());
        let second = registrations.begin(binding());
        assert_ne!(first, second, "a registration repeated the one before it");
        assert_eq!(registrations.of(binding()), Some(second));
        // A second connection's registrations are not the first's either.
        let other = Registrations::default();
        let third = other.begin(binding());
        assert!(
            third != first && third != second,
            "a registration repeated one of an earlier connection"
        );
    }

    #[test]
    fn a_notice_of_a_registration_the_client_gave_up_is_dropped() {
        let registrations = Registrations::default();
        let old = registrations.begin(binding());
        let current = registrations.begin(binding());
        assert!(
            notice_of(document(old), &registrations).is_none(),
            "a notice of the older registration was kept"
        );
        assert!(
            matches!(
                notice_of(document(current), &registrations),
                Some(Notice::Document { document: 1, .. })
            ),
            "a notice of the current registration was dropped"
        );
        // A binding the client gave no registration to has none to belong to.
        assert!(notice_of(document(current + 1), &registrations).is_none());
    }

    #[test]
    fn a_report_of_what_was_consumed_is_not_passed_on() {
        let registrations = Registrations::default();
        let current = registrations.begin(binding());
        let report = Notice4::Consumed {
            binding_id: binding(),
            registration: current,
            generation: 0,
            clean: true,
            native: None,
            terminal: None,
        };
        assert!(notice_of(report, &registrations).is_none());
    }

    #[test]
    fn a_restore_carries_the_registration_of_its_binding_and_no_position() {
        let registrations = Registrations::default();
        let current = registrations.begin(binding());
        let request = Request {
            request_id: 9,
            body: RequestBody::Restore {
                binding_id: binding(),
                state: vec![1, 2, 3],
                deadline_ms: 50,
            },
        };
        let RequestBody4::Restore {
            registration,
            through,
            state,
            ..
        } = request_of(request, &registrations, true).body
        else {
            panic!("a restore is a restore");
        };
        assert_eq!(registration, current);
        assert_eq!(through, None);
        assert_eq!(state, vec![1, 2, 3]);
    }
}

//! What a client of `kr-plugin-host/4` writes and reads in the words the client already has.
//!
//! The client's own vocabulary is that of `/3`. Over a `/4` connection each request is turned into
//! its `/4` frame as it is written, and each frame into the `/3` frame it comes to as it is read,
//! so everything above the connection reads the same answers and notices whichever protocol the
//! host speaks. A `/4` member the client has no use for is read and dropped: the position a
//! checkpoint states, the report of what an instance consumed, the events a gap lost and the
//! generation of a fault. A notice that names a registration the host refused or removed is dropped
//! too, since it belongs to an attempt the host did not keep. A notice of a registration whose
//! answer has not been read is kept, since the host can write it before the answer, unless the
//! answer to a removal written since has been read.

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

/// What the client knows of the registrations of one connection, settled by what the host answers.
///
/// A registration the client writes is not its binding's until the host answers it as registered:
/// the host refuses a second registration of a binding that has one and keeps the first, so a
/// number the client minted for the second attempt owns nothing. Each answer is read here, by the
/// request it answers, and the record of what it settled is removed with it.
///
/// The host answers in tasks of its own, so an answer can be read after the requests written later
/// than the one it answers. The order the client wrote the requests in decides what an answer
/// means: a removal ends every registration of its binding that was written before it, and an
/// answer never makes a registration the binding's once a removal, or a later registration that the
/// host answered as registered, has ended it.
#[derive(Debug, Default)]
pub(crate) struct Registrations(Mutex<Held>);

#[derive(Debug, Default)]
struct Held {
    /// The registration each binding runs under: the one the host answered as registered, until
    /// the answer to a removal of it.
    live: HashMap<Uuid, u64>,
    /// The registrations written whose answers have not been read, by the request that carries each.
    trying: HashMap<u64, Attempt>,
    /// The removals written whose answers have not been read, by the request that carries each.
    removing: HashMap<u64, Removal>,
    /// The number of the latest registration written, which orders every request against a removal.
    latest: u64,
}

/// A registration written and not yet answered.
#[derive(Debug)]
struct Attempt {
    binding_id: Uuid,
    registration: u64,
    /// Whether a removal of the binding has been written since: the host will have removed this
    /// registration, if it made it, so its answer makes nothing the binding's.
    ended: bool,
}

/// A removal written and not yet answered.
#[derive(Debug)]
struct Removal {
    binding_id: Uuid,
    /// The latest registration number written when the removal was written: the removal ends the
    /// binding's registrations up to that number.
    through: u64,
}

impl Registrations {
    /// Gives the registration carried by request `request_id` a number it never had, and waits for
    /// the host's answer before it is the binding's.
    fn begin(&self, request_id: u64, binding_id: Uuid) -> u64 {
        let registration = NEXT_REGISTRATION.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut held) = self.0.lock() {
            held.latest = registration;
            held.trying.insert(
                request_id,
                Attempt {
                    binding_id,
                    registration,
                    ended: false,
                },
            );
        }
        registration
    }

    /// Notes that request `request_id` asks the host to remove a binding. It ends every registration
    /// of the binding written so far for installing, whether or not its answer has been read; a
    /// registration the host already answered as registered stays the binding's until the removal's
    /// answer is read.
    fn removal(&self, request_id: u64, binding_id: Uuid) {
        if let Ok(mut held) = self.0.lock() {
            let through = held.latest;
            for attempt in held.trying.values_mut() {
                if attempt.binding_id == binding_id {
                    attempt.ended = true;
                }
            }
            held.removing.insert(
                request_id,
                Removal {
                    binding_id,
                    through,
                },
            );
        }
    }

    /// Settles what the host's answer to request `reply_to` decides about registrations.
    ///
    /// A registration answered as registered is the binding's, unless a removal written after it
    /// has ended it or a later registration is already the binding's. Any other answer to it leaves
    /// the binding as it was, so a refused duplicate keeps the registration the host holds. A
    /// removal that is answered ends every registration of its binding that was written before it,
    /// those not yet answered too, and no registration written after it.
    fn settled(&self, reply_to: u64, body: &ResponseBody4) {
        let Ok(mut held) = self.0.lock() else {
            return;
        };
        if let Some(attempt) = held.trying.remove(&reply_to) {
            if !attempt.ended
                && matches!(
                    body,
                    ResponseBody4::Registered { registration, .. } if *registration == attempt.registration
                )
                && held
                    .live
                    .get(&attempt.binding_id)
                    .is_none_or(|live| *live < attempt.registration)
            {
                held.live.insert(attempt.binding_id, attempt.registration);
            }
        } else if let Some(removal) = held.removing.remove(&reply_to)
            && matches!(
                body,
                ResponseBody4::Unbound { .. } | ResponseBody4::Refused { .. }
            )
        {
            let Removal {
                binding_id,
                through,
            } = removal;
            if held
                .live
                .get(&binding_id)
                .is_some_and(|live| *live <= through)
            {
                held.live.remove(&binding_id);
            }
            held.trying.retain(|_, attempt| {
                attempt.binding_id != binding_id || attempt.registration > through
            });
        }
    }

    /// The registration the binding runs under, where the host answered one as registered.
    fn of(&self, binding_id: Uuid) -> Option<u64> {
        self.0
            .lock()
            .ok()
            .and_then(|held| held.live.get(&binding_id).copied())
    }

    /// Whether what carries `registration` belongs to the binding's registration, or to one the host
    /// has not yet answered, whose first notices can be read before its answer.
    fn is_current(&self, binding_id: Uuid, registration: u64) -> bool {
        self.0.lock().is_ok_and(|held| {
            held.live.get(&binding_id) == Some(&registration)
                || held.trying.values().any(|attempt| {
                    attempt.binding_id == binding_id && attempt.registration == registration
                })
        })
    }
}

/// Turns a request into the frame of `/4`.
///
/// A registration is given its number here, as the request is written, so that what the host
/// writes about it can never arrive before the client knows the number. `minting` is false when
/// only the size of the frame is wanted, which records nothing.
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
                registrations.begin(request_id, binding.binding_id)
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
        RequestBody::Unbind { binding_id } => {
            if minting {
                registrations.removal(request_id, binding_id);
            }
            RequestBody4::Unbind { binding_id }
        }
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
        Frame4::Response { reply_to, body } => {
            registrations.settled(reply_to, &body);
            Some(Frame::Response {
                reply_to,
                body: response_of(body),
            })
        }
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

    fn registered(registration: u64) -> ResponseBody4 {
        ResponseBody4::Registered {
            registration,
            origin: "cached".to_owned(),
            elapsed_ms: 1,
        }
    }

    fn refused() -> ResponseBody4 {
        ResponseBody4::Refused {
            request: "register_binding".to_owned(),
            detail: "refused".to_owned(),
            disabled: false,
        }
    }

    /// Writes a registration of the binding as request `request_id` and returns its number.
    fn register(registrations: &Registrations, request_id: u64) -> u64 {
        registrations.begin(request_id, binding())
    }

    #[test]
    fn a_registration_never_repeats_an_earlier_one_of_the_binding() {
        let registrations = Registrations::default();
        let first = register(&registrations, 1);
        let second = register(&registrations, 2);
        assert_ne!(first, second, "a registration repeated the one before it");
        // A second connection's registrations are not the first's either.
        let other = Registrations::default();
        let third = register(&other, 1);
        assert!(
            third != first && third != second,
            "a registration repeated one of an earlier connection"
        );
    }

    #[test]
    fn a_registration_is_the_bindings_when_the_host_answers_it_as_registered() {
        let registrations = Registrations::default();
        let first = register(&registrations, 1);
        assert_eq!(
            registrations.of(binding()),
            None,
            "a registration was the binding's before the host answered it"
        );
        registrations.settled(1, &registered(first));
        assert_eq!(registrations.of(binding()), Some(first));
    }

    #[test]
    fn a_refused_duplicate_keeps_the_registration_the_host_holds() {
        let registrations = Registrations::default();
        let first = register(&registrations, 1);
        registrations.settled(1, &registered(first));
        let second = register(&registrations, 2);
        // While its answer is awaited, the notices of both are the binding's.
        assert!(notice_of(document(first), &registrations).is_some());
        assert!(notice_of(document(second), &registrations).is_some());
        registrations.settled(2, &refused());
        assert_eq!(
            registrations.of(binding()),
            Some(first),
            "a refused duplicate took the binding's registration"
        );
        assert!(
            matches!(
                notice_of(document(first), &registrations),
                Some(Notice::Document { document: 1, .. })
            ),
            "a notice of the registration the host holds was dropped"
        );
        assert!(
            notice_of(document(second), &registrations).is_none(),
            "a notice of the refused registration was kept"
        );
    }

    #[test]
    fn a_registration_the_host_refused_leaves_nothing_behind() {
        let registrations = Registrations::default();
        register(&registrations, 1);
        registrations.settled(1, &refused());
        let held = registrations.0.lock().expect("the record is usable");
        assert!(
            held.trying.is_empty() && held.live.is_empty() && held.removing.is_empty(),
            "a refused registration left a record: {held:?}"
        );
    }

    #[test]
    fn a_removal_the_host_answered_leaves_nothing_behind() {
        let registrations = Registrations::default();
        let first = register(&registrations, 1);
        registrations.settled(1, &registered(first));
        registrations.removal(2, binding());
        registrations.settled(2, &ResponseBody4::Unbound { existed: true });
        assert_eq!(registrations.of(binding()), None);
        assert!(
            notice_of(document(first), &registrations).is_none(),
            "a notice of a removed registration was kept"
        );
        let held = registrations.0.lock().expect("the record is usable");
        assert!(
            held.trying.is_empty() && held.live.is_empty() && held.removing.is_empty(),
            "a removal left a record: {held:?}"
        );
    }

    #[test]
    fn a_removal_answered_after_a_later_registration_keeps_the_later_one() {
        let registrations = Registrations::default();
        let first = register(&registrations, 1);
        registrations.settled(1, &registered(first));
        registrations.removal(2, binding());
        // The host removes the first, registers the second, and the second's answer is read before
        // the removal's.
        let second = register(&registrations, 3);
        registrations.settled(3, &registered(second));
        registrations.settled(2, &ResponseBody4::Unbound { existed: true });
        assert_eq!(
            registrations.of(binding()),
            Some(second),
            "a removal of the first registration ended the second"
        );
    }

    #[test]
    fn a_registration_answered_after_a_later_one_took_its_place_does_not_replace_it() {
        let registrations = Registrations::default();
        let first = register(&registrations, 1);
        // The caller stops waiting for the answer and unbinds. The host removes the first
        // registration and answers the unbind before the first registration's answer is read.
        registrations.removal(2, binding());
        registrations.settled(2, &ResponseBody4::Unbound { existed: true });
        assert!(
            notice_of(document(first), &registrations).is_none(),
            "a notice of a registration the unbind removed was kept while its answer was unread"
        );
        // A second registration is made and answered.
        let second = register(&registrations, 3);
        registrations.settled(3, &registered(second));
        // The first registration's answer is read last.
        registrations.settled(1, &registered(first));
        assert_eq!(
            registrations.of(binding()),
            Some(second),
            "a late answer of the first registration replaced the second"
        );
        assert!(
            matches!(
                notice_of(document(second), &registrations),
                Some(Notice::Document { document: 1, .. })
            ),
            "a notice of the registration the host holds was dropped"
        );
        assert!(
            notice_of(document(first), &registrations).is_none(),
            "a notice of the removed registration was kept"
        );
        let request = Request {
            request_id: 9,
            body: RequestBody::Restore {
                binding_id: binding(),
                state: vec![1],
                deadline_ms: 50,
            },
        };
        let RequestBody4::Restore { registration, .. } =
            request_of(request, &registrations, true).body
        else {
            panic!("a restore is a restore");
        };
        assert_eq!(
            registration, second,
            "a restore named a registration the host had removed"
        );
        let held = registrations.0.lock().expect("the record is usable");
        assert!(
            held.trying.is_empty() && held.removing.is_empty(),
            "the answers left a record behind: {held:?}"
        );
    }

    #[test]
    fn a_registration_answered_after_the_unbind_that_ended_it_was_written_is_not_kept() {
        let registrations = Registrations::default();
        let first = register(&registrations, 1);
        // The unbind is written before the host's answer to the registration is read.
        registrations.removal(2, binding());
        registrations.settled(1, &registered(first));
        assert_eq!(
            registrations.of(binding()),
            None,
            "a registration that an unbind already ended became the binding's"
        );
        registrations.settled(2, &ResponseBody4::Unbound { existed: true });
        assert_eq!(registrations.of(binding()), None);
        assert!(
            notice_of(document(first), &registrations).is_none(),
            "a notice of a removed registration was kept"
        );
        let held = registrations.0.lock().expect("the record is usable");
        assert!(
            held.trying.is_empty() && held.live.is_empty() && held.removing.is_empty(),
            "the answers left a record behind: {held:?}"
        );
    }

    #[test]
    fn a_registration_answered_after_a_later_one_was_installed_does_not_replace_it() {
        let registrations = Registrations::default();
        let first = register(&registrations, 1);
        let second = register(&registrations, 2);
        // The answers are read in the reverse of the order the requests were written.
        registrations.settled(2, &registered(second));
        registrations.settled(1, &registered(first));
        assert_eq!(
            registrations.of(binding()),
            Some(second),
            "an answer of an earlier registration replaced a later one"
        );
    }

    #[test]
    fn a_removal_written_after_a_second_registration_ends_the_binding_whichever_answer_is_read_first()
     {
        for removal_first in [false, true] {
            let registrations = Registrations::default();
            let first = register(&registrations, 1);
            registrations.settled(1, &registered(first));
            // A second registration of the binding is written while the first stands, and the
            // unbind after it. The host refuses the second as a duplicate and removes the first.
            let second = register(&registrations, 2);
            registrations.removal(3, binding());
            let unbound = ResponseBody4::Unbound { existed: true };
            if removal_first {
                registrations.settled(3, &unbound);
                registrations.settled(2, &refused());
            } else {
                registrations.settled(2, &refused());
                registrations.settled(3, &unbound);
            }
            assert_eq!(
                registrations.of(binding()),
                None,
                "a registration was the binding's after the unbind that removed it was answered"
            );
            assert!(
                notice_of(document(first), &registrations).is_none(),
                "a notice of the removed registration was kept"
            );
            assert!(
                notice_of(document(second), &registrations).is_none(),
                "a notice of the refused registration was kept"
            );
            let held = registrations.0.lock().expect("the record is usable");
            assert!(
                held.trying.is_empty() && held.live.is_empty() && held.removing.is_empty(),
                "the answers left a record behind: {held:?}"
            );
        }
    }

    #[test]
    fn a_registration_written_after_a_removal_is_kept_when_the_removals_answer_is_read_first() {
        let registrations = Registrations::default();
        // The unbind is written, then a registration of the binding. The unbind's answer is read
        // before the registration's.
        registrations.removal(1, binding());
        let later = register(&registrations, 2);
        registrations.settled(1, &ResponseBody4::Unbound { existed: false });
        assert!(
            notice_of(document(later), &registrations).is_some(),
            "a notice of a registration written after the unbind was dropped"
        );
        registrations.settled(2, &registered(later));
        assert_eq!(
            registrations.of(binding()),
            Some(later),
            "a removal ended a registration written after it"
        );
    }

    #[test]
    fn a_report_of_what_was_consumed_is_not_passed_on() {
        let registrations = Registrations::default();
        let current = register(&registrations, 1);
        registrations.settled(1, &registered(current));
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
        let current = register(&registrations, 1);
        registrations.settled(1, &registered(current));
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

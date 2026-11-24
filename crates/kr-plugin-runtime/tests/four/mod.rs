//! The fourth plugin host protocol on the host: one host serving it beside the third, each on an
//! endpoint of its own.
//!
//! A connection here speaks the frames of `kr-plugin-host/4` itself, with no client between it and
//! the host, so what a case reads is what the host wrote. Every case runs the host with its writer
//! open or closed by the setter, never by the shipped default.

use std::collections::HashMap;

use kr_plugin_runtime::runtime::binding::BindingRequest;
use kr_plugin_service::launcher::{check_proof, fresh_challenge};
use kr_plugin_service::protocol::{
    BindingRegistration, ComponentSource, Frame, HostProtocol, RequestBody, ResponseBody,
    WireSourceEvent,
};
use kr_plugin_service::protocol4::{
    BindingRegistration4, Checkpointed, Consumed, Frame4, Notice4, RecordState, Request4,
    RequestBody4, ResponseBody4, Through,
};
use kr_plugin_service::vocabulary::{MAX_NODE_BYTES, wire_event};
use kr_protocol::ids::SourceEventHandle;

use super::{HANG_GUARD, Raw, Served, components, reached};

mod connect;
mod record;

fn handle(text: &str) -> SourceEventHandle {
    SourceEventHandle::new(text).expect("a bounded handle")
}

/// A connection that speaks the frames of `/4` itself.
struct Raw4 {
    reader: kr_ipc::framed::FrameReader,
    writer: kr_ipc::framed::FrameWriter,
    next: u64,
    answers: HashMap<u64, ResponseBody4>,
    /// Every notice the connection has read, in the order it read them.
    notices: Vec<Notice4>,
}

impl Raw4 {
    async fn connect(endpoint: &str) -> Self {
        let endpoint = kr_ipc::paths::Endpoint::from_path(endpoint).expect("an endpoint");
        let connection = kr_ipc::endpoint::Connection::connect(&endpoint)
            .await
            .expect("connects to the plugin host");
        let (reader, writer) =
            kr_ipc::framed::split(connection, kr_protocol::frame::StreamKind::Control);
        Self {
            reader,
            writer,
            next: 0,
            answers: HashMap::new(),
            notices: Vec::new(),
        }
    }

    async fn send(&mut self, body: RequestBody4) -> u64 {
        self.next += 1;
        let request_id = self.next;
        self.writer
            .write_message(&Request4 { request_id, body })
            .await
            .expect("the request is written");
        request_id
    }

    /// Reads one frame, keeping what it is.
    async fn read(&mut self) {
        let frame: Frame4 =
            tokio::time::timeout(HANG_GUARD, self.reader.read_message_without_schema())
                .await
                .expect("the host wrote nothing")
                .expect("the host's frame reads as a frame of the fourth protocol");
        match frame {
            Frame4::Response { reply_to, body } => {
                self.answers.insert(reply_to, body);
            }
            Frame4::Notice(notice) => self.notices.push(notice),
        }
    }

    async fn ask(&mut self, body: RequestBody4) -> ResponseBody4 {
        let request_id = self.send(body).await;
        self.answer_of(request_id).await
    }

    /// Reads until the answer to `request_id` has come, and returns it.
    async fn answer_of(&mut self, request_id: u64) -> ResponseBody4 {
        while !self.answers.contains_key(&request_id) {
            self.read().await;
        }
        self.answers
            .remove(&request_id)
            .expect("the answer is there")
    }

    /// Reads until a notice that `wanted` holds of has come, and returns every notice read so far.
    async fn until(&mut self, wanted: impl Fn(&Notice4) -> bool) -> Vec<Notice4> {
        while !self.notices.iter().any(&wanted) {
            self.read().await;
        }
        self.notices.clone()
    }

    /// Reads until a notice that `second` holds of has come after one that `first` holds of, and
    /// returns every notice read so far.
    async fn until_after(
        &mut self,
        first: impl Fn(&Notice4) -> bool,
        second: impl Fn(&Notice4) -> bool,
    ) -> Vec<Notice4> {
        loop {
            if let Some(at) = self.notices.iter().position(&first)
                && self.notices[at..].iter().any(&second)
            {
                return self.notices.clone();
            }
            self.read().await;
        }
    }

    async fn register(
        &mut self,
        request: &BindingRequest,
        component: &ComponentSource,
        registration: u64,
    ) -> ResponseBody4 {
        self.ask(RequestBody4::RegisterBinding(Box::new(
            BindingRegistration4 {
                registration,
                binding: BindingRegistration {
                    binding_id: request.binding_id.get(),
                    identity: request.identity.clone(),
                    facts: kr_plugin_service::vocabulary::wire_facts(&request.facts),
                    executable: request.executable.clone(),
                    component: component.clone(),
                },
            },
        )))
        .await
    }

    async fn event(&mut self, request: &BindingRequest, name: &str, text: &str) -> ResponseBody4 {
        self.ask(RequestBody4::Event {
            binding_id: request.binding_id.get(),
            event: wire_event(&components::scrape(name, text)),
        })
        .await
    }

    async fn checkpoint(&mut self, request: &BindingRequest) -> Checkpointed {
        let answered = self
            .ask(RequestBody4::Checkpoint {
                binding_id: request.binding_id.get(),
                deadline_ms: u64::try_from(HANG_GUARD.as_millis()).expect("milliseconds"),
            })
            .await;
        let ResponseBody4::Called {
            value: Some(kr_plugin_service::protocol4::CallValue4::Checkpointed(checkpointed)),
            ..
        } = answered
        else {
            panic!("a checkpoint was answered with {answered:?}");
        };
        *checkpointed
    }

    async fn restore(
        &mut self,
        request: &BindingRequest,
        registration: u64,
        state: Vec<u8>,
        through: Option<Through>,
    ) -> ResponseBody4 {
        self.ask(RequestBody4::Restore {
            binding_id: request.binding_id.get(),
            registration,
            state,
            through,
            deadline_ms: u64::try_from(HANG_GUARD.as_millis()).expect("milliseconds"),
        })
        .await
    }

    /// Removes a binding. Every notice the binding produced is written before the answer.
    async fn unbind(&mut self, request: &BindingRequest) {
        let answered = self
            .ask(RequestBody4::Unbind {
                binding_id: request.binding_id.get(),
            })
            .await;
        assert!(
            matches!(answered, ResponseBody4::Unbound { .. }),
            "an unbind was answered with {answered:?}"
        );
    }
}

/// The component that records what it observes, installed on `served`, or nothing when the test
/// components are not built.
fn recording(served: &Served) -> Option<ComponentSource> {
    let wasm = components::component("recording")?;
    let (path, digest, bytes) = served.install("recording", &wasm);
    Some(ComponentSource {
        path,
        digest,
        bytes,
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_24_24_each_endpoint_speaks_one_protocol_and_the_fourth_states_its_build() {
    let served = Served::start_dual(true).await;
    let mut four = Raw4::connect(served.endpoint4()).await;
    let refused = four
        .ask(RequestBody4::Hello {
            protocol: HostProtocol::V3.name.to_owned(),
        })
        .await;
    let ResponseBody4::Refused {
        detail,
        disabled: false,
        ..
    } = refused
    else {
        panic!("the fourth endpoint answered the third protocol's name with {refused:?}");
    };
    assert_eq!(
        detail,
        format!(
            "this endpoint speaks {} and the caller offered {}",
            HostProtocol::V4.name,
            HostProtocol::V3.name
        ),
        "the fourth endpoint says which protocol it speaks"
    );
    let hello = four
        .ask(RequestBody4::Hello {
            protocol: HostProtocol::V4.name.to_owned(),
        })
        .await;
    let ResponseBody4::Hello {
        protocol,
        descriptor,
    } = hello
    else {
        panic!("the fourth endpoint answered its own name with {hello:?}");
    };
    assert_eq!(protocol, HostProtocol::V4.name);
    assert_eq!(descriptor.protocol, HostProtocol::V4.name);
    assert_eq!(descriptor.endpoint, served.endpoint4());
    assert_eq!(descriptor.build, super::Served::build());

    let mut three = Raw::connect(&served).await;
    let refused = three
        .ask(RequestBody::Hello {
            protocol: HostProtocol::V4.name.to_owned(),
        })
        .await;
    let ResponseBody::Refused {
        detail,
        disabled: false,
        ..
    } = refused
    else {
        panic!("the third endpoint answered the fourth protocol's name with {refused:?}");
    };
    // The third protocol's refusal is the text it was released with.
    assert_eq!(
        detail,
        format!(
            "this host speaks {} and the caller offered {}",
            HostProtocol::V3.name,
            HostProtocol::V4.name
        ),
        "the third endpoint says what it said when it was released"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_24_24_a_proof_verifies_against_the_endpoint_the_challenge_arrived_on_only() {
    let served = Served::start_dual(true).await;
    let mut four = Raw4::connect(served.endpoint4()).await;
    let nonce = fresh_challenge().expect("a challenge");
    let verified = four.ask(RequestBody4::Verify { nonce }).await;
    let ResponseBody4::Verified(proof) = verified else {
        panic!("a challenge was answered with {verified:?}");
    };
    let mut named_by_the_fourth = served.descriptor.clone();
    named_by_the_fourth.endpoint = served.endpoint4().to_owned();
    assert!(
        check_proof(&named_by_the_fourth, &nonce, &proof).is_ok(),
        "the proof does not verify against the endpoint it was asked on"
    );
    assert!(
        check_proof(&served.descriptor, &nonce, &proof).is_err(),
        "the proof verifies against the third protocol's endpoint too"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_24_24_an_open_host_names_the_registration_and_reports_what_a_pass_consumed_after_its_fault()
 {
    let served = Served::start_dual(true).await;
    let Some(component) = recording(&served) else {
        return;
    };
    let mut four = Raw4::connect(served.endpoint4()).await;
    let request = components::request("recording", 31);
    let registered = four.register(&request, &component, 7).await;
    assert!(
        matches!(
            registered,
            ResponseBody4::Registered {
                registration: 7,
                ..
            }
        ),
        "the registration was answered with {registered:?}"
    );
    // Both events are in the queue before the pass that takes them starts, so one pass returns
    // se-1 and traps on se-2, and reports once it is over.
    let mut stop = served
        .host
        .runtime()
        .stop_next_pump(request.binding_id)
        .expect("the binding is live");
    let admitted = four.event(&request, "se-1", "x").await;
    assert!(
        matches!(admitted, ResponseBody4::Admitted { free_bytes, .. } if free_bytes > 0),
        "the first event was answered with {admitted:?}"
    );
    four.event(&request, "se-2", "!trap").await;
    assert!(
        tokio::time::timeout(HANG_GUARD, stop.reached())
            .await
            .expect("the binding's pass stands at the stop"),
        "the stop was replaced before a pass reached it"
    );
    stop.release();
    let notices = four
        .until_after(
            |notice| matches!(notice, Notice4::Fault { .. }),
            |notice| matches!(notice, Notice4::Consumed { .. }),
        )
        .await;
    let fault = notices
        .iter()
        .position(|notice| matches!(notice, Notice4::Fault { .. }))
        .expect("the trap was told");
    let report = fault
        + notices[fault..]
            .iter()
            .position(|notice| matches!(notice, Notice4::Consumed { .. }))
            .expect("the pass was reported");
    let Notice4::Fault {
        registration,
        event,
        generation,
        ..
    } = &notices[fault]
    else {
        panic!("a fault was expected");
    };
    assert_eq!(
        (*registration, event.clone(), *generation),
        (7, Some(handle("se-2")), 1),
        "the fault names the registration, the event that trapped and the next generation"
    );
    let Notice4::Consumed {
        registration,
        clean,
        terminal,
        ..
    } = &notices[report]
    else {
        panic!("a report was expected");
    };
    assert_eq!(
        (*registration, *clean, terminal.clone()),
        (7, false, Some(handle("se-1"))),
        "the report names the registration, that the trap made it unclean, and the last event returned"
    );
    four.unbind(&request).await;
}

/// A report that the binding made before a restore, and that the notice writer holds while the
/// restore completes, is not written after the restore's answer: it describes the state the restore
/// replaced.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_24_24_a_report_of_the_state_a_restore_replaced_is_not_written_after_its_answer() {
    let served = Served::start_dual(true).await;
    let Some(component) = recording(&served) else {
        return;
    };
    let mut four = Raw4::connect(served.endpoint4()).await;
    let request = components::request("recording", 35);
    four.register(&request, &component, 7).await;
    // The report of the first event is taken off the notice queue and held at the writer.
    let hold = served.host.hold_notice_writes();
    four.event(&request, "se-1", "x").await;
    reached(&hold, "the writer never took the report off the queue").await;
    let saved = four.checkpoint(&request).await;
    assert_eq!(
        saved
            .consumed
            .as_ref()
            .and_then(|consumed| consumed.terminal.clone()),
        Some(handle("se-1")),
        "the instance had not consumed the first event when the state was saved"
    );
    // A plain restore: the registration has been offered an event, so one that carries a position
    // would set nothing.
    let restored = four.restore(&request, 7, saved.state, None).await;
    assert!(
        matches!(
            restored,
            ResponseBody4::Called {
                record: Some(RecordState::NotSet),
                ..
            }
        ),
        "a plain restore was answered with {restored:?}"
    );
    let before_the_answer = four.notices.len();
    hold.release();
    // What the instance consumes after the restore is reported after it, and only that.
    four.event(&request, "se-2", "y").await;
    let notices = four
        .until(|notice| {
            matches!(notice, Notice4::Consumed { terminal: Some(last), .. } if *last == handle("se-2"))
        })
        .await;
    let stale: Vec<&Notice4> = notices[before_the_answer..]
        .iter()
        .filter(|notice| {
            matches!(notice, Notice4::Consumed { terminal: Some(last), .. } if *last == handle("se-1"))
        })
        .collect();
    assert!(
        stale.is_empty(),
        "the report of the state the restore replaced was written after its answer: {stale:?}"
    );
    four.unbind(&request).await;
}

/// An event the host refuses before it reaches the queue is a loss like any other: what the
/// instance consumes after it is not a prefix of what was offered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_24_24_an_event_refused_before_the_queue_clears_clean_for_what_follows() {
    let served = Served::start_dual(true).await;
    let Some(component) = recording(&served) else {
        return;
    };
    let mut four = Raw4::connect(served.endpoint4()).await;
    let request = components::request("recording", 36);
    four.register(&request, &component, 7).await;
    four.event(&request, "se-1", "x").await;
    let unknown = four
        .ask(RequestBody4::Event {
            binding_id: request.binding_id.get(),
            event: WireSourceEvent {
                provenance: "elsewhere".to_owned(),
                ..wire_event(&components::scrape("se-2", "y"))
            },
        })
        .await;
    assert!(
        matches!(
            unknown,
            ResponseBody4::Refused {
                disabled: false,
                ..
            }
        ),
        "an event of a provenance the host does not know was answered with {unknown:?}"
    );
    four.event(&request, "se-3", "z").await;
    let saved = loop {
        let saved = four.checkpoint(&request).await;
        let consumed = saved
            .consumed
            .clone()
            .expect("an open host states what the instance has consumed");
        if consumed.terminal == Some(handle("se-3")) {
            break saved;
        }
        tokio::task::yield_now().await;
    };
    assert_eq!(
        saved.consumed.map(|consumed| consumed.clean),
        Some(false),
        "what the instance consumed after the refused event was said to follow it"
    );
}

/// A restore whose state is over the bound is a request this host refuses, with its writer open or
/// closed, and the instance is as it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_24_24_a_restore_with_a_state_over_the_bound_is_refused_and_changes_nothing() {
    for open in [true, false] {
        let served = Served::start_dual(open).await;
        let Some(component) = recording(&served) else {
            return;
        };
        let mut four = Raw4::connect(served.endpoint4()).await;
        let request = components::request("recording", if open { 37 } else { 38 });
        four.register(&request, &component, 7).await;
        four.event(&request, "se-1", "x").await;
        let before = if open {
            loop {
                let saved = four.checkpoint(&request).await;
                if saved
                    .consumed
                    .as_ref()
                    .is_some_and(|consumed| consumed.terminal == Some(handle("se-1")))
                {
                    break Some(saved);
                }
                tokio::task::yield_now().await;
            }
        } else {
            None
        };
        let over = vec![0_u8; usize::try_from(MAX_NODE_BYTES).expect("a usize bound") + 1];
        let refused = four
            .restore(
                &request,
                7,
                over,
                Some(Through {
                    native: None,
                    terminal: Some(handle("se-1")),
                }),
            )
            .await;
        assert!(
            matches!(
                refused,
                ResponseBody4::Refused {
                    disabled: false,
                    ..
                }
            ),
            "a restore of a state over the bound was answered with {refused:?} (open: {open})"
        );
        if let Some(before) = before {
            let after = four.checkpoint(&request).await;
            assert_eq!(
                (after.state, after.consumed),
                (before.state, before.consumed),
                "the refused restore changed the instance"
            );
        }
        // The binding still runs: an event is consumed after the refusal.
        four.event(&request, "se-2", "y").await;
        four.unbind(&request).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_24_24_a_closed_host_writes_no_report_no_position_and_no_record() {
    let served = Served::start_dual(false).await;
    let Some(component) = recording(&served) else {
        return;
    };
    let mut four = Raw4::connect(served.endpoint4()).await;
    let request = components::request("recording", 32);
    four.register(&request, &component, 7).await;
    four.event(&request, "se-1", "x").await;
    four.event(&request, "se-2", "!trap").await;
    let notices = four
        .until(|notice| matches!(notice, Notice4::Fault { .. }))
        .await;
    let Some(Notice4::Fault {
        event, generation, ..
    }) = notices
        .iter()
        .find(|notice| matches!(notice, Notice4::Fault { .. }))
    else {
        panic!("a fault was expected");
    };
    assert_eq!(
        (event.clone(), *generation),
        (None, 1),
        "a closed host names no event, and still the next generation"
    );
    let checkpointed = four.checkpoint(&request).await;
    assert_eq!(
        checkpointed.consumed, None,
        "a closed host states no record"
    );
    // Everything the binding produced is written before the answer to its unbind.
    four.unbind(&request).await;
    assert!(
        !four
            .notices
            .iter()
            .any(|notice| matches!(notice, Notice4::Consumed { .. })),
        "a closed host reported what an instance consumed"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_24_24_a_restore_that_carries_a_position_sets_the_record_of_the_registration_it_is_for()
 {
    let served = Served::start_dual(true).await;
    let Some(component) = recording(&served) else {
        return;
    };
    let mut four = Raw4::connect(served.endpoint4()).await;
    let first = components::request("recording", 33);
    four.register(&first, &component, 7).await;
    four.event(&first, "se-1", "x").await;
    four.event(&first, "se-2", "y").await;
    // The state is checkpointed once the instance has consumed both events.
    let saved = loop {
        let saved = four.checkpoint(&first).await;
        let consumed = saved
            .consumed
            .clone()
            .expect("an open host states what the instance has consumed");
        if consumed.terminal == Some(handle("se-2")) {
            break saved;
        }
        tokio::task::yield_now().await;
    };
    let Some(Consumed {
        registration: 7,
        generation: 0,
        clean: true,
        ..
    }) = saved.consumed.clone()
    else {
        panic!("the saved record was {:?}", saved.consumed);
    };

    // A second registration of another binding, which the saved state is moved into.
    let second = components::request("recording", 34);
    four.register(&second, &component, 8).await;
    let through = Through {
        native: None,
        terminal: Some(handle("se-2")),
    };
    let restored = four
        .restore(&second, 8, saved.state.clone(), Some(through.clone()))
        .await;
    assert!(
        matches!(
            restored,
            ResponseBody4::Called {
                record: Some(RecordState::Set),
                ..
            }
        ),
        "a restore with a position was answered with {restored:?}"
    );
    let moved = four.checkpoint(&second).await;
    assert_eq!(
        moved.consumed,
        Some(Consumed {
            registration: 8,
            generation: 0,
            clean: true,
            native: None,
            terminal: Some(handle("se-2")),
        }),
        "the record carries the registration it was restored into and the positions it was saved with"
    );

    // A restore for another registration than the binding's own is refused, and nothing changes.
    let refused = four
        .restore(&second, 7, saved.state.clone(), Some(through))
        .await;
    let ResponseBody4::Refused {
        detail,
        disabled: false,
        ..
    } = refused
    else {
        panic!("a restore for another registration was answered with {refused:?}");
    };
    assert_eq!(
        detail,
        format!(
            "the restore is for registration 7 and binding {} was registered as 8",
            second.binding_id.get()
        ),
        "the refusal says which registration the binding has"
    );
    assert_eq!(four.checkpoint(&second).await.consumed, moved.consumed);

    // A plain restore sets no record and the position is no longer clean.
    let plain = four.restore(&second, 8, saved.state, None).await;
    assert!(
        matches!(
            plain,
            ResponseBody4::Called {
                record: Some(RecordState::NotSet),
                ..
            }
        ),
        "a plain restore was answered with {plain:?}"
    );
    let after = four.checkpoint(&second).await;
    assert_eq!(after.consumed.map(|consumed| consumed.clean), Some(false));
}

// An unbind retires the registration when it is read, so a restore that was read before it and runs
// after it is for a binding that is being removed, and is told so.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_24_24_a_restore_read_before_an_unbind_and_run_after_it_is_refused_as_for_a_binding_being_removed()
 {
    let served = Served::start_dual(true).await;
    let Some(component) = recording(&served) else {
        return;
    };
    let mut four = Raw4::connect(served.endpoint4()).await;
    let request = components::request("recording", 42);
    four.register(&request, &component, 7).await;
    let hold = served.host.hold_calls_before_they_run();
    let restoring = four
        .send(RequestBody4::Restore {
            binding_id: request.binding_id.get(),
            registration: 7,
            state: Vec::new(),
            through: None,
            deadline_ms: u64::try_from(HANG_GUARD.as_millis()).expect("milliseconds"),
        })
        .await;
    reached(&hold, "the restore's task never started").await;
    four.unbind(&request).await;
    hold.release();
    let refused = four.answer_of(restoring).await;
    let ResponseBody4::Refused {
        detail,
        disabled: false,
        ..
    } = refused
    else {
        panic!("a restore for a binding being removed was answered with {refused:?}");
    };
    assert_eq!(
        detail,
        format!(
            "the restore is for registration 7 and binding {} is being removed",
            request.binding_id.get()
        ),
        "the refusal says the binding is being removed"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_24_24_a_closed_host_restores_nothing_for_a_position_and_says_it_set_no_record() {
    let served = Served::start_dual(false).await;
    let Some(component) = recording(&served) else {
        return;
    };
    let mut four = Raw4::connect(served.endpoint4()).await;
    let first = components::request("recording", 35);
    let second = components::request("recording", 36);
    four.register(&first, &component, 7).await;
    four.register(&second, &component, 8).await;
    four.event(&first, "se-1", "x").await;
    // A state that differs from the second binding's own, once the first has taken the event in.
    let before = four.checkpoint(&second).await.state;
    let saved = loop {
        let saved = four.checkpoint(&first).await;
        if saved.state != before {
            break saved;
        }
        tokio::task::yield_now().await;
    };
    let restored = four
        .restore(
            &second,
            8,
            saved.state.clone(),
            Some(Through {
                native: None,
                terminal: Some(handle("se-1")),
            }),
        )
        .await;
    assert!(
        matches!(
            restored,
            ResponseBody4::Called {
                record: Some(RecordState::NotSet),
                ..
            }
        ),
        "a closed host answered a restore with a position with {restored:?}"
    );
    assert_eq!(
        four.checkpoint(&second).await.state,
        before,
        "a closed host restored the state"
    );
}

// A registration that has been offered an event may have consumed past the state a restore would
// bring back, and a position set from the restore would call what follows a continuation of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_24_24_an_open_host_restores_nothing_for_a_position_once_the_registration_has_been_offered_an_event()
 {
    let served = Served::start_dual(true).await;
    let Some(component) = recording(&served) else {
        return;
    };
    let mut four = Raw4::connect(served.endpoint4()).await;
    let first = components::request("recording", 43);
    let second = components::request("recording", 44);
    four.register(&first, &component, 7).await;
    four.register(&second, &component, 8).await;
    four.event(&first, "se-1", "x").await;
    four.event(&second, "se-9", "y").await;
    // Each instance has taken its event in.
    let saved = loop {
        let saved = four.checkpoint(&first).await;
        if saved
            .consumed
            .as_ref()
            .is_some_and(|consumed| consumed.terminal == Some(handle("se-1")))
        {
            break saved;
        }
        tokio::task::yield_now().await;
    };
    let current = loop {
        let current = four.checkpoint(&second).await;
        if current
            .consumed
            .as_ref()
            .is_some_and(|consumed| consumed.terminal == Some(handle("se-9")))
        {
            break current;
        }
        tokio::task::yield_now().await;
    };
    assert_ne!(saved.state, current.state, "the two states do not differ");

    let restored = four
        .restore(
            &second,
            8,
            saved.state.clone(),
            Some(Through {
                native: None,
                terminal: Some(handle("se-1")),
            }),
        )
        .await;
    assert!(
        matches!(
            restored,
            ResponseBody4::Called {
                record: Some(RecordState::NotSet),
                ..
            }
        ),
        "an open host answered a restore with a position, after an event was offered, with {restored:?}"
    );
    let after = four.checkpoint(&second).await;
    assert_eq!(
        after.state, current.state,
        "the host restored the state of another registration's position"
    );
    assert_eq!(
        after.consumed, current.consumed,
        "the host changed what the instance has consumed"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_24_24_a_third_protocol_connection_on_a_host_with_its_writer_open_is_told_nothing_new()
 {
    use kr_plugin_service::protocol::{CallValue, Notice};

    let served = Served::start_dual(true).await;
    let Some(component) = recording(&served) else {
        return;
    };
    // Every frame this connection is written is read here, as a frame of the third protocol, and
    // not through a helper that unwraps a read: a frame that protocol does not have fails this case,
    // and a connection the host closed is said to be closed.
    macro_rules! next_frame_of_three {
        ($three:expr) => {{
            let frame: Result<Frame, _> =
                tokio::time::timeout(HANG_GUARD, $three.reader.read_message_without_schema())
                    .await
                    .expect("the host wrote nothing");
            match frame {
                Ok(frame) => frame,
                Err(kr_ipc::error::IpcError::PeerClosed) => {
                    panic!("the host closed the connection")
                }
                Err(error) => {
                    panic!("the host wrote a frame the third protocol does not have: {error:?}")
                }
            }
        }};
    }
    // Reads until the answer to `$id`, and keeps the notices that come first.
    macro_rules! answered_by {
        ($three:expr, $id:expr, $notices:expr) => {{
            loop {
                match next_frame_of_three!($three) {
                    Frame::Response { reply_to, body } if reply_to == $id => break body,
                    Frame::Response { .. } => {}
                    Frame::Notice(notice) => $notices.push(notice),
                }
            }
        }};
    }
    let mut three = Raw::connect(&served).await;
    let mut notices = Vec::new();

    // A registration, two events one of which traps, and an unbind: the trap is told, and the
    // answer to the unbind follows everything the binding produced.
    let first = components::request("recording", 37);
    let request = first.clone();
    let registering = three.send_register(&request, &component).await;
    let registered = answered_by!(three, registering, notices);
    assert!(
        matches!(registered, ResponseBody::Registered { .. }),
        "the registration was answered with {registered:?}"
    );
    for (name, text) in [("se-1", "x"), ("se-2", "!trap")] {
        let id = three
            .send(RequestBody::Event {
                binding_id: request.binding_id.get(),
                event: wire_event(&components::scrape(name, text)),
            })
            .await;
        answered_by!(three, id, notices);
    }
    while !notices
        .iter()
        .any(|notice| matches!(notice, Notice::Fault { .. }))
    {
        match next_frame_of_three!(three) {
            Frame::Notice(notice) => notices.push(notice),
            Frame::Response { .. } => {}
        }
    }
    let unbinding = three.send_unbind(&request).await;
    answered_by!(three, unbinding, notices);
    // A call into a binding that is gone is refused, and the connection stays open.
    let id = three
        .send(RequestBody::Checkpoint {
            binding_id: first.binding_id.get(),
            deadline_ms: u64::try_from(HANG_GUARD.as_millis()).expect("milliseconds"),
        })
        .await;
    let gone = answered_by!(three, id, notices);
    assert!(
        matches!(
            gone,
            ResponseBody::Refused {
                disabled: false,
                ..
            }
        ),
        "a checkpoint of a binding that is gone was answered with {gone:?}"
    );

    // A checkpoint and a restore: the state comes back as the third protocol has it, and takes the
    // restore, which carries no registration and no position.
    let request = components::request("recording", 38);
    let registering = three.send_register(&request, &component).await;
    answered_by!(three, registering, notices);
    let id = three
        .send(RequestBody::Checkpoint {
            binding_id: request.binding_id.get(),
            deadline_ms: u64::try_from(HANG_GUARD.as_millis()).expect("milliseconds"),
        })
        .await;
    let checkpointed = answered_by!(three, id, notices);
    let ResponseBody::Called {
        value: Some(CallValue::State(state)),
        ..
    } = checkpointed
    else {
        panic!("a checkpoint was answered with {checkpointed:?}");
    };
    assert!(!state.is_empty(), "the checkpoint carried no state");
    let id = three
        .send(RequestBody::Restore {
            binding_id: request.binding_id.get(),
            state,
            deadline_ms: u64::try_from(HANG_GUARD.as_millis()).expect("milliseconds"),
        })
        .await;
    let restored = answered_by!(three, id, notices);
    assert!(
        matches!(
            restored,
            ResponseBody::Called {
                value: Some(CallValue::Document),
                fault: None,
                ..
            }
        ),
        "a restore was answered with {restored:?}"
    );

    // A queue that drops events behind a pass that has not taken any, and then refuses a request
    // it has no room for: the host tells the offerer of each, and later the reader of the loss.
    let mut stop = served
        .host
        .runtime()
        .stop_next_pump(request.binding_id)
        .expect("the binding is live");
    let big = "x".repeat(400 * 1024);
    let mut admissions = std::collections::BTreeSet::new();
    let mut offered = Vec::new();
    for index in 0..12 {
        offered.push(components::scrape(&format!("se-{index}"), &big));
    }
    for index in 0..24 {
        offered.push(components::native_request(
            &format!("se-{}", 100 + index),
            &format!("{}", 100 + index),
            &big,
        ));
    }
    for (at, event) in offered.iter().enumerate() {
        let id = three
            .send(RequestBody::Event {
                binding_id: request.binding_id.get(),
                event: wire_event(event),
            })
            .await;
        let admitted = answered_by!(three, id, notices);
        let ResponseBody::Admitted { admission, .. } = admitted else {
            panic!("an event was answered with {admitted:?}");
        };
        admissions.insert(admission);
        if at == 0 {
            assert!(
                tokio::time::timeout(HANG_GUARD, stop.reached())
                    .await
                    .expect("the binding's pass stands at the stop"),
                "the stop was replaced before a pass reached it"
            );
        }
    }
    assert!(
        admissions.contains("queued_with_gap") && admissions.contains("refused"),
        "the events were admitted as {admissions:?}"
    );
    stop.release();
    while !notices
        .iter()
        .any(|notice| matches!(notice, Notice::Gap { events, .. } if *events > 0))
    {
        match next_frame_of_three!(three) {
            Frame::Notice(notice) => notices.push(notice),
            Frame::Response { .. } => {}
        }
    }
    let unbinding = three.send_unbind(&request).await;
    answered_by!(three, unbinding, notices);

    assert!(
        notices
            .iter()
            .any(|notice| matches!(notice, Notice::Fault { .. })),
        "the third protocol was not told of the trap: {notices:?}"
    );
    // A report of what the instance consumed, written as a frame this protocol has, would be a gap
    // that lost nothing.
    assert!(
        notices.iter().all(|notice| !matches!(
            notice,
            Notice::Gap {
                events: 0,
                bytes: 0,
                documents: 0,
                ..
            }
        )),
        "the third protocol was told of a gap that lost nothing: {notices:?}"
    );
}

/// Floods a binding whose pass is held until its queue has dropped events, and returns the gap the
/// host wrote about them.
async fn gap_of_a_flood(open: bool, seed: u8) -> Option<Notice4> {
    let served = Served::start_dual(open).await;
    let component = recording(&served)?;
    let mut four = Raw4::connect(served.endpoint4()).await;
    let request = components::request("recording", seed);
    four.register(&request, &component, 7).await;
    let mut stop = served
        .host
        .runtime()
        .stop_next_pump(request.binding_id)
        .expect("the binding is live");
    // Twelve events of 400 KiB are more than the binding's queue holds, and the pass that would
    // empty it stands at its stop until the last one is admitted.
    let big = "x".repeat(400 * 1024);
    for index in 0..12 {
        four.event(&request, &format!("se-{index}"), &big).await;
    }
    assert!(
        tokio::time::timeout(HANG_GUARD, stop.reached())
            .await
            .expect("the binding's pass stands at the stop"),
        "the stop was replaced before a pass reached it"
    );
    stop.release();
    let notices = four
        .until(|notice| matches!(notice, Notice4::Gap { events, .. } if *events > 0))
        .await;
    notices
        .into_iter()
        .find(|notice| matches!(notice, Notice4::Gap { events, .. } if *events > 0))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_24_24_an_open_host_names_the_first_and_last_event_a_gap_lost() {
    let Some(Notice4::Gap {
        registration,
        first,
        last,
        ..
    }) = gap_of_a_flood(true, 38).await
    else {
        return;
    };
    assert_eq!(registration, 7);
    assert_eq!(
        first,
        Some(handle("se-0")),
        "the oldest event was the first lost"
    );
    assert!(last.is_some(), "a gap that lost events names the last");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_24_24_a_closed_host_names_neither_the_first_nor_the_last_event_a_gap_lost() {
    let Some(Notice4::Gap {
        registration,
        first,
        last,
        ..
    }) = gap_of_a_flood(false, 39).await
    else {
        return;
    };
    assert_eq!(registration, 7);
    assert_eq!(
        (first, last),
        (None, None),
        "a closed host named a position"
    );
}

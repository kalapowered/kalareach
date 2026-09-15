//! The policy layer, side-effect routing and the byte policy the reducer sees.
//!
//! The question these tests ask is always the same one: can something leave the terminal that
//! nobody asked for? A clipboard write to a device the person is not using, a bell to every window,
//! a sequence applied to the canonical grid that policy refused.

use kr_protocol::ids::{AttachmentId, InputLeaseEpoch};
use kr_protocol::scalars::{U64, Uuid};
use kr_term::class::SequenceClass;
use kr_term::diag::DiagnosticKind;
use kr_term::engine::{Engine, EngineConfig};
use kr_term::event::DirectDisposition;
use kr_term::lane::LaneGate;
use kr_term::lexer::Lexer;
use kr_term::policy::Policy;
use kr_term::sideeffect::{
    ClipboardReadPolicy, ClipboardSelection, ClipboardWritePolicy, LeaseHolder,
    SideEffectDestination, SideEffectKind, SideEffectPolicy, SideEffectRefusal,
};

fn attachment() -> AttachmentId {
    AttachmentId::new(Uuid::from_bytes([7; 16]))
}

fn leased_engine() -> Engine {
    let mut engine = Engine::new(EngineConfig::default()).expect("engine");
    engine.set_lease_holder(LeaseHolder::new(attachment(), InputLeaseEpoch(U64::new(3))));
    engine
}

#[test]
fn a_bell_goes_to_the_lease_holder_and_nowhere_else() {
    let mut engine = leased_engine();
    let outcome = engine.feed(b"\x07", 0);
    assert_eq!(outcome.side_effects.len(), 1);
    assert_eq!(outcome.side_effects[0].kind, SideEffectKind::Bell);
    let SideEffectDestination::Attachment { id, epoch } = outcome.side_effects[0].destination
    else {
        panic!("a bell must name one attachment");
    };
    assert_eq!(id, attachment());
    assert_eq!(epoch, InputLeaseEpoch(U64::new(3)));
    assert!(outcome.forward.is_empty(), "the bell byte stops here");
}

#[test]
fn a_side_effect_without_a_lease_becomes_a_host_event() {
    let mut engine = Engine::new(EngineConfig::default()).expect("engine");
    let outcome = engine.feed(b"\x07", 0);
    assert_eq!(
        outcome.side_effects[0].destination,
        SideEffectDestination::HostEvent,
        "no lease means a durable host event, never a broadcast"
    );
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|d| d.kind == DiagnosticKind::SideEffectWithoutDestination)
    );
}

#[test]
fn a_clipboard_write_is_decoded_and_routed_to_one_destination() {
    let mut engine = leased_engine();
    let outcome = engine.feed(b"\x1b]52;c;c2VjcmV0\x1b\\", 0);
    assert_eq!(outcome.side_effects.len(), 1);
    assert_eq!(
        outcome.side_effects[0].kind,
        SideEffectKind::ClipboardWrite {
            selection: ClipboardSelection::Clipboard,
            content: b"secret".to_vec(),
        }
    );
    assert!(outcome.forward.is_empty());
}

/// An oversized clipboard write is rejected whole, never truncated into a shorter secret.
#[test]
fn an_oversized_clipboard_write_is_rejected_whole() {
    let mut engine = leased_engine();
    let mut input = b"\x1b]52;c;".to_vec();
    input.extend(std::iter::repeat_n(b'A', 900_000));
    input.extend_from_slice(b"\x1b\\");
    let policy = Policy {
        side_effects: SideEffectPolicy {
            max_clipboard_encoded: 1024,
            ..SideEffectPolicy::DEFAULT
        },
        ..Policy::DEFAULT
    };
    let mut bounded = Engine::new(EngineConfig {
        policy,
        ..EngineConfig::DEFAULT
    })
    .expect("engine");
    let outcome = bounded.feed(&input, 0);
    assert!(outcome.side_effects.is_empty(), "nothing is delivered");
    assert!(matches!(
        outcome.refusals.first(),
        Some(SideEffectRefusal::TooLarge { .. })
    ));
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|d| d.kind == DiagnosticKind::ClipboardWriteRejected)
    );

    // Past the lexer's own 1 MiB bound the string never becomes an OSC 52 at all.
    let mut huge = b"\x1b]52;c;".to_vec();
    huge.extend(std::iter::repeat_n(b'A', 1_100_000));
    huge.extend_from_slice(b"\x1b\\");
    let outcome = engine.feed(&huge, 0);
    assert!(outcome.side_effects.is_empty());
    assert!(outcome.forward.is_empty());
}

#[test]
fn a_clipboard_read_is_answered_empty_without_asking_anyone() {
    let mut engine = leased_engine();
    let outcome = engine.feed(b"\x1b]52;c;?\x1b\\", 0);
    assert!(
        outcome.side_effects.is_empty(),
        "the default read consults no client"
    );
    let replies = engine.lane_mut().drain(LaneGate::default(), 4096, 0);
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0].bytes(), b"\x1b]52;c;\x1b\\");
}

#[test]
fn a_policy_that_allows_reads_routes_them_to_the_lease_holder() {
    let policy = Policy {
        side_effects: SideEffectPolicy {
            clipboard_read: ClipboardReadPolicy::LeaseHolder,
            ..SideEffectPolicy::DEFAULT
        },
        ..Policy::DEFAULT
    };
    let mut engine = Engine::new(EngineConfig {
        policy,
        ..EngineConfig::DEFAULT
    })
    .expect("engine");
    engine.set_lease_holder(LeaseHolder::new(attachment(), InputLeaseEpoch(U64::new(1))));
    let outcome = engine.feed(b"\x1b]52;p;?\x1b\\", 0);
    assert_eq!(
        outcome.side_effects[0].kind,
        SideEffectKind::ClipboardRead {
            selection: ClipboardSelection::Primary
        }
    );
}

#[test]
fn a_denying_policy_refuses_the_write_and_says_so() {
    let policy = Policy {
        side_effects: SideEffectPolicy {
            clipboard_write: ClipboardWritePolicy::Deny,
            ..SideEffectPolicy::DEFAULT
        },
        ..Policy::DEFAULT
    };
    let mut engine = Engine::new(EngineConfig {
        policy,
        ..EngineConfig::DEFAULT
    })
    .expect("engine");
    let outcome = engine.feed(b"\x1b]52;c;c2VjcmV0\x1b\\", 0);
    assert!(outcome.side_effects.is_empty());
    assert_eq!(
        outcome.refusals.first(),
        Some(&SideEffectRefusal::PolicyDenied)
    );
}

#[test]
fn notifications_and_progress_are_recognised_by_subcommand() {
    let mut engine = leased_engine();
    let outcome = engine.feed(b"\x1b]777;notify;Title;Body\x1b\\", 0);
    assert_eq!(
        outcome.side_effects[0].kind,
        SideEffectKind::Notification {
            title: Some("Title".to_owned()),
            body: "Body".to_owned(),
        }
    );

    let outcome = engine.feed(b"\x1b]9;4;1;42\x1b\\", 0);
    assert_eq!(
        outcome.side_effects[0].kind,
        SideEffectKind::Progress {
            progress: kr_term::sideeffect::Progress::Percent(42)
        }
    );

    // An unrecognised subcommand is an extension, not a side effect of unknown shape.
    let outcome = engine.feed(b"\x1b]777;precmd\x1b\\", 0);
    assert!(outcome.side_effects.is_empty());
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|d| d.kind == DiagnosticKind::UnclassifiedSequence)
    );
}

/// The reducer cannot apply a sequence policy rejected, even when handed one directly.
#[test]
fn the_reducer_refuses_what_policy_refused() {
    let policy = Policy::DEFAULT;
    let mut lexer = Lexer::new();
    let mut events = Vec::new();
    // A query, a side effect and an extension: none of them may reach the grid.
    lexer.feed(b"\x1b[c\x07\x1b[?2027h\x1b_Gf=24;AAAA\x1b\\", &mut events);
    lexer.close(&mut events);
    assert!(!events.is_empty());
    for event in &events {
        assert_ne!(event.class, SequenceClass::Display);
        assert_ne!(event.class, SequenceClass::Mode);
        assert!(!policy.decide(event).apply_to_grid);
        assert!(
            kr_term::adapter::adapt(event).actions.is_empty(),
            "the adapter produces no action for {event:?}"
        );
    }
}

/// Malformed input moves the attachment to projected mode rather than reaching a terminal.
#[test]
fn malformed_input_requires_projection() {
    let mut engine = Engine::new(EngineConfig::default()).expect("engine");
    let outcome = engine.feed(b"ok\xed\xa0\x80more", 0);
    assert_eq!(
        outcome.projection_required_at,
        Some(2),
        "projection starts at the preceding safe cursor"
    );
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|d| d.kind == DiagnosticKind::MalformedUtf8)
    );
    // The good text on either side is still forwardable.
    assert!(!outcome.forward.is_empty());
}

/// No malformed byte ever reaches a physical terminal as an unclassified introducer.
#[test]
fn no_unclassified_introducer_is_ever_forwarded() {
    let inputs: [&[u8]; 6] = [
        b"\x9b31m",
        b"\x9d2;t\x07",
        b"\x90q\x1b\\",
        b"\x9f payload \x1b\\",
        b"\xc2\x9b31m",
        b"\x1b_Gf=24;AAAA\x1b\\",
    ];
    for input in inputs {
        let mut engine = Engine::new(EngineConfig::default()).expect("engine");
        let outcome = engine.feed(input, 0);

        let mut lexer = Lexer::new();
        let mut events = Vec::new();
        lexer.feed(input, &mut events);
        lexer.close(&mut events);
        assert!(!events.is_empty());

        for event in &events {
            if event.disposition == DirectDisposition::Forward {
                continue;
            }
            let start = event.span.start();
            let end = event.span.end();
            assert!(
                !outcome
                    .forward
                    .iter()
                    .any(|span| span.start() < end && start < span.end()),
                "{input:?}: a forwarded span overlaps a sequence that stops here: {event:?}"
            );
            if event.eight_bit_introducer {
                // Either rendered from canonical state or consumed outright. Neither path lets the
                // byte reach a terminal that would read it as an introducer.
                assert!(matches!(
                    event.disposition,
                    DirectDisposition::RequireProjection | DirectDisposition::Withhold
                ));
            }
        }
    }
}

/// Mode 9001 stops at the boundary that owns it and is never sent to a remote client.
#[test]
fn win32_input_mode_terminates_at_its_boundary() {
    let mut engine = Engine::new(EngineConfig::default()).expect("engine");
    let outcome = engine.feed(b"\x1b[?9001h", 0);
    assert!(outcome.forward.is_empty(), "never broadcast");
    assert!(
        !engine.modes().is_set(kr_term::modes::ModeKind::Dec, 9001),
        "a Unix backend does not enter win32 input mode"
    );

    let conpty = Policy {
        backend: kr_term::policy::Backend::ConPty,
        ..Policy::DEFAULT
    };
    let mut windows = Engine::new(EngineConfig {
        policy: conpty,
        ..EngineConfig::DEFAULT
    })
    .expect("engine");
    let outcome = windows.feed(b"\x1b[?9001h", 0);
    assert!(outcome.forward.is_empty(), "still never broadcast");
    assert!(
        windows.modes().win32_input(),
        "the worker records what its own ConPTY asked for"
    );
    // And it reports that honestly when asked.
    let replies = windows
        .lane_mut()
        .drain(kr_term::lane::LaneGate::default(), 4096, 0);
    assert!(replies.is_empty());
    windows.feed(b"\x1b[?9001$p", 0);
    let replies = windows
        .lane_mut()
        .drain(kr_term::lane::LaneGate::default(), 4096, 0);
    assert_eq!(replies[0].bytes(), b"\x1b[?9001;1$y");
}

/// The title stack is the session's own and cannot reach past it.
#[test]
fn the_title_stack_is_virtualised_and_bounded() {
    let mut engine = Engine::new(EngineConfig::default()).expect("engine");
    engine.feed(b"\x1b]2;outer\x07", 0);
    assert_eq!(engine.titles().window(), "outer");

    // Popping an empty stack leaves the session's own title alone.
    engine.feed(b"\x1b[23t\x1b[23t", 0);
    assert_eq!(engine.titles().window(), "outer");
    assert_eq!(engine.titles().underflows(), 2);

    // Pushing past the bound keeps the stack bounded.
    let mut input = Vec::new();
    for index in 0..40 {
        input.extend_from_slice(format!("\x1b]2;t{index}\x07\x1b[22t").as_bytes());
    }
    engine.feed(&input, 0);
    assert!(engine.titles().depth() <= kr_term::title::MAX_DEPTH);
}

/// Diagnostics are rate limited, and the suppressed count travels with the next one through.
#[test]
fn diagnostics_are_rate_limited_but_counted() {
    let mut engine = Engine::new(EngineConfig::default()).expect("engine");
    let mut input = Vec::new();
    for _ in 0..500 {
        input.extend_from_slice(b"\x1b[?77h");
    }
    let outcome = engine.feed(&input, 0);
    let unclassified = outcome
        .diagnostics
        .iter()
        .filter(|d| d.kind == DiagnosticKind::UnclassifiedSequence)
        .count();
    assert_eq!(unclassified, 1, "one diagnostic reached the status stream");
    let total = engine
        .diagnostic_totals()
        .into_iter()
        .find(|(kind, _)| *kind == DiagnosticKind::UnclassifiedSequence)
        .map(|(_, count)| count)
        .unwrap_or(0);
    assert_eq!(total, 500, "every occurrence is still counted");
}

/// Nothing the engine produces is ever written into the application's output stream.
#[test]
fn diagnostics_never_touch_the_output_stream() {
    let mut engine = Engine::new(EngineConfig::default()).expect("engine");
    let before = engine.output_cursor();
    let input = b"\x1b[?77h\x1b_Gf=1;A\x1b\\";
    engine.feed(input, 0);
    let consumed = engine.output_cursor() - before;
    assert_eq!(
        consumed,
        input.len() as u64,
        "the cursor advances by the input only"
    );
    assert_eq!(engine.grid().writer_log().bytes, 0);
}

// ------------------------------------------- behaviour the review found wrong

/// Title stack operations are the session's own and never reach the outer terminal's stack.
#[test]
fn title_stack_operations_are_not_forwarded() {
    let mut engine = Engine::new(EngineConfig::default()).expect("engine");
    let outcome = engine.feed(b"\x1b]2;inner\x07\x1b[22t\x1b[23t", 0);
    // The title itself travels, so an attach client can set the outer title under its own policy.
    assert!(!outcome.forward.is_empty());
    // The push and the pop do not.
    let forwarded: u64 = outcome.forward.iter().map(|span| span.len()).sum();
    assert_eq!(
        forwarded,
        b"\x1b]2;inner\x07".len() as u64,
        "only the OSC 2 sequence is forwarded, not the stack operations"
    );
}

/// A title may contain semicolons, and all of it is the title.
#[test]
fn a_title_keeps_everything_after_its_selector() {
    let mut engine = Engine::new(EngineConfig::default()).expect("engine");
    engine.feed(b"\x1b]2;one;two;three\x07", 0);
    assert_eq!(engine.titles().window(), "one;two;three");
}

/// A soft reset returns the primary screen and resets the projection with it.
#[test]
fn a_soft_reset_returns_the_primary_screen() {
    let mut engine = Engine::new(EngineConfig::default()).expect("engine");
    engine.feed(b"\x1b[?1049h", 0);
    assert!(engine.grid().alternate_active());
    assert!(engine.modes().is_set(kr_term::modes::ModeKind::Dec, 1049));

    let outcome = engine.feed(b"\x1b[!p", 0);
    assert!(
        !engine.grid().alternate_active(),
        "the grid is back on the primary screen"
    );
    assert!(
        !engine.modes().is_set(kr_term::modes::ModeKind::Dec, 1049),
        "and the tracked mode agrees with it"
    );
    assert!(outcome.projection_reset, "a client is told to start again");
}

/// A combined mode request keeps the modes that are not the backend's business.
#[test]
fn a_combined_request_containing_win32_input_keeps_its_other_modes() {
    let mut engine = Engine::new(EngineConfig::default()).expect("engine");
    let outcome = engine.feed(b"\x1b[?9001;1049h", 0);
    assert!(
        engine.grid().alternate_active(),
        "the alternate-screen half of the request still happened"
    );
    assert!(
        !engine.modes().is_set(kr_term::modes::ModeKind::Dec, 9001),
        "a Unix backend does not enter win32 input mode"
    );
    assert!(
        outcome.forward.is_empty(),
        "the request never travels onwards, because it names mode 9001"
    );
}

/// The keypad state has one owner, whichever sequence set it.
#[test]
fn the_keypad_state_has_one_owner() {
    let mut engine = Engine::new(EngineConfig::default()).expect("engine");
    engine.feed(b"\x1b=", 0);
    assert!(engine.modes().keypad_application());
    assert!(engine.modes().is_set(kr_term::modes::ModeKind::Dec, 66));

    engine.feed(b"\x1b[?66l", 0);
    assert!(!engine.modes().keypad_application());
}

/// A parameter no grid could act on is clamped before anything tries.
#[test]
fn an_enormous_parameter_is_bounded_before_the_grid_sees_it() {
    let mut engine = Engine::new(EngineConfig::default()).expect("engine");
    let started = std::time::Instant::now();
    // Forward tabulation, insert characters and repeat: each one loops per unit in the reducer.
    engine.feed(b"\x1b[4294967295I\x1b[4294967295@\x1b[4294967295b", 0);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "a few bytes of input must not buy unbounded work"
    );
}

/// Shell-integration sequences produce untrusted observations rather than authority.
#[test]
fn shell_integration_produces_untrusted_observations() {
    let mut engine = Engine::new(EngineConfig::default()).expect("engine");
    let outcome = engine.feed(
        b"\x1b]7;file://host/tmp\x1b\\\x1b]133;A\x1b\\\x1b]1337;CurrentDir=/srv\x1b\\",
        0,
    );
    let sources: Vec<kr_term::engine::ObservationSource> = outcome
        .observations
        .iter()
        .map(|observation| observation.source)
        .collect();
    assert_eq!(
        sources,
        vec![
            kr_term::engine::ObservationSource::WorkingDirectory,
            kr_term::engine::ObservationSource::PromptBoundary,
            kr_term::engine::ObservationSource::TerminalMetadata,
        ]
    );
    assert_eq!(outcome.observations[0].value, "file://host/tmp");
}

/// The session's hyperlink table is bounded, and passing the bound is visible.
#[test]
fn the_hyperlink_table_is_bounded() {
    let mut engine = Engine::new(EngineConfig::default()).expect("engine");
    let limit = engine.budget().limits().unique_links;
    let mut input = Vec::new();
    for index in 0..limit + 16 {
        input.extend_from_slice(
            format!("\x1b]8;;https://example.invalid/{index}\x1b\\x\x1b]8;;\x1b\\").as_bytes(),
        );
    }
    let outcome = engine.feed(&input, 0);
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|d| d.kind == DiagnosticKind::ResidentStateTruncated),
        "passing the bound is reported out of band"
    );
    assert!(engine.budget().truncations() > 0);
}

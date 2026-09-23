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

/// The keyboard state a snapshot of `engine` carries.
fn keyboard(engine: &mut Engine) -> kr_term::snapshot::KeyboardSnapshot {
    let size = engine.grid().size();
    let viewport = kr_term::snapshot::Viewport {
        top_row: 0,
        rows: size.rows,
        left_col: 0,
        cols: size.cols,
    };
    engine.snapshot(viewport, 0).0.keyboard
}

fn attachment() -> AttachmentId {
    AttachmentId::new(Uuid::from_bytes([7; 16]))
}

fn leased_engine() -> Engine {
    let mut engine = Engine::new(EngineConfig::default()).expect("engine");
    engine.set_lease_holder(LeaseHolder::new(attachment(), InputLeaseEpoch(U64::new(3))));
    engine
}

/// KR-REQ-08.38: the default destination of a side effect is the attachment holding the input
/// lease, at its epoch, and nothing of it is forwarded to anyone else.
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

/// KR-REQ-08.38: with no lease there is no destination, and the side effect becomes a host event
/// rather than a broadcast.
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

/// KR-REQ-08.06: a clipboard write is decoded and routed to one named attachment, never forwarded
/// in the output stream.
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

/// KR-REQ-08.06: the host policy decides whether a side effect is delivered at all, and a refusal
/// is reported rather than delivered somewhere else.
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
            id: None,
            urgency: kr_term::sideeffect::NotificationUrgency::Normal,
            display: kr_term::sideeffect::NotificationDisplay::Always,
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

    // A value that is present and invalid is not the same as one that was left out. Both of these
    // would otherwise take the omitted form's answer.
    for input in [
        b"\x1b]9;4;256\x07".as_slice(),
        b"\x1b]9;4;x\x07".as_slice(),
        b"\x1b]9;4;1;101\x07".as_slice(),
        b"\x1b]99;p=not-a-subcommand;hello\x07".as_slice(),
        b"\x1b]99;a=run-this;hello\x07".as_slice(),
    ] {
        let outcome = engine.feed(input, 0);
        assert!(
            outcome.side_effects.is_empty(),
            "{input:?} became a side effect"
        );
        assert!(
            outcome.forward.is_empty(),
            "{input:?} reached a physical terminal"
        );
    }

    // Qualified metadata reaches the destination rather than stopping at the boundary.
    let outcome = engine.feed(b"\x1b]99;i=build:o=invisible:u=2;Hello\x07", 0);
    assert_eq!(
        outcome.side_effects[0].kind,
        SideEffectKind::Notification {
            title: None,
            body: "Hello".to_owned(),
            id: Some("build".to_owned()),
            urgency: kr_term::sideeffect::NotificationUrgency::Critical,
            display: kr_term::sideeffect::NotificationDisplay::Invisible,
        }
    );

    // The qualified forms still work, including the one with no state at all.
    for input in [
        b"\x1b]9;4\x07".as_slice(),
        b"\x1b]9;4;0\x07".as_slice(),
        b"\x1b]99;i=note-1:p=title;Build\x07".as_slice(),
    ] {
        let outcome = engine.feed(input, 0);
        assert!(
            !outcome.side_effects.is_empty(),
            "{input:?} is a qualified notification"
        );
    }
}

/// KR-REQ-08.08: the reducer cannot apply a sequence policy rejected, even when handed one
/// directly.
#[test]
fn the_reducer_refuses_what_policy_refused() {
    let policy = Policy::DEFAULT;
    let mut lexer = Lexer::new();
    let mut events = Vec::new();
    let context = kr_term::adapter::AdaptContext { rows: 24, cols: 80 };
    // A query, a side effect and an extension: none of them may reach the grid.
    lexer.feed(b"\x1b[c\x07\x1b[?2027h\x1b_Gf=24;AAAA\x1b\\", &mut events);
    lexer.close(&mut events);
    assert!(!events.is_empty());
    for event in &events {
        assert_ne!(event.class, SequenceClass::Display);
        assert_ne!(event.class, SequenceClass::Mode);
        assert!(!policy.decide(event).apply_to_grid);
        assert!(
            kr_term::adapter::adapt(event, context).actions.is_empty(),
            "the adapter produces no action for {event:?}"
        );
    }
}

/// KR-REQ-08.08: what direct mode forwards is cut from the parser's own spans.
///
/// The bytes the engine hands on are exactly the bytes of the events policy forwarded, in order.
/// Each input here is one a second reading could frame differently: an escape that abandons a
/// title rather than doubling inside it, a raw string terminator inside a title's payload, and a
/// sequence split across two reads. The framing that decides what reaches a terminal counts
/// offsets; it never decides for itself where a control family begins or ends.
#[test]
fn what_is_forwarded_is_cut_from_the_parsers_own_spans() {
    let inputs: [&[&[u8]]; 3] = [
        &[b"\x1b]2;x\x1b\x1b]52;c;c2VjcmV0\x07after"],
        &[b"\x1b]0;a\x9cb\x07text"],
        &[b"a\x1b[1;3", b"1mb\x1b[6n\x07\x1b[?1049h\x1b_Gf=1;A\x1b\\c"],
    ];
    for reads in inputs {
        let whole: Vec<u8> = reads.concat();

        // What the one parse and the policy decided, read straight from the events.
        let policy = Policy::DEFAULT;
        let mut lexer = Lexer::new();
        let mut events = Vec::new();
        for read in reads {
            lexer.feed(read, &mut events);
        }
        lexer.close(&mut events);
        let decided: Vec<u8> = events
            .iter()
            .filter(|event| policy.decide(event).disposition == DirectDisposition::Forward)
            .flat_map(|event| event.raw().to_vec())
            .collect();

        // What the engine forwards, read back from the offsets it hands on.
        let mut engine = Engine::new(EngineConfig::default()).expect("engine");
        let mut spans = Vec::new();
        for read in reads {
            spans.extend(engine.feed(read, 0).forward);
        }
        spans.extend(engine.close(0).forward);
        let forwarded: Vec<u8> = spans
            .iter()
            .flat_map(|span| {
                let start = usize::try_from(span.start()).expect("a small offset");
                let end = usize::try_from(span.end()).expect("a small offset");
                whole[start..end].to_vec()
            })
            .collect();

        assert_eq!(
            forwarded,
            decided,
            "{}: the forwarded bytes are the forwarded events' own bytes",
            String::from_utf8_lossy(&whole).escape_debug()
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

/// KR-REQ-08.47: a batch direct mode cannot carry moves the attachment to projection at the safe
/// cursor before it, the malformed text is drawn as U+FFFD with a diagnostic out of band, and none
/// of the rejected bytes is forwarded.
#[test]
fn a_batch_direct_mode_cannot_carry_is_projected_with_replacement_characters() {
    let mut engine = Engine::new(EngineConfig::default()).expect("engine");
    // A surrogate, which is never valid UTF-8, between two runs of good text.
    let input = b"ok\xed\xa0\x80more";
    let outcome = engine.feed(input, 0);
    let settled = engine.quiesce(0);

    assert_eq!(
        outcome.projection_required_at,
        Some(2),
        "projection starts at the safe cursor before the malformed bytes"
    );
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == DiagnosticKind::MalformedUtf8),
        "the replacement is reported out of band"
    );
    for span in outcome.forward.iter().chain(settled.forward.iter()) {
        assert!(
            span.end() <= 2 || span.start() >= 5,
            "a forwarded span reaches into the malformed bytes: {span:?}"
        );
    }

    // The canonical grid, which is what a projected attachment is drawn from, holds U+FFFD where
    // the malformed bytes were and the good text on either side of them.
    let first: String = engine.grid().visible_rows()[0]
        .runs
        .iter()
        .map(|run| run.text.as_str())
        .collect();
    let first = first.trim_end();
    let between = first
        .strip_prefix("ok")
        .and_then(|rest| rest.strip_suffix("more"))
        .unwrap_or_else(|| panic!("the good text is kept around the replacement: {first:?}"));
    assert!(
        !between.is_empty() && between.chars().all(|c| c == '\u{fffd}'),
        "the malformed bytes are drawn as U+FFFD: {first:?}"
    );
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

/// KR-REQ-08.09: diagnostics are an out-of-band status stream, rate limited, with every occurrence
/// still counted.
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

/// KR-REQ-08.09: nothing the engine produces is ever written into the application's output
/// stream or painted into the grid; diagnostics travel out of band.
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

/// An engine with no input lease, for the cases that do not need one.
fn plain_engine() -> Engine {
    Engine::new(EngineConfig::default()).expect("engine")
}

/// A mode is forwarded live, including the keyboard flags a direct terminal has to follow.
///
/// The flags in force, that is. The push and the pop that put them there are the session's own
/// business; `an_application_that_works_the_keyboard_stack_takes_nothing_of_the_terminals_own`
/// covers those.
#[test]
fn the_keyboard_flags_in_force_are_forwarded_like_any_other_mode() {
    let mut engine = plain_engine();
    let outcome = engine.feed(b"\x1b[>4;2m\x1b[=3u", 0);
    assert_eq!(
        outcome.forward.len(),
        1,
        "both sequences are forwarded, as one span"
    );
    assert!(outcome.projection_required_at.is_none());
    // The grid library still never sees a key encoding.
    assert_eq!(engine.grid().unrecognised(), 0);

    // An unqualified resource or sublist still stops here.
    for input in [b"\x1b[>5;2m".as_slice(), b"\x1b[>4:99m".as_slice()] {
        let mut engine = plain_engine();
        let outcome = engine.feed(input, 0);
        assert!(outcome.forward.is_empty(), "{input:?} was forwarded");
    }
}

/// A parameter that selects an operation is never reduced to a different operation.
#[test]
fn a_selector_is_not_clamped_like_a_count() {
    let mut engine = kr_term::engine::Engine::new(kr_term::engine::EngineConfig {
        size: kr_term::budget::GridSize::new(2, 2),
        ..kr_term::engine::EngineConfig::DEFAULT
    })
    .expect("engine");
    engine.feed(b"AA\r\nBB\r\nCC\r\nDD", 0);
    engine.quiesce(0);
    let before: Vec<String> = engine
        .grid()
        .visible_rows()
        .iter()
        .map(|row| row.runs.iter().map(|run| run.text.as_str()).collect())
        .collect();
    engine.feed(b"\x1b[3J", 0);
    let after: Vec<String> = engine
        .grid()
        .visible_rows()
        .iter()
        .map(|row| row.runs.iter().map(|run| run.text.as_str()).collect())
        .collect();
    assert_eq!(before, after, "erasing the scrollback erased the screen");

    // A selector outside its own set is an extension, not a smaller selector.
    let outcome = engine.feed(b"\x1b[9J", 0);
    assert!(outcome.forward.is_empty());

    // Tab stops: clearing all of them is selector 3, which must not become selector 2.
    let mut engine = kr_term::engine::Engine::new(kr_term::engine::EngineConfig {
        size: kr_term::budget::GridSize::new(2, 2),
        ..kr_term::engine::EngineConfig::DEFAULT
    })
    .expect("engine");
    engine.feed(b"\x1b[2G\x1bH\x1b[3g", 0);
    assert!(
        engine.grid().tab_stops().is_empty(),
        "every tab stop is cleared"
    );
}

/// A hyperlink target may contain the separator that divides the fields around it.
#[test]
fn a_hyperlink_target_keeps_its_semicolons() {
    let mut engine = plain_engine();
    engine.feed(
        b"\x1b]8;;https://example.invalid/a;b\x1b\\X\x1b]8;;\x1b\\",
        0,
    );
    engine.quiesce(0);
    let rows = engine.grid().visible_rows();
    let link = rows[0]
        .runs
        .iter()
        .find_map(|run| run.hyperlink.clone())
        .expect("the link survived");
    assert_eq!(link, "https://example.invalid/a;b");
}

/// A selective title push saves only what it names, and a pop restores only what was saved.
#[test]
fn a_selective_title_save_leaves_the_other_title_alone() {
    let mut engine = plain_engine();
    engine.feed(
        b"\x1b]0;initial\x07\x1b[22;1t\x1b]0;second\x07\x1b[22;2t\x1b]0;third\x07\x1b[23;1t\x1b[23;2t",
        0,
    );
    let size = engine.grid().size();
    let view = kr_term::snapshot::Viewport {
        top_row: 0,
        rows: size.rows,
        left_col: 0,
        cols: size.cols,
    };
    let (snapshot, _) = engine.snapshot(view, 0);
    assert_eq!(
        (snapshot.title.icon.as_str(), snapshot.title.window.as_str()),
        ("initial", "third"),
        "the icon pop finds the entry that saved an icon, and the window title is untouched"
    );
}

/// A control that arrives inside a sequence still happens, and so does the sequence.
#[test]
fn an_embedded_control_is_performed_where_it_appears() {
    fn engine_at(cols: u32, rows: u32) -> Engine {
        let mut engine = Engine::new(EngineConfig {
            size: kr_term::budget::GridSize::new(cols, rows),
            ..EngineConfig::DEFAULT
        })
        .expect("engine");
        engine.set_lease_holder(LeaseHolder::new(attachment(), InputLeaseEpoch(U64::new(3))));
        engine
    }

    // A bell inside a cursor movement rings once, and the movement still happens.
    let mut engine = engine_at(20, 3);
    let outcome = engine.feed(b"\x1b[5\x07C", 0);
    assert_eq!(
        engine.grid().cursor(),
        (5, 0),
        "the movement still happened"
    );
    assert_eq!(outcome.side_effects.len(), 1, "the bell still rang");
    assert!(
        outcome.forward.is_empty() && outcome.projection_required_at.is_some(),
        "the bytes stop here, so nothing performs the bell twice"
    );

    // So does a line feed.
    let mut engine = engine_at(20, 3);
    engine.feed(b"\x1b[5\nC", 0);
    assert_eq!(engine.grid().cursor(), (5, 1));

    // Every control is performed, however many there are, and the sequence still happens.
    let mut engine = engine_at(20, 3);
    let outcome = engine.feed(b"\x1b[5\x07\x07\x07\x07\x07\x07\x07\x07\x07C", 0);
    assert!(outcome.forward.is_empty());
    assert_eq!(outcome.side_effects.len(), 9, "every bell rang");
    assert_eq!(engine.grid().cursor(), (5, 0), "and the movement happened");
}

/// An application's Kitty keyboard stack operations never reach a direct attachment's terminal.
///
/// The stack that terminal holds belongs to whatever was running when the attachment arrived. A
/// push would bury an entry it had saved and a pop would take one, so the session keeps a stack of
/// its own and the attachment projects instead. What the terminal needs — the flags in force — is
/// installed as a state by the restoration that projection produces.
#[test]
fn an_application_that_works_the_keyboard_stack_takes_nothing_of_the_terminals_own() {
    let mut engine = leased_engine();

    // A push. The bytes stop here and the attachment projects.
    let outcome = engine.feed(b"\x1b[>5u", 0);
    assert!(
        outcome.forward.is_empty(),
        "a push must not reach a terminal that has a stack of its own"
    );
    assert!(outcome.projection_required_at.is_some());
    assert_eq!(keyboard(&mut engine).primary.flags, Some(5));
    assert_eq!(keyboard(&mut engine).primary.stack, vec![0]);

    // Another push, then a pop: the flags go back to what the first push installed, and neither
    // sequence travels.
    let outcome = engine.feed(b"\x1b[>3u", 0);
    assert!(outcome.forward.is_empty());
    assert_eq!(keyboard(&mut engine).primary.flags, Some(3));
    let outcome = engine.feed(b"\x1b[<1u", 0);
    assert!(
        outcome.forward.is_empty(),
        "a pop must not reach a terminal that has a stack of its own"
    );
    assert!(outcome.projection_required_at.is_some());
    let snapshot = keyboard(&mut engine);
    assert_eq!(
        (snapshot.primary.flags, snapshot.primary.stack),
        (Some(5), vec![0]),
        "the pop put back what the session had, through the session's own stack"
    );

    // A pop deeper than the session ever pushed empties the session's stack and nothing else.
    let outcome = engine.feed(b"\x1b[<65535u", 0);
    assert!(
        outcome.forward.is_empty(),
        "a pop past the session's own stack must not reach the terminal's"
    );
    let snapshot = keyboard(&mut engine);
    assert_eq!(snapshot.primary.flags, None);
    assert!(snapshot.primary.stack.is_empty());

    // And the flags a direct terminal needs still arrive, because an absolute setting is not a
    // stack operation and is forwarded live.
    let outcome = engine.feed(b"\x1b[=5;1u", 0);
    assert_eq!(
        outcome.forward.len(),
        1,
        "the flags in force still reach a direct terminal"
    );
    assert_eq!(keyboard(&mut engine).primary.flags, Some(5));

    // A push the profile does not qualify changed nothing, so it needs no projection either.
    let outcome = engine.feed(b"\x1b[>16u", 0);
    assert!(
        outcome.forward.is_empty(),
        "an unqualified flag is consumed"
    );
    assert!(
        outcome.projection_required_at.is_none(),
        "and it changed nothing, so nothing has to repaint"
    );
}

/// Each buffer's keyboard stack is its own, and neither reaches a terminal.
#[test]
fn the_alternate_buffers_keyboard_stack_is_not_the_shells() {
    let mut engine = leased_engine();
    engine.feed(b"\x1b[>1u", 0);
    engine.feed(b"\x1b[?1049h", 0);
    let outcome = engine.feed(b"\x1b[>9u", 0);
    assert!(outcome.forward.is_empty());

    let snapshot = keyboard(&mut engine);
    assert_eq!(snapshot.primary.flags, Some(1));
    assert_eq!(snapshot.alternate.flags, Some(9));
    assert_eq!(snapshot.alternate.stack, vec![0]);

    // A full-screen application emptying its own stack on the way out takes nothing of the
    // shell's, and nothing of the terminal's either.
    let outcome = engine.feed(b"\x1b[<65535u", 0);
    assert!(outcome.forward.is_empty());
    engine.feed(b"\x1b[?1049l", 0);
    let snapshot = keyboard(&mut engine);
    assert_eq!(
        snapshot.primary.flags,
        Some(1),
        "what the shell negotiated is still what the shell negotiated"
    );
}

//! The wire between the control daemon and the description process: section 23's frame over the
//! child's standard input and output, and what a reader does with a stream that ends or lies.

use std::io::Cursor;

use kr_describe::prompt::{Datum, Prompt, PromptKind};
use kr_describe::wire::{
    Answer, AssetFile, Background, JobEnd, JobLimits, LoadEnd, Phases, Request, VerifyResult,
    WIRE_VERSION, WireError, frame_of, read_frame, read_message, same_release, write_message,
};
use kr_protocol::frame::FrameError;
use kr_protocol::identity::{ProcessStartIdentity, ProcessStartSource};
use kr_protocol::scalars::{Bytes, Nullable, U64};

fn every_request() -> Vec<Request> {
    vec![
        Request::Hello {
            build: "kr-controller/0.1.0".to_owned(),
            wire: U64::new(WIRE_VERSION),
        },
        Request::Load {
            id: U64::new(1),
            profile_id: "minicpm5-2b-q4-k-m".to_owned(),
            revision: U64::new(1),
            assets: vec![AssetFile {
                file_name: "MiniCPM5-2B-Q4_K_M.gguf".to_owned(),
                path: "/state/models/minicpm5-2b-q4-k-m/1/MiniCPM5-2B-Q4_K_M.gguf".to_owned(),
            }],
            deadline_ms: U64::new(300_000),
        },
        Request::Generate {
            id: U64::new(2),
            prompt: Prompt {
                kind: PromptKind::Description,
                revision: U64::new(3),
                cursor_from: U64::new(1),
                cursor_to: U64::new(4),
                facts: vec![Datum {
                    label: "directory".to_owned(),
                    text: "kalareach".to_owned(),
                }],
                events: Vec::new(),
            },
            grammar: "root ::= \"{\"".to_owned(),
            limits: JobLimits {
                context_tokens: U64::new(4_096),
                max_output_tokens: U64::new(128),
                prompt_tokens: U64::new(891),
                cpu_threads: U64::new(4),
            },
            deadline_ms: U64::new(30_000),
            ceiling_bytes: U64::new(4 << 30),
        },
        Request::Generate {
            id: U64::new(4),
            prompt: Prompt {
                kind: PromptKind::Summary,
                revision: U64::new(0),
                cursor_from: U64::new(10),
                cursor_to: U64::new(14),
                facts: Vec::new(),
                events: vec![Datum {
                    label: "change command_completed".to_owned(),
                    text: "cargo test exited 0".to_owned(),
                }],
            },
            grammar: kr_describe::output::SUMMARY_GRAMMAR.to_owned(),
            limits: JobLimits {
                context_tokens: U64::new(4_096),
                max_output_tokens: U64::new(128),
                prompt_tokens: U64::new(891),
                cpu_threads: U64::new(4),
            },
            deadline_ms: U64::new(30_000),
            ceiling_bytes: U64::new(4 << 30),
        },
        Request::Verify {
            id: U64::new(3),
            profile_id: "minicpm5-2b-q4-k-m".to_owned(),
            revision: U64::new(1),
            file_name: "MiniCPM5-2B-Q4_K_M.gguf".to_owned(),
            path: "/state/models/minicpm5-2b-q4-k-m/1/MiniCPM5-2B-Q4_K_M.gguf.partial".to_owned(),
            deadline_ms: U64::new(600_000),
        },
        Request::Cancel { id: U64::new(2) },
    ]
}

fn every_answer() -> Vec<Answer> {
    vec![
        Answer::Ready {
            build: "kr-describe-inference/0.1.0".to_owned(),
            wire: U64::new(WIRE_VERSION),
            target: "aarch64-apple-darwin".to_owned(),
            identity: Nullable::some(ProcessStartIdentity::new(
                4_242,
                ProcessStartSource::MacosProcBsdInfo,
                1_700_000_000,
            )),
            background: Background {
                mechanism: "lowest_thread_priority".to_owned(),
                cpu: true,
                io: false,
                why: Nullable::null(),
            },
            ceiling: "sampler".to_owned(),
        },
        Answer::Loaded {
            id: U64::new(1),
            load_ms: U64::new(12_700),
            rss_bytes: U64::new(2_620_000_000),
        },
        Answer::LoadEnded {
            id: U64::new(1),
            why: LoadEnd::LockHeld,
            detail: Nullable::some("another process holds the lock".to_owned()),
        },
        Answer::Produced {
            id: U64::new(2),
            bytes: Bytes::from(b"{\"title\":\"kalareach\"}".to_vec()),
            phases: Phases {
                prompt_tokens: U64::new(300),
                prompt_ms: U64::new(900),
                sampling_ms: U64::new(40),
                decode_ms: U64::new(2_100),
            },
            peak_rss_bytes: U64::new(2_930_000_000),
        },
        Answer::Cancelling { id: U64::new(2) },
        Answer::Ended {
            id: U64::new(2),
            why: JobEnd::Cancelled,
            detail: Nullable::null(),
        },
        Answer::Verified {
            id: U64::new(3),
            result: VerifyResult::Mismatch,
            detail: Nullable::some("the digest is not the recorded one".to_owned()),
        },
    ]
}

/// Every request and every answer crosses the wire unchanged, one frame each, in order.
#[test]
fn every_request_and_answer_crosses_the_wire_unchanged() {
    let mut stream = Vec::new();
    for request in every_request() {
        write_message(&mut stream, &request).expect("a request is written");
    }
    let mut reader = Cursor::new(stream);
    for expected in every_request() {
        let read: Request = read_message(&mut reader)
            .expect("a request is read")
            .expect("a whole frame");
        assert_eq!(read, expected);
    }
    assert!(
        read_message::<Request>(&mut reader)
            .expect("the end")
            .is_none(),
        "a stream that ends between frames is a clean end"
    );

    let mut stream = Vec::new();
    for answer in every_answer() {
        stream.extend(frame_of(&answer).expect("an answer is framed"));
    }
    let mut reader = Cursor::new(stream);
    for expected in every_answer() {
        let read: Answer = read_message(&mut reader)
            .expect("an answer is read")
            .expect("a whole frame");
        assert_eq!(read, expected);
    }
}

/// A stream that ends inside a frame is a truncated frame, never a clean end, whether it stopped
/// inside the length or inside the payload; the control is the same frame whole.
#[test]
fn a_stream_that_ends_inside_a_frame_is_a_truncated_frame() {
    let whole = frame_of(&every_answer()[1]).expect("a frame");
    assert!(
        read_frame(&mut Cursor::new(whole.clone()))
            .expect("the whole frame")
            .is_some(),
        "the whole frame is read"
    );
    for cut in [1, 3, 4, 5, whole.len() - 1] {
        let error = read_frame(&mut Cursor::new(whole[..cut].to_vec()))
            .expect_err("a frame cut short is refused");
        assert!(
            matches!(error, WireError::Truncated { read, expected } if read == cut && expected >= cut),
            "{cut} bytes of {}: {error}",
            whole.len()
        );
    }
}

/// A declared length past the control bound is refused before a byte of the payload is read.
#[test]
fn a_length_past_the_bound_is_refused_before_the_payload_is_read() {
    let mut stream = (2_u32 * 1024 * 1024).to_be_bytes().to_vec();
    stream.extend(std::iter::repeat_n(0_u8, 16));
    let mut reader = Cursor::new(stream);
    let error = read_frame(&mut reader).expect_err("the length is refused");
    assert!(
        matches!(error, WireError::Frame(FrameError::PayloadTooLarge { .. })),
        "{error}"
    );
    assert_eq!(reader.position(), 4, "nothing past the length was read");
}

/// A whole frame whose payload is not a message of this wire is refused: bytes that are not
/// KR-CBOR-1, and a message with a field this wire does not have.
#[test]
fn a_frame_that_is_not_a_message_of_this_wire_is_refused() {
    let garbage = kr_protocol::frame::FrameCodec::new(kr_protocol::frame::StreamKind::Control)
        .encode(&[0xff, 0x00, 0x13])
        .expect("a frame");
    assert!(matches!(
        read_message::<Answer>(&mut Cursor::new(garbage)),
        Err(WireError::Frame(FrameError::Cbor(_)))
    ));

    #[derive(serde::Serialize)]
    struct Stranger {
        kind: &'static str,
        id: U64,
        why: JobEnd,
        detail: Nullable<String>,
        confidence: U64,
    }
    let stranger = frame_of(&Stranger {
        kind: "ended",
        id: U64::new(2),
        why: JobEnd::Failed,
        detail: Nullable::null(),
        confidence: U64::new(9),
    })
    .expect("a frame");
    assert!(matches!(
        read_message::<Answer>(&mut Cursor::new(stranger)),
        Err(WireError::Frame(FrameError::Cbor(_)))
    ));
}

/// The daemon speaks to a process of its own release, and to no other.
#[test]
fn the_daemon_speaks_only_to_a_process_of_its_own_release() {
    let release = env!("CARGO_PKG_VERSION");
    assert!(same_release(&format!("kr-describe-inference/{release}")));
    assert!(same_release(&format!("kr-describe-stub/{release}")));
    assert!(!same_release("kr-describe-inference/0.0.0-other"));
    assert!(!same_release("kr-describe-inference"));
    assert!(!same_release(""));
}

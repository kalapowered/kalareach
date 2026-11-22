//! What the names of an invocation's data pipes are: 128 random bits, a fixed prefix, no path and no
//! host, and a name the client's reply can carry.

use kr_boundary_windows::channel::{is_data_pipe_name, pipe_names};
use kr_boundary_windows::frame::invocation::{
    InvocationId, InvocationReply, MAX_PIPE_NAME_BYTES, read_reply, write_reply,
};

const BITS: [u8; 16] = [
    0x00, 0x01, 0x02, 0x0a, 0x0b, 0x0c, 0xf0, 0xf1, 0xf2, 0xfe, 0xff, 0x10, 0x20, 0x30, 0x40, 0x50,
];

#[test]
fn the_names_carry_the_bits_in_lowercase_hexadecimal_and_say_which_stream_they_are() {
    let names = pipe_names(BITS);
    assert_eq!(
        names.stdout,
        r"\\.\pipe\KalaReachBoundary-0001020a0b0cf0f1f2feff1020304050-out"
    );
    assert_eq!(
        names.stderr,
        r"\\.\pipe\KalaReachBoundary-0001020a0b0cf0f1f2feff1020304050-err"
    );
    assert_ne!(names, pipe_names([7; 16]));
}

#[test]
fn a_name_the_broker_makes_is_a_data_pipe_name_and_nothing_else_is() {
    let names = pipe_names(BITS);
    assert!(is_data_pipe_name(&names.stdout));
    assert!(is_data_pipe_name(&names.stderr));
    for refused in [
        r"\\.\pipe\KalaReachBoundaryPersons",
        r"\\.\pipe\KalaReachBoundaryAdministrators",
        r"\\host\pipe\KalaReachBoundary-0001020a0b0cf0f1f2feff1020304050-out",
        r"\\.\pipe\..\KalaReachBoundary-0001020a0b0cf0f1f2feff1020304050-out",
        r"\\.\pipe\KalaReachBoundary-0001020a0b0cf0f1f2feff1020304050-in",
        r"\\.\pipe\KalaReachBoundary-0001020A0B0CF0F1F2FEFF1020304050-out",
        r"\\.\pipe\KalaReachBoundary-0001020a0b0cf0f1f2feff10203040-out",
        r"\\.\pipe\KalaReachBoundary-0001020a0b0cf0f1f2feff102030405000-out",
        r"\\.\pipe\KalaReachBoundary-0001020a0b0cf0f1f2feff1020304050-out\x",
        r"\\.\pipe\KalaReachBoundary-0001020a0b0cf0f1f2feff1020304050\-out",
        r"pipe\KalaReachBoundary-0001020a0b0cf0f1f2feff1020304050-out",
        "",
    ] {
        assert!(!is_data_pipe_name(refused), "{refused}");
    }
}

#[test]
fn the_names_fit_the_reply_that_carries_them() {
    let names = pipe_names(BITS);
    assert!(names.stdout.len() <= MAX_PIPE_NAME_BYTES);
    let reply = InvocationReply::Accepted {
        invocation: InvocationId::from_bytes(BITS),
        stdout_pipe: names.stdout.clone(),
        stderr_pipe: names.stderr.clone(),
    };
    let mut bytes = Vec::new();
    write_reply(&mut bytes, &reply).expect("the reply is written");
    assert_eq!(
        read_reply(&mut bytes.as_slice()).expect("the reply is read"),
        reply
    );
}

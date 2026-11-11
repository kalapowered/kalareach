//! The broker's pipe protocol: framed messages, the limits that bound them, and the requests the
//! broker answers.
//!
//! A frame is a four-byte little-endian length and that many bytes of JSON. The length is checked
//! against [`MAX_FRAME`] before any byte of the body is read or allocated, so a client cannot make
//! the broker hold more than one frame's limit. The one request that carries a list of paths and a
//! message, [`invocation::OperateRequest`], has a limit of its own, [`invocation::MAX_OPERATE_FRAME`], which
//! [`invocation::read_request`] applies to it and to no other request. The first frame of every connection says
//! which version of this protocol the client speaks; a broker and a host update apart, so a version
//! the broker does not speak is refused with the instruction to repair.
//!
//! A message names no process, token, program, variable, configuration option or handle, and a
//! field the protocol does not name is a parse error. The broker takes the caller's identity from
//! the pipe, never from the message.
//!
//! The frames of an invocation ([`invocation::InvocationRequest`] and [`invocation::InvocationReply`]) are bounded field by
//! field as well: each has a `check` that the readers call, and the writers refuse to send what it
//! refuses.

use std::io::{self, Read, Write};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub mod invocation;

/// The version of this protocol.
pub const VERSION: u32 = 1;

/// The most bytes one frame may carry.
pub const MAX_FRAME: usize = 16 * 1024;

/// A frame that could not be read or written.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// The peer ended the connection between frames.
    #[error("the connection ended")]
    Closed,
    /// The frame is longer than the limit allows.
    #[error("a frame of {0} bytes is longer than the limit")]
    TooLong(usize),
    /// The frame's body is not a message of this protocol.
    #[error("the message is not one this protocol carries: {0}")]
    Malformed(String),
    /// A field of the message is outside its bounds.
    #[error("{0}")]
    Field(#[from] FieldError),
    /// The connection failed.
    #[error("the connection failed: {0}")]
    Io(#[from] io::Error),
}

/// A field of a message that is outside its bounds.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum FieldError {
    /// A text is longer than its limit.
    #[error("the {field} is {got} long and the limit is {max}")]
    TooLong {
        /// Which field.
        field: &'static str,
        /// The limit.
        max: usize,
        /// The length it has.
        got: usize,
    },
    /// A list has more items than its limit.
    #[error("there are {got} {field} and the limit is {max}")]
    TooMany {
        /// Which field.
        field: &'static str,
        /// The limit.
        max: usize,
        /// The count it has.
        got: usize,
    },
    /// A text holds a character that its field may not hold, or is empty where it may not be.
    #[error("the {field} is not in the form this protocol carries")]
    Form {
        /// Which field.
        field: &'static str,
    },
    /// A text that a person reads holds a character that is not printable ASCII.
    #[error("the {field} is not printable text")]
    NotPrintable {
        /// Which field.
        field: &'static str,
    },
}

/// Writes one message as a frame.
///
/// # Errors
///
/// Returns [`FrameError::TooLong`] for a message over the limit and [`FrameError::Io`] when the
/// connection fails.
pub fn write<W: Write, T: Serialize>(writer: &mut W, message: &T) -> Result<(), FrameError> {
    write_within(writer, message, MAX_FRAME)
}

/// Reads one frame and the message in it.
///
/// # Errors
///
/// Returns [`FrameError::Closed`] when the peer ended the connection before a frame began,
/// [`FrameError::TooLong`] before reading the body of a frame over the limit,
/// [`FrameError::Malformed`] for a body that is not a message, and [`FrameError::Io`] for a
/// connection that failed or ended inside a frame.
pub fn read<R: Read, T: DeserializeOwned>(reader: &mut R) -> Result<T, FrameError> {
    let body = read_body(reader, MAX_FRAME)?;
    serde_json::from_slice(&body).map_err(|error| FrameError::Malformed(error.to_string()))
}

fn write_within<W: Write, T: Serialize>(
    writer: &mut W,
    message: &T,
    limit: usize,
) -> Result<(), FrameError> {
    let body =
        serde_json::to_vec(message).map_err(|error| FrameError::Malformed(error.to_string()))?;
    if body.len() > limit {
        return Err(FrameError::TooLong(body.len()));
    }
    let length = u32::try_from(body.len()).map_err(|_| FrameError::TooLong(body.len()))?;
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&length.to_le_bytes());
    frame.extend_from_slice(&body);
    writer.write_all(&frame)?;
    writer.flush()?;
    Ok(())
}

fn read_body<R: Read>(reader: &mut R, limit: usize) -> Result<Vec<u8>, FrameError> {
    let mut length = [0_u8; 4];
    let mut got = 0;
    while got < length.len() {
        match reader.read(&mut length[got..]) {
            Ok(0) if got == 0 => return Err(FrameError::Closed),
            Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into()),
            Ok(count) => got += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    let length = u32::from_le_bytes(length) as usize;
    if length > limit {
        return Err(FrameError::TooLong(length));
    }
    let mut body = vec![0_u8; length];
    reader.read_exact(&mut body)?;
    Ok(body)
}

/// Which boundary account an operation runs as.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Class {
    /// The checkout and apply account, which runs Git alone.
    Checkout,
    /// The connection account, which runs Git, its transport programs and the credential helper.
    Connect,
}

/// What a client asks the broker.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "request", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Request {
    /// The first frame of every connection.
    Hello {
        /// The protocol version the client speaks.
        version: u32,
    },
    /// What state the broker is in. The braces keep the request a record, so that a field the
    /// protocol does not name is refused here as it is everywhere else.
    Status {},
    /// Turns the maintenance state on or off. An administrator only.
    Maintenance {
        /// Whether the broker refuses new invocations.
        on: bool,
    },
    /// Proves that the policy refuses an unlisted program to a class's token and runs a listed
    /// one. An administrator only.
    Prove {
        /// The account to prove.
        class: Class,
    },
    /// Proves that a program the policy refused runs again for a class's token, which is how
    /// removal shows that the boundary is released. An administrator only.
    Release {
        /// The account to prove.
        class: Class,
    },
}

/// Why the broker refused a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Refusal {
    /// The client speaks another protocol version.
    Version,
    /// The caller is not who the request needs.
    Caller,
    /// The broker is in the maintenance state.
    Maintenance,
    /// The request is not one the broker answers.
    Malformed,
    /// The request failed.
    Failed,
}

/// What the broker answers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "answer", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Response {
    /// The broker's own version, answering a `hello`.
    Hello {
        /// The protocol version the broker speaks.
        version: u32,
    },
    /// The broker's state.
    Status {
        /// Whether the broker refuses new invocations.
        maintenance: bool,
    },
    /// The request was carried out.
    Done {},
    /// The result of a proof.
    Proof {
        /// Whether the policy refused the unlisted program to this class and the listed program ran.
        ready: bool,
        /// What the proof saw, in a form a person can read.
        detail: String,
    },
    /// The request was refused.
    Refused {
        /// The kind of refusal.
        reason: Refusal,
        /// What was refused and why.
        detail: String,
    },
}

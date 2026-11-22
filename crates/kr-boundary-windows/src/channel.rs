//! The names of an invocation's data pipes and the time the broker waits for the client to connect
//! to them.
//!
//! The broker makes one named pipe for the standard output and one for the standard error of every
//! invocation, and tells the client their names. A name carries 128 random bits so that no other
//! program can guess it before the client opens it, and no path and no host, so that it names a pipe
//! of this computer and nothing else.

use std::time::Duration;

/// How long the broker waits for the client to connect to both pipes before it ends the invocation.
pub const CONNECT_BOUND: Duration = Duration::from_secs(10);

/// What every data pipe's name starts with.
const PREFIX: &str = r"\\.\pipe\KalaReachBoundary-";
const OUT: &str = "-out";
const ERR: &str = "-err";
const DIGITS: usize = 32;

/// The names of one invocation's two data pipes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PipeNames {
    /// The pipe that carries Git's standard output.
    pub stdout: String,
    /// The pipe that carries Git's standard error.
    pub stderr: String,
}

/// The names that 128 random bits make.
#[must_use]
pub fn pipe_names(bits: [u8; 16]) -> PipeNames {
    let digits = hex::encode(bits);
    PipeNames {
        stdout: format!("{PREFIX}{digits}{OUT}"),
        stderr: format!("{PREFIX}{digits}{ERR}"),
    }
}

/// Whether a text is the name of a data pipe: the fixed prefix, 32 lowercase hexadecimal digits and
/// one of the two endings, with no path and no host.
#[must_use]
pub fn is_data_pipe_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix(PREFIX) else {
        return false;
    };
    let Some(digits) = rest.strip_suffix(OUT).or_else(|| rest.strip_suffix(ERR)) else {
        return false;
    };
    digits.len() == DIGITS
        && digits
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

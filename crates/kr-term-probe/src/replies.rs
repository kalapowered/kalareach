//! Reading what a terminal writes back.
//!
//! A terminal answers a question with a control sequence of its own, and the answers to several
//! questions asked together arrive as one run of bytes. Each reader here looks through that run for
//! the one reply it is after and ignores the rest, which is also how it copes with a terminal that
//! adds something nobody asked for.

/// Where a terminal says its cursor is, one-based, as the reply to the cursor position report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct Position {
    /// The row, counted from one.
    pub row: u32,
    /// The column, counted from one.
    pub col: u32,
}

/// The parameters of the first `CSI <numbers> <final>` in `bytes`, with `introducer` between the
/// bracket and the numbers (`?` or `>` for the private forms, nothing for the plain one).
fn csi(bytes: &[u8], introducer: Option<u8>, last: u8) -> Option<Vec<u32>> {
    let mut at = 0;
    while at + 1 < bytes.len() {
        if bytes[at] == 0x1b && bytes[at + 1] == b'[' {
            let mut end = at + 2;
            if let Some(byte) = introducer {
                if bytes.get(end) != Some(&byte) {
                    at += 1;
                    continue;
                }
                end += 1;
            }
            let start = end;
            while end < bytes.len() && (bytes[end].is_ascii_digit() || bytes[end] == b';') {
                end += 1;
            }
            if bytes.get(end) == Some(&last) {
                let text = std::str::from_utf8(&bytes[start..end]).ok()?;
                return text
                    .split(';')
                    .map(|part| {
                        if part.is_empty() {
                            Some(0)
                        } else {
                            part.parse().ok()
                        }
                    })
                    .collect();
            }
        }
        at += 1;
    }
    None
}

/// The cursor position the run of bytes reports, if it holds a report.
#[must_use]
pub fn cursor_position(bytes: &[u8]) -> Option<Position> {
    match csi(bytes, None, b'R')?.as_slice() {
        [row, col] => Some(Position {
            row: *row,
            col: *col,
        }),
        _ => None,
    }
}

/// The reply to primary device attributes, which ends every read.
#[must_use]
pub fn primary_attributes(bytes: &[u8]) -> Option<Vec<u32>> {
    csi(bytes, Some(b'?'), b'c')
}

/// The reply to secondary device attributes.
#[must_use]
pub fn secondary_attributes(bytes: &[u8]) -> Option<Vec<u32>> {
    csi(bytes, Some(b'>'), b'c')
}

/// The size in cells the terminal says its window has, as `(rows, columns)`.
#[must_use]
pub fn window_size(bytes: &[u8]) -> Option<(u32, u32)> {
    match csi(bytes, None, b't')?.as_slice() {
        [8, rows, cols] => Some((*rows, *cols)),
        _ => None,
    }
}

/// The status a terminal reports for a private mode, from its reply to a mode query.
#[must_use]
pub fn mode_status(bytes: &[u8], mode: u32) -> Option<u32> {
    let mut at = 0;
    while at + 2 < bytes.len() {
        if bytes[at..].starts_with(b"\x1b[?") {
            let start = at + 3;
            let mut end = start;
            while end < bytes.len() && (bytes[end].is_ascii_digit() || bytes[end] == b';') {
                end += 1;
            }
            if bytes[end..].starts_with(b"$y") {
                let text = std::str::from_utf8(&bytes[start..end]).ok()?;
                let (reported, status) = text.split_once(';')?;
                if reported.parse::<u32>().ok()? == mode {
                    return status.parse().ok();
                }
            }
        }
        at += 1;
    }
    None
}

/// The text of the reply to the terminal version query, when the terminal gives one.
#[must_use]
pub fn version_text(bytes: &[u8]) -> Option<String> {
    let start = bytes.windows(4).position(|window| window == b"\x1bP>|")? + 4;
    let rest = &bytes[start..];
    let end = rest
        .windows(2)
        .position(|window| window == b"\x1b\\")
        .or_else(|| rest.iter().position(|byte| *byte == 0x07))?;
    Some(String::from_utf8_lossy(&rest[..end]).into_owned())
}

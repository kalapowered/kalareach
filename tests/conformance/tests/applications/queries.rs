//! Finds the queries in a byte stream: the sequences an application writes to ask its terminal
//! something, which the terminal answers by typing into the application's input.
//!
//! Section 8 makes the host the only thing that answers them. A query that reached an attached
//! terminal would be answered twice, once by the host and once by the terminal, and a stream a
//! terminal was sent with no query in it is the evidence that it could not have been.
//!
//! This list is written from what terminals answer, independently of the engine's own class table,
//! so an omission in one is not repeated in the other:
//!
//! * `ENQ`, and `ESC Z`;
//! * device attributes (`CSI c`, `CSI > c`, `CSI = c`), device status and cursor position
//!   (`CSI n` in either form), mode reports (`CSI $ p`), the terminal's version (`CSI > q`),
//!   keyboard and modifier reports (`CSI ? u`, `CSI ? m`), parameter and checksum reports
//!   (`CSI x`, `CSI * y`, `CSI $ w`, `CSI $ u`), graphics attributes (`CSI ? S`) and the window
//!   reports of `CSI t` (11, 13 to 16, 18 to 21);
//! * status strings and capabilities (`DCS $ q`, `DCS + q`);
//! * any operating-system command with a `?` field: colours, the palette and the clipboard.

/// One query found in a stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Query {
    /// Where it starts.
    pub at: usize,
    /// Its bytes, as written.
    pub bytes: Vec<u8>,
}

impl std::fmt::Display for Query {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.bytes).escape_debug())
    }
}

/// Every query in `stream`, in order.
#[must_use]
pub fn find(stream: &[u8]) -> Vec<Query> {
    let mut found = Vec::new();
    let mut at = 0;
    while at < stream.len() {
        match stream[at] {
            0x05 => {
                found.push(Query {
                    at,
                    bytes: vec![0x05],
                });
                at += 1;
            }
            0x1b => {
                let (end, query) = sequence(stream, at);
                if query {
                    found.push(Query {
                        at,
                        bytes: stream[at..end].to_vec(),
                    });
                }
                at = end.max(at + 1);
            }
            _ => at += 1,
        }
    }
    found
}

/// Reads the escape sequence at `at` and returns where it ends and whether it asks something.
fn sequence(stream: &[u8], at: usize) -> (usize, bool) {
    match stream.get(at + 1) {
        Some(b'[') => csi(stream, at + 2),
        Some(b'P') => string(stream, at + 2, |body| {
            body.starts_with(b"$q") || body.starts_with(b"+q")
        }),
        Some(b']') => string(stream, at + 2, |body| {
            body.split(|b| *b == b';')
                .skip(1)
                .any(|field| field == b"?")
        }),
        Some(b'_' | b'^' | b'X') => string(stream, at + 2, |_| false),
        Some(b'Z') => (at + 2, true),
        Some(_) => (at + 2, false),
        None => (at + 1, false),
    }
}

fn csi(stream: &[u8], from: usize) -> (usize, bool) {
    let mut end = from;
    while end < stream.len() && (0x20..=0x3f).contains(&stream[end]) {
        end += 1;
    }
    let Some(&last) = stream.get(end) else {
        return (stream.len(), false);
    };
    if !(0x40..=0x7e).contains(&last) {
        // Not a well-formed control sequence; whatever it was, it asks nothing.
        return (end, false);
    }
    let body = &stream[from..end];
    let private = body
        .first()
        .copied()
        .filter(|b| matches!(b, b'?' | b'>' | b'=' | b'<'));
    let intermediates: Vec<u8> = body
        .iter()
        .copied()
        .filter(|b| (0x20..=0x2f).contains(b))
        .collect();
    let parameters: Vec<u8> = body
        .iter()
        .copied()
        .skip(usize::from(private.is_some()))
        .filter(|b| (0x30..=0x3f).contains(b))
        .collect();
    let first = parameters
        .split(|b| *b == b';')
        .next()
        .and_then(|p| std::str::from_utf8(p).ok())
        .and_then(|p| p.parse::<u32>().ok());
    let query = match (private, intermediates.as_slice(), last) {
        (None | Some(b'>' | b'='), [], b'c') => true,
        (None | Some(b'?'), [], b'n') => true,
        (None | Some(b'?'), [b'$'], b'p') => true,
        (Some(b'>'), [], b'q') => true,
        (Some(b'?'), [], b'u' | b'm' | b'S') => true,
        (None, [], b'x') => true,
        (None, [b'*'], b'y') => true,
        (None, [b'$'], b'w' | b'u') => true,
        (None, [b'&'], b'u') => true,
        (None, [], b't') => matches!(first, Some(11 | 13 | 14 | 15 | 16 | 18 | 19 | 20 | 21)),
        _ => false,
    };
    (end + 1, query)
}

/// Reads a control string (`DCS`, `OSC`, `APC`, `PM`, `SOS`) whose body starts at `from`, ended by
/// `ST` or, for an operating-system command, `BEL`.
fn string(stream: &[u8], from: usize, asks: impl Fn(&[u8]) -> bool) -> (usize, bool) {
    let mut end = from;
    while end < stream.len() {
        match stream[end] {
            0x07 => return (end + 1, asks(&stream[from..end])),
            0x1b if stream.get(end + 1) == Some(&b'\\') => {
                return (end + 2, asks(&stream[from..end]));
            }
            _ => end += 1,
        }
    }
    (stream.len(), false)
}

#[cfg(test)]
mod tests {
    use super::find;

    fn found(stream: &[u8]) -> Vec<String> {
        find(stream).iter().map(ToString::to_string).collect()
    }

    #[test]
    fn requests_are_found_and_settings_are_not() {
        assert_eq!(
            found(
                b"a\x1b[c\x1b[>0q\x1b[?u\x1b[?2004h\x1b[>1u\x1b[6n\x1b[?1049$p\x1b[14t\x1b[22;0t"
            ),
            [
                "\\u{1b}[c",
                "\\u{1b}[>0q",
                "\\u{1b}[?u",
                "\\u{1b}[6n",
                "\\u{1b}[?1049$p",
                "\\u{1b}[14t"
            ]
        );
    }

    #[test]
    fn a_string_query_is_found_by_its_question_mark_or_its_introducer() {
        assert_eq!(
            found(b"\x1b]11;?\x07\x1b]0;title\x07\x1bP+q544e\x1b\\\x1bP$qm\x1b\\\x1b]52;c;?\x1b\\"),
            [
                "\\u{1b}]11;?\\u{7}",
                "\\u{1b}P+q544e\\u{1b}\\\\",
                "\\u{1b}P$qm\\u{1b}\\\\",
                "\\u{1b}]52;c;?\\u{1b}\\\\"
            ]
        );
    }

    #[test]
    fn a_reply_is_not_a_request() {
        // What a terminal answers with travels the other way and is not a question.
        assert!(
            found(b"\x1b[?62;22c\x1b[24;80R\x1b[?1;2$y\x1b]11;rgb:0000/0000/0000\x07").is_empty()
        );
    }
}

//! Comments in Kotlin and Swift sources.
//!
//! The report does not build these languages' tests, so it reads no more of them than their
//! comments: `//` to the end of the line and `/* */`, nested as both languages allow, with string
//! literals (a triple-quoted one included) and Kotlin's character literals stepped over.

/// A comment and the line it starts on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Comment {
    /// The line it starts on, from 1.
    pub line: usize,
    /// Its text, markers included.
    pub text: String,
}

/// Every comment in `source`.
#[must_use]
pub fn comments(source: &str) -> Vec<Comment> {
    let chars: Vec<char> = source.chars().collect();
    let mut found = Vec::new();
    let mut at = 0;
    let mut line = 1;
    let starts = |at: usize, text: &str| {
        text.chars()
            .enumerate()
            .all(|(i, c)| chars.get(at + i) == Some(&c))
    };
    while at < chars.len() {
        let c = chars[at];
        if starts(at, "//") {
            let begin = at;
            while at < chars.len() && chars[at] != '\n' {
                at += 1;
            }
            found.push(Comment {
                line,
                text: chars[begin..at].iter().collect(),
            });
        } else if starts(at, "/*") {
            let (begin, first_line) = (at, line);
            let mut depth = 0_usize;
            while at < chars.len() {
                if starts(at, "/*") {
                    depth += 1;
                    at += 2;
                } else if starts(at, "*/") {
                    depth -= 1;
                    at += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    if chars[at] == '\n' {
                        line += 1;
                    }
                    at += 1;
                }
            }
            found.push(Comment {
                line: first_line,
                text: chars[begin..at.min(chars.len())].iter().collect(),
            });
        } else if starts(at, "\"\"\"") {
            at += 3;
            while at < chars.len() && !starts(at, "\"\"\"") {
                if chars[at] == '\n' {
                    line += 1;
                }
                at += 1;
            }
            at += 3;
        } else if c == '"' {
            at += 1;
            while at < chars.len() && chars[at] != '"' && chars[at] != '\n' {
                at += if chars[at] == '\\' { 2 } else { 1 };
            }
            at += 1;
        } else if c == '\''
            && (chars.get(at + 2) == Some(&'\'')
                || (chars.get(at + 1) == Some(&'\\') && chars.get(at + 3) == Some(&'\'')))
        {
            at += if chars.get(at + 1) == Some(&'\\') {
                4
            } else {
                3
            };
        } else {
            if c == '\n' {
                line += 1;
            }
            at += 1;
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::comments;

    #[test]
    fn comments_are_found_and_markers_inside_strings_are_not() {
        let found = comments(
            "// KR-REQ-15.17: first\nval url = \"https://example//not\"\n/* one\n /* nested */ two */\nval c = '/'\nval s = \"\"\"\n// not a comment\n\"\"\"\n// last\n",
        );
        let lines: Vec<usize> = found.iter().map(|comment| comment.line).collect();
        assert_eq!(lines, [1, 3, 9]);
        assert!(found[1].text.ends_with("two */"));
    }
}

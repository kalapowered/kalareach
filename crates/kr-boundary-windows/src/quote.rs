//! A command line for a child, written so that the platform's own argument splitting gives back
//! the parts that were quoted.
//!
//! Windows hands a program one string, and the program (or the system's `CommandLineToArgvW`)
//! splits it. The broker never lets a caller write that string: it quotes each part itself, with
//! the one set of rules below, so that a part with a space, a quote or a trailing backslash is
//! still one argument and no part can end another.
//!
//! The first part is the program's name. The platform reads it by a rule of its own, with no
//! escapes, so it is wrapped in quotes when it holds a space or a tab and is otherwise left as it
//! is. A program's path cannot hold a quote, which the file system refuses.

/// Quotes the parts of a command line and joins them with spaces.
///
/// The first part is the program's name, the others are its arguments.
#[must_use]
pub fn quote_command_line(parts: &[&str]) -> String {
    let mut line = String::new();
    for (index, part) in parts.iter().enumerate() {
        if index > 0 {
            line.push(' ');
        }
        if index == 0 {
            program_name(&mut line, part);
        } else {
            argument(&mut line, part);
        }
    }
    line
}

fn program_name(line: &mut String, name: &str) {
    if name.is_empty() || name.contains([' ', '\t']) {
        line.push('"');
        line.push_str(name);
        line.push('"');
    } else {
        line.push_str(name);
    }
}

fn argument(line: &mut String, part: &str) {
    if !part.is_empty() && !part.contains([' ', '\t', '\n', '\u{b}', '"']) {
        line.push_str(part);
        return;
    }
    line.push('"');
    let mut backslashes = 0_usize;
    for character in part.chars() {
        match character {
            '\\' => backslashes += 1,
            '"' => {
                // The backslashes before a quote are doubled, and the quote itself is escaped.
                line.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                line.push('"');
                backslashes = 0;
            }
            other => {
                line.extend(std::iter::repeat_n('\\', backslashes));
                line.push(other);
                backslashes = 0;
            }
        }
    }
    // The backslashes before the closing quote are doubled so that they do not escape it.
    line.extend(std::iter::repeat_n('\\', backslashes * 2));
    line.push('"');
}

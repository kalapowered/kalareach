//! The part of Markdown the method index's check reads: which lines are headings, what a heading
//! says once it is rendered, and the anchor its page gives it.
//!
//! The block rules follow CommonMark for what decides whether a line is a heading: fenced code with
//! its opening length and closing syntax, indented code, ATX and setext headings, and the list
//! items, block quotes, tables and HTML that a setext underline cannot turn into a heading. The
//! inline rules cover what changes a heading's anchor: code spans, escapes, link destinations,
//! HTML tags, entities and emphasis. Anchors are given the way GitHub gives them: the rendered text
//! lower-cased, with letters, digits, hyphens and underscores kept, spaces turned into hyphens and
//! everything else dropped, and a repeated anchor numbered in document order.
//!
//! It is not a renderer. A heading the index links to is also held to be plain text, so its anchor
//! never depends on the approximations below.

use std::collections::HashMap;

/// One heading, as written and as its page anchors it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Heading {
    /// The heading's content as the document writes it, without its markers.
    pub(crate) source: String,
    /// The anchor the rendered page gives it.
    pub(crate) anchor: String,
}

/// Returns every heading in a document, in order, each with its anchor.
pub(crate) fn headings(text: &str) -> Vec<Heading> {
    let mut sources = Vec::new();
    let mut fence: Option<(char, usize)> = None;
    let mut paragraph: Vec<&str> = Vec::new();
    let mut in_container = false;
    for line in text.lines() {
        if let Some((marker, length)) = fence {
            if closes_fence(line, marker, length) {
                fence = None;
            }
            continue;
        }
        let (indent, rest) = indentation(line);
        if rest.trim().is_empty() {
            paragraph.clear();
            in_container = false;
            continue;
        }
        if indent >= 4 {
            // Indented code, unless it continues a paragraph.
            if !paragraph.is_empty() {
                paragraph.push(rest.trim());
            }
            continue;
        }
        if let Some(opened) = opens_fence(rest) {
            paragraph.clear();
            in_container = false;
            fence = Some(opened);
            continue;
        }
        if let Some(content) = atx_content(rest) {
            paragraph.clear();
            in_container = false;
            sources.push(content.to_owned());
            continue;
        }
        if !paragraph.is_empty() && is_setext_underline(rest) {
            sources.push(paragraph.join(" "));
            paragraph.clear();
            continue;
        }
        if is_thematic_break(rest) {
            paragraph.clear();
            in_container = false;
            continue;
        }
        if starts_container(rest) {
            paragraph.clear();
            in_container = true;
            // A block quote or a list item can hold an ATX heading, and its page anchors it.
            if let Some(content) = container_content(rest).and_then(atx_content) {
                sources.push(content.to_owned());
            }
            continue;
        }
        if !in_container {
            paragraph.push(rest.trim());
        }
    }
    let mut taken: HashMap<String, usize> = HashMap::new();
    sources
        .into_iter()
        .map(|source| {
            let anchor = allocate(&mut taken, slug(&render(&source)));
            Heading { source, anchor }
        })
        .collect()
}

/// Returns the anchor of a heading that is the first on its page with this anchor.
pub(crate) fn anchor(source: &str) -> String {
    slug(&render(source))
}

/// Returns true when a heading renders as its own text, give or take code-span markers.
///
/// A link, emphasis, an escape, an entity or HTML in a heading makes what a reader sees differ
/// from what the document says, so the index never names such a heading.
pub(crate) fn is_plain(source: &str) -> bool {
    !source.contains(['[', ']', '*', '_', '<', '>', '\\', '&'])
}

/// Returns the anchor to give next: the base the first time, then the base numbered from one.
fn allocate(taken: &mut HashMap<String, usize>, base: String) -> String {
    let mut anchor = base.clone();
    while taken.contains_key(&anchor) {
        let count = taken.entry(base.clone()).or_insert(0);
        *count += 1;
        anchor = format!("{base}-{count}");
    }
    taken.insert(anchor.clone(), 0);
    anchor
}

/// Returns the anchor text of rendered heading text.
fn slug(rendered: &str) -> String {
    rendered
        .to_lowercase()
        .chars()
        .filter_map(|character| match character {
            ' ' => Some('-'),
            '-' | '_' => Some(character),
            other if other.is_alphanumeric() => Some(other),
            _ => None,
        })
        .collect()
}

/// Returns the text a heading's content renders as.
fn render(source: &str) -> String {
    let characters: Vec<char> = source.chars().collect();
    let mut out = String::new();
    let mut index = 0;
    while index < characters.len() {
        let character = characters[index];
        match character {
            '\\' if characters
                .get(index + 1)
                .is_some_and(char::is_ascii_punctuation) =>
            {
                out.push(characters[index + 1]);
                index += 2;
            }
            '`' => {
                let run = run_length(&characters, index, '`');
                match closing_code_run(&characters, index + run, run) {
                    Some(end) => {
                        let content: String = characters[index + run..end].iter().collect();
                        out.push_str(&code_span_content(&content));
                        index = end + run;
                    }
                    None => {
                        out.extend(std::iter::repeat_n('`', run));
                        index += run;
                    }
                }
            }
            ']' if characters.get(index + 1) == Some(&'(') => {
                // A link's destination is not part of what it reads as.
                match characters[index + 1..].iter().position(|next| *next == ')') {
                    Some(offset) => index += offset + 2,
                    None => {
                        out.push(character);
                        index += 1;
                    }
                }
            }
            '<' => match characters[index + 1..].iter().position(|next| *next == '>') {
                Some(offset) => {
                    let inner: String = characters[index + 1..index + 1 + offset].iter().collect();
                    // An autolink shows its address; a tag shows nothing.
                    if inner.contains("://") || inner.contains('@') {
                        out.push_str(&inner);
                    }
                    index += offset + 2;
                }
                None => {
                    out.push(character);
                    index += 1;
                }
            },
            '&' => {
                let rest: String = characters[index..].iter().collect();
                let entity = [
                    ("&amp;", '&'),
                    ("&lt;", '<'),
                    ("&gt;", '>'),
                    ("&quot;", '"'),
                    ("&#39;", '\''),
                ]
                .into_iter()
                .find(|(name, _)| rest.starts_with(name));
                match entity {
                    Some((name, replacement)) => {
                        out.push(replacement);
                        index += name.chars().count();
                    }
                    None => {
                        out.push(character);
                        index += 1;
                    }
                }
            }
            '*' => index += 1,
            '_' => {
                let inside_a_word = index > 0
                    && characters[index - 1].is_alphanumeric()
                    && characters
                        .get(index + 1)
                        .is_some_and(|next| next.is_alphanumeric());
                if inside_a_word {
                    out.push(character);
                }
                index += 1;
            }
            _ => {
                out.push(character);
                index += 1;
            }
        }
    }
    out
}

fn run_length(characters: &[char], start: usize, wanted: char) -> usize {
    characters[start..]
        .iter()
        .take_while(|character| **character == wanted)
        .count()
}

/// Returns where the backtick run that closes a code span of `length` starts, if one does.
fn closing_code_run(characters: &[char], from: usize, length: usize) -> Option<usize> {
    let mut index = from;
    while index < characters.len() {
        if characters[index] == '`' {
            let run = run_length(characters, index, '`');
            if run == length {
                return Some(index);
            }
            index += run;
        } else {
            index += 1;
        }
    }
    None
}

/// Returns a code span's content: one space is stripped from each end when both ends have one.
fn code_span_content(content: &str) -> String {
    if content.len() >= 2
        && content.starts_with(' ')
        && content.ends_with(' ')
        && !content.chars().all(|character| character == ' ')
    {
        content[1..content.len() - 1].to_owned()
    } else {
        content.to_owned()
    }
}

/// Returns a line's indentation in columns, a tab reaching the next multiple of four, and the rest.
fn indentation(line: &str) -> (usize, &str) {
    let mut columns = 0;
    for (offset, character) in line.char_indices() {
        match character {
            ' ' => columns += 1,
            '\t' => columns += 4 - columns % 4,
            _ => return (columns, &line[offset..]),
        }
    }
    (columns, "")
}

/// Returns the fence a line opens: its character and its length.
fn opens_fence(rest: &str) -> Option<(char, usize)> {
    let marker = rest
        .chars()
        .next()
        .filter(|first| matches!(first, '`' | '~'))?;
    let length = rest
        .chars()
        .take_while(|character| *character == marker)
        .count();
    if length < 3 {
        return None;
    }
    let info = &rest[length..];
    if marker == '`' && info.contains('`') {
        return None;
    }
    Some((marker, length))
}

/// Returns true when a line closes a fence of this character and length.
fn closes_fence(line: &str, marker: char, length: usize) -> bool {
    let (indent, rest) = indentation(line);
    if indent >= 4 {
        return false;
    }
    let run = rest
        .chars()
        .take_while(|character| *character == marker)
        .count();
    run >= length && rest[run..].trim().is_empty()
}

/// Returns an ATX heading's content, when the line is one.
fn atx_content(rest: &str) -> Option<&str> {
    let level = rest.bytes().take_while(|byte| *byte == b'#').count();
    if !(1..=6).contains(&level) {
        return None;
    }
    let after = &rest[level..];
    if !(after.is_empty() || after.starts_with(' ') || after.starts_with('\t')) {
        return None;
    }
    let content = after.trim();
    let without_closing = content.trim_end_matches('#');
    if without_closing.is_empty() {
        return Some("");
    }
    if without_closing.len() < content.len() && without_closing.ends_with([' ', '\t']) {
        return Some(without_closing.trim_end());
    }
    Some(content)
}

fn is_setext_underline(rest: &str) -> bool {
    let underline = rest.trim_end();
    !underline.is_empty()
        && (underline.chars().all(|character| character == '=')
            || underline.chars().all(|character| character == '-'))
}

fn is_thematic_break(rest: &str) -> bool {
    let marks: Vec<char> = rest
        .chars()
        .filter(|character| !matches!(character, ' ' | '\t'))
        .collect();
    marks.len() >= 3
        && matches!(marks[0], '-' | '*' | '_')
        && marks.iter().all(|character| *character == marks[0])
}

/// Returns true when a line starts a list item, a block quote, a table row or an HTML block.
///
/// A line that follows one of those without a blank line between continues it, so a setext
/// underline after it is not a heading.
fn starts_container(rest: &str) -> bool {
    let mut characters = rest.chars();
    let first = characters.next().unwrap_or(' ');
    let second = characters.next();
    let separated = |next: Option<char>| next.is_none_or(|next| matches!(next, ' ' | '\t'));
    if matches!(first, '-' | '*' | '+') && separated(second) {
        return true;
    }
    if matches!(first, '>' | '|' | '<') {
        return true;
    }
    let digits = rest.chars().take_while(char::is_ascii_digit).count();
    if (1..=9).contains(&digits) {
        let mut after = rest[digits..].chars();
        return matches!(after.next(), Some('.' | ')')) && separated(after.next());
    }
    false
}

/// Returns what follows a block quote marker or a list item marker, repeated ones included.
fn container_content(rest: &str) -> Option<&str> {
    let mut content = rest;
    let mut stripped = false;
    loop {
        if let Some(quoted) = content.strip_prefix('>') {
            content = quoted.strip_prefix(' ').unwrap_or(quoted);
        } else if let Some(item) = ["- ", "* ", "+ "]
            .into_iter()
            .find_map(|marker| content.strip_prefix(marker))
        {
            content = item;
        } else {
            let digits = content.chars().take_while(char::is_ascii_digit).count();
            let after = &content[digits..];
            match after
                .strip_prefix(". ")
                .or_else(|| after.strip_prefix(") "))
            {
                Some(item) if (1..=9).contains(&digits) => content = item,
                _ => break,
            }
        }
        stripped = true;
        content = content.trim_start_matches(' ');
    }
    stripped.then_some(content)
}

#[cfg(test)]
mod tests {
    use super::{Heading, anchor, headings, is_plain};

    fn sources(text: &str) -> Vec<String> {
        headings(text)
            .into_iter()
            .map(|heading| heading.source)
            .collect()
    }

    fn anchors(text: &str) -> Vec<String> {
        headings(text)
            .into_iter()
            .map(|heading| heading.anchor)
            .collect()
    }

    #[test]
    fn an_anchor_is_the_rendered_heading_lower_cased_with_punctuation_dropped() {
        assert_eq!(anchor("What a reboot does"), "what-a-reboot-does");
        assert_eq!(anchor("The `kr` command line"), "the-kr-command-line");
        assert_eq!(
            anchor("An owner's confirmations"),
            "an-owners-confirmations"
        );
        assert_eq!(
            anchor("Two activations, each atomic on its own"),
            "two-activations-each-atomic-on-its-own"
        );
        assert_eq!(
            anchor("Shown before a call (KR-REQ-15.19)"),
            "shown-before-a-call-kr-req-1519"
        );
        assert_eq!(anchor("Café — déjà vu"), "café--déjà-vu");
        assert_eq!(
            anchor("`kr_protocol::wire` and snake_case"),
            "kr_protocolwire-and-snake_case"
        );
        assert_eq!(anchor("[What a sync does](other.md)"), "what-a-sync-does");
        assert_eq!(anchor("*Emphasis* and _more_"), "emphasis-and-more");
        assert_eq!(
            anchor("A <br> tag &amp; an \\_escape"),
            "a--tag--an-_escape"
        );
    }

    #[test]
    fn a_plain_heading_has_no_inline_markup_beyond_code() {
        assert!(is_plain("The `kr` command line"));
        assert!(!is_plain("[What a sync does](other.md)"));
        assert!(!is_plain("*Emphasis*"));
        assert!(!is_plain("snake_case"));
    }

    #[test]
    fn a_heading_is_an_atx_or_setext_line_outside_code() {
        let text = "# Title\n\
                    text\n\
                    ## Section ##\n\
                    ```bash\n\
                    # a comment\n\
                    ```\n\
                    ~~~\n\
                    ## Also code\n\
                    ~~~\n\
                    #hashtag\n\
                    \n    \
                    ## indented code\n\
                    \n\
                    Setext one\n\
                    ==========\n\
                    Setext\n\
                    two\n\
                    ---\n\
                    ### Last ###\n\
                    ### Escaped \\#\n\
                    ### Closed after a backslash \\ ##\n";
        assert_eq!(
            sources(text),
            [
                "Title",
                "Section",
                "Setext one",
                "Setext two",
                "Last",
                "Escaped \\#",
                "Closed after a backslash \\"
            ]
        );
    }

    #[test]
    fn a_fence_closes_only_on_its_own_character_at_its_length_or_longer() {
        let text = "````markdown\n\
                    ```\n\
                    ## Inside the longer fence\n\
                    ````\n\
                    ## After it\n\
                    ```\n\
                    ``` not a close\n\
                    ## Still code\n\
                    ~~~\n\
                    ## Also still code\n\
                    `````\n\
                    ## Out again\n\
                    ``` `not a fence`\n\
                    ## A heading, because the line above opened nothing\n";
        assert_eq!(
            sources(text),
            [
                "After it",
                "Out again",
                "A heading, because the line above opened nothing"
            ]
        );
    }

    #[test]
    fn an_underline_after_a_list_item_quote_table_or_blank_line_is_not_a_heading() {
        let text = "- item\n\
                    continued lazily\n\
                    ---\n\
                    > quoted\n\
                    ===\n\
                    | a | b |\n\
                    ---\n\
                    \n\
                    ---\n\
                    1. first\n\
                    ---\n";
        assert_eq!(sources(text), Vec::<String>::new());
    }

    #[test]
    fn a_heading_inside_a_block_quote_or_list_item_counts() {
        assert_eq!(
            sources("> ## Quoted\n- ### Listed\n1. #### Numbered\n> - ## Both\n"),
            ["Quoted", "Listed", "Numbered", "Both"]
        );
    }

    #[test]
    fn a_repeated_anchor_is_numbered_in_document_order() {
        let text = "## Limits\n\
                    ## Limits\n\
                    ## Limits-1\n\
                    ## `Limits`\n";
        assert_eq!(
            anchors(text),
            ["limits", "limits-1", "limits-1-1", "limits-2"]
        );
        assert_eq!(
            headings("## [Limits](x.md)\n## Limits\n"),
            [
                Heading {
                    source: "[Limits](x.md)".to_owned(),
                    anchor: "limits".to_owned()
                },
                Heading {
                    source: "Limits".to_owned(),
                    anchor: "limits-1".to_owned()
                }
            ]
        );
    }
}

//! The shared-content preview an issuer sees before an invitation exists.
//!
//! Section 25: "A shared live screen can contain text printed before the invitation; the preview
//! must show what is being shared." So the preview is the text itself, bounded, with a mark when
//! the bound cut it. A count of lines, or a promise that the screen is "the current view", would
//! be a description of the sharing rather than a sight of it.

use kr_protocol::sharing::{LiveScreenPreview, MAX_PREVIEW_LINE_CHARS, MAX_PREVIEW_LINES};

/// Builds the preview for a run of screen lines.
///
/// Lines beyond [`MAX_PREVIEW_LINES`] are dropped and characters beyond
/// [`MAX_PREVIEW_LINE_CHARS`] are cut, both of which set [`LiveScreenPreview::truncated`]. The cut
/// is by character rather than by byte, so a preview never ends inside a code point.
#[must_use]
pub fn live_screen_preview<'a>(lines: impl IntoIterator<Item = &'a str>) -> LiveScreenPreview {
    let mut kept: Vec<String> = Vec::new();
    let mut truncated = false;
    for line in lines {
        if kept.len() >= MAX_PREVIEW_LINES {
            truncated = true;
            break;
        }
        let mut characters = line.chars();
        let cut: String = characters.by_ref().take(MAX_PREVIEW_LINE_CHARS).collect();
        if characters.next().is_some() {
            truncated = true;
        }
        kept.push(cut);
    }
    LiveScreenPreview {
        lines: kept,
        truncated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_screen_previews_whole() {
        let preview = live_screen_preview(["one", "two"]);
        assert_eq!(preview.lines, vec!["one".to_owned(), "two".to_owned()]);
        assert!(!preview.truncated);
    }

    #[test]
    fn a_long_screen_says_it_was_cut() {
        let long: Vec<String> = (0..MAX_PREVIEW_LINES + 4)
            .map(|row| row.to_string())
            .collect();
        let preview = live_screen_preview(long.iter().map(String::as_str));
        assert_eq!(preview.lines.len(), MAX_PREVIEW_LINES);
        assert!(preview.truncated);
    }

    #[test]
    fn a_long_line_is_cut_by_character_and_says_so() {
        let line = "é".repeat(MAX_PREVIEW_LINE_CHARS + 10);
        let preview = live_screen_preview([line.as_str()]);
        let shown = preview.lines.first().expect("one line");
        assert_eq!(shown.chars().count(), MAX_PREVIEW_LINE_CHARS);
        assert!(preview.truncated);
    }
}

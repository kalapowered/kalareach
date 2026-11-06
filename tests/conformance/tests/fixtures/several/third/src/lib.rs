//! The third of three libraries that each have a unit test and a documentation test.

/// The answer.
///
/// ```
/// assert_eq!(third::answer(), 3);
/// ```
#[must_use]
pub const fn answer() -> u8 {
    3
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_answers() {
        assert_eq!(super::answer(), 3);
    }
}

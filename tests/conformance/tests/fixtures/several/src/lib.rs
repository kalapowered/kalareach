//! The first of three libraries that each have a unit test and a documentation test.

/// The answer.
///
/// ```
/// assert_eq!(first::answer(), 1);
/// ```
#[must_use]
pub const fn answer() -> u8 {
    1
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_answers() {
        assert_eq!(super::answer(), 1);
    }
}

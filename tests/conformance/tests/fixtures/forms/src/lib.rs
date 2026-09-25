//! A crate whose cases and tests key rows in every form the report reads.

/// One case.
pub struct Case {
    /// The rows it covers.
    pub covers: &'static str,
    /// Its input.
    pub input: u8,
}

/// The cases. Rustdoc builds the example into a program of its own, which Cargo runs through
/// the same runner as the test binaries.
///
/// ```
/// assert_eq!(forms::CASES[0].input, 1);
/// ```
pub const CASES: &[Case] = &[Case {
    covers: "KR-REQ-02.02 row one",
    input: 1,
}];

#[cfg(test)]
mod tests {
    //! KR-REQ-02.03: the unit tests of this crate.

    #[test]
    fn the_table_is_read() {
        assert_eq!(crate::CASES[0].input, 1);
    }
}

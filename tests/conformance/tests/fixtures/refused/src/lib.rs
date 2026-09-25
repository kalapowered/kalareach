//! A crate whose tests name rows the report refuses.

#[cfg(test)]
mod tests {
    /// KR-ACC-036: a row past the end of section 21's table.
    #[test]
    fn names_a_row_that_does_not_exist() {}

    /// KR-REQ-09 and KR-REQ-01.01: a bare section beside a row.
    #[test]
    fn names_a_section() {}
}

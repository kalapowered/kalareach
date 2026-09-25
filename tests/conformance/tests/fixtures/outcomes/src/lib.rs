//! A crate whose tests pass, fail and are ignored. This documentation names KR-REQ-05.01, which is
//! product code's, so it keys no test.

#[cfg(test)]
mod tests {
    /// KR-REQ-04.01.
    #[test]
    fn passes() {}

    /// KR-REQ-04.02.
    #[test]
    #[ignore = "needs a device; the device lane runs it"]
    fn is_ignored() {}

    /// KR-REQ-04.03.
    #[test]
    fn fails() {
        panic!("this case fails on purpose");
    }

    /// KR-REQ-04.04.
    #[test]
    fn passes_too() {}

    /// KR-REQ-04.04.
    #[test]
    #[ignore = "needs a device; the device lane runs it"]
    fn is_ignored_too() {}

    /// KR-REQ-04.05.
    #[test]
    fn returns_early() {
        if std::env::var_os("OUTCOMES_DEVICE").is_none() {
            println!("skipped: OUTCOMES_DEVICE names no device to drive");
            return;
        }
        panic!("a device was named, and this tree has none");
    }
}

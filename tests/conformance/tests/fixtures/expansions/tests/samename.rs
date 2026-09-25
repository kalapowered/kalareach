//! One test name in two modules, which names two tests.

mod first {
    // KR-REQ-03.57: the first of two tests of one name.
    #[test]
    fn example() {}
}

mod second {
    // KR-REQ-03.58: the second.
    #[test]
    fn example() {}
}

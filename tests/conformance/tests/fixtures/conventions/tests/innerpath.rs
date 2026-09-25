//! An inline module whose own `path` attribute, written inside it, moves the files of its modules.

mod shifted {
    #![path = "moved"]
    pub mod sub;
}

/// KR-REQ-03.65: a case beside a module file the compiler finds where the inner attribute points.
fn shared() {}

#[test]
fn example() {
    println!(shared());
}

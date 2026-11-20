// KR-REQ-04.01: a test of the second workspace that passes.
#[test]
fn passes() {}

// KR-REQ-04.02: a test of the second workspace that stands down before it checks anything.
#[test]
fn stands_down() {
    println!("skipped: nothing to check here");
    return;
}

// KR-REQ-03.01: a test of the first workspace that passes.
#[test]
fn passes() {}

// KR-REQ-03.02: a test of the first workspace that stands down before it checks anything.
#[test]
fn stands_down() {
    println!("stands down: nothing to check here");
    return;
}

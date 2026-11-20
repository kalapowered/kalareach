// KR-REQ-05.02: a test that holds the value a set-up step gave it.
#[test]
fn a_set_up_step_leaves_the_file_the_variable_names() {
    let file = std::env::var("KR_MADE_BY_SET_UP").expect("the step names the file");
    let text = std::fs::read_to_string(file).expect("the set-up step made the file");
    assert_eq!(text.trim(), "made by the set-up step");
}

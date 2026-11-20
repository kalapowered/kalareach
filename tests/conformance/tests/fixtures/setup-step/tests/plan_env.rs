// KR-REQ-05.01: a test that holds the variables the plan and the step gave it.
#[test]
fn the_plan_and_the_step_give_their_variables() {
    assert_eq!(std::env::var("KR_FROM_PLAN").as_deref(), Ok("plan"));
    assert_eq!(std::env::var("KR_FROM_STEP").as_deref(), Ok("step"));
    // The step's value replaces the plan's value of the same name.
    assert_eq!(std::env::var("KR_IN_BOTH").as_deref(), Ok("the step's"));
}

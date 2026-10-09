//! A revocation's fence debt is settled once, however many callers settle it at once.

use std::sync::Arc;
use std::time::Duration;

use kr_protocol::ids::GrantId;

use super::Audience;

/// Two barriers raised at once over one published debt fence the host once: the one that
/// takes the registry first captures the debt and advances the revision, and the other finds
/// nothing to capture and answers with the revision the first advanced to.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_settlements_of_one_debt_fence_once() {
    let temp = kr_ipc::testing::TempHost::create();
    let controller = super::a_floor_owed_its_record::daemon(&temp).await;
    let before = controller.policy().authority_revision();
    let withdrawn = GrantId::new(kr_ipc::new_uuid());
    let debt = controller
        .owe_debt("a withdrawal", super::Reach::Host)
        .expect("the debt is written");

    // The registry is held, so a barrier stops before it captures anything: both wait there.
    let registry = controller.registry.lock().await;
    let first = {
        let controller = Arc::clone(&controller);
        tokio::spawn(async move {
            let own = controller.publish_debts(&[(debt, super::Reach::Host)]);
            controller
                .complete_revocation(Audience::Host, [withdrawn].into_iter().collect(), own)
                .await
                .map(|result| result.authority_revision)
        })
    };
    let second = {
        let controller = Arc::clone(&controller);
        tokio::spawn(async move {
            controller
                .barrier(controller.publish_debts(&[]))
                .await
                .map(|barrier| barrier.authority_revision)
        })
    };
    tokio::time::sleep(Duration::from_millis(500)).await;
    drop(registry);

    let first = first
        .await
        .expect("the first settlement ends")
        .expect("it succeeds");
    let second = second
        .await
        .expect("the second settlement ends")
        .expect("it succeeds");
    assert_eq!(
        controller.policy().authority_revision().get(),
        before.get() + 1,
        "one withdrawal, one fence"
    );
    assert_eq!(first, second);
    assert!(
        controller
            .sharing()
            .grants()
            .fence_owed()
            .expect("readable")
            .is_empty(),
        "and nothing is owed"
    );
}

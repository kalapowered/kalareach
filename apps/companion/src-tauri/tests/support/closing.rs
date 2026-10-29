//! An account whose deletion the service has closed, for the suites that settle what a closed
//! account leaves on the device.
//!
//! The account is the real one over a real store; the only stand-in is the transport, which answers
//! the confirmation as the service does when it closes the account.

#![allow(dead_code)]

use std::sync::Arc;

use companion_tauri::account::Account;
use companion_tauri::account::carrier::{Boxed, Carrier, Ending, Plan, Unavailable};
use kr_client::services::account::deletion::{
    DeletionOutcome, DeviceSteps, ManagedAccountDeletion, StepFuture,
};
use kr_client::services::account::{
    ACCOUNT_ORIGIN, AccountMark, AccountService, AccountToken, Client, IssuedGrant,
    PendingAuthorisation, Redirect, RefreshToken, SignedInAccount,
};
use kr_client::services::{NullService, ServiceFuture, ServiceHttp, ServiceHttpAnswer};
use kr_crypto::store::MemoryStore;
use kr_protocol::service::GatewayOrigin;

/// The application's own steps, not taken yet: the confirmation that closes the account leaves them
/// for the look that the test makes through the application.
struct NotYet;

impl DeviceSteps for NotYet {
    fn notifications(&self) -> StepFuture<'_> {
        Box::pin(async { false })
    }

    fn recovery(&self, _deleted: AccountMark) -> StepFuture<'_> {
        Box::pin(async { false })
    }
}

/// The service, as it answers a confirmation that closes the account, and a look at the outcome
/// until it is made unreachable.
#[derive(Debug, Default)]
struct Closing {
    unreachable: std::sync::atomic::AtomicBool,
}

fn answered(body: &str) -> ServiceFuture<'static, ServiceHttpAnswer> {
    let answer = ServiceHttpAnswer {
        status: 200,
        body: body.as_bytes().to_vec(),
    };
    Box::pin(async move { Ok(answer) })
}

impl ServiceHttp for Closing {
    fn post_json<'a>(
        &'a self,
        url: &'a str,
        _body: &'a [u8],
        _headers: &'a [(&'a str, &'a str)],
    ) -> ServiceFuture<'a, ServiceHttpAnswer> {
        if url.ends_with("/status") {
            if self.unreachable.load(std::sync::atomic::Ordering::SeqCst) {
                return Box::pin(async {
                    Err(kr_client::error::ClientError::Host(
                        kr_protocol::error::ProtocolError::new(
                            kr_protocol::error::ErrorCode::UpstreamUnavailable,
                            "unreachable".to_owned(),
                        ),
                    ))
                });
            }
            answered(r#"{"ok":true,"data":{"state":"open"}}"#)
        } else {
            answered(r#"{"ok":true,"data":{"result":"closed","state":"closing"}}"#)
        }
    }

    fn get_json<'a>(
        &'a self,
        _url: &'a str,
        _headers: &'a [(&'a str, &'a str)],
    ) -> ServiceFuture<'a, ServiceHttpAnswer> {
        answered(r#"{"ok":false,"error":{"code":"NOT_FOUND","message":"no"}}"#)
    }
}

/// A browser nobody opens: sign-in is not under test here.
struct NoBrowser;

impl Carrier for NoBrowser {
    fn plan(&self) -> Boxed<'_, Result<Plan, Unavailable>> {
        Box::pin(async {
            Ok(Plan {
                redirect: Redirect::Loopback,
            })
        })
    }

    fn carry<'a>(
        &'a self,
        _plan: &'a Plan,
        _url: String,
        _pending: &'a mut PendingAuthorisation,
        _cancel: tokio::sync::watch::Receiver<bool>,
    ) -> Boxed<'a, Ending> {
        Box::pin(async { Ending::Cancelled })
    }
}

/// An account that was signed in and has just had its deletion closed by the service: the stored
/// sign-in is gone, and the record of the deletion waits for the device to settle what is its own.
pub async fn closed_account() -> Arc<Account> {
    closed_account_with(ACCOUNT_ORIGIN, Arc::new(Closing::default())).await
}

/// [`closed_account`], for the account of the same name signed in to the service at `origin`.
pub async fn closed_account_at(origin: &str) -> Arc<Account> {
    closed_account_with(origin, Arc::new(Closing::default())).await
}

/// [`closed_account_at`], over a service that cannot be reached once the account is closed: a look
/// at how the removal goes fails.
pub async fn closed_account_unreachable_at(origin: &str) -> Arc<Account> {
    let service = Arc::new(Closing::default());
    let account = closed_account_with(origin, Arc::clone(&service)).await;
    service
        .unreachable
        .store(true, std::sync::atomic::Ordering::SeqCst);
    account
}

async fn closed_account_with(origin: &str, service_http: Arc<Closing>) -> Arc<Account> {
    let service: Arc<dyn AccountService> = Arc::new(NullService);
    let signed_in = Arc::new(SignedInAccount::new(
        Arc::clone(&service),
        Arc::new(MemoryStore::new()),
        Client::Desktop,
    ));
    signed_in
        .commit(
            IssuedGrant {
                access_token: AccountToken::new("an-access-token").expect("a token"),
                expires_in_seconds: 600,
                refresh_token: RefreshToken::new("a-refresh-token").expect("a token"),
                scopes: vec!["openid".to_owned()],
                subject: "account-one".to_owned(),
            },
            "a-nonce",
        )
        .await
        .expect("the sign-in is kept");
    let origin = GatewayOrigin::new(origin).expect("an origin");
    let deletion = Arc::new(ManagedAccountDeletion::new(
        &origin,
        service_http,
        Arc::clone(&signed_in),
    ));
    let account = Arc::new(Account::new(
        signed_in,
        service,
        origin,
        Arc::new(NoBrowser),
        Arc::new(|_| {}),
        deletion,
    ));
    assert_eq!(
        account.deletion().confirm("12345678", &[], &NotYet).await,
        Ok(DeletionOutcome::Closed { finished: false })
    );
    account
}

//! The line of a failed revocation, held against the orders of events that reach it.
//!
//! Each case makes one order through a store and a service that fail where the case says, on a real
//! `SignedInAccount`, and asserts what the one function returned (the variant of `Unrevoked`), the
//! whole line the daemon writes for it, and what the queue holds afterwards. No variant is made by
//! hand. The account's own lock is not a step the store can fail, so no case makes it fail: the
//! lines name no step that a variant does not record, which is what lets one line stand for the
//! orders that reach it.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use kr_client::error::ClientError;
use kr_client::services::ServiceFuture;
use kr_client::services::account::{
    AccountIdentity, AccountService, AccountToken, AccountUsage, AuthorisationGrant, Client,
    Commit, Exchanged, RefreshToken, Refreshed, SignedInAccount, StoredGrant, Unrevoked,
};
use kr_crypto::store::{MemoryStore, SecretName, SecretStore};
use kr_protocol::error::{ErrorCode, ProtocolError};

use super::{CALL_OPEN, REFUSED_EXCHANGE, UNKEPT, WITHHELD, failed_revocation_line};

/// What the store does with the next write of the revocation queue (a set or a delete).
#[derive(Clone, Copy)]
enum Write {
    Works,
    /// Refused before anything changes.
    Refused,
    /// The write is installed and then reported as failed, as a flush that fails after the rename
    /// or the unlink did.
    LandsThenFails,
}

/// A store whose reads and writes of the revocation queue fail where the order says.
struct OrderStore {
    inner: MemoryStore,
    /// For each next read of the queue, whether it fails; none left means reads work.
    reads: Mutex<VecDeque<bool>>,
    /// For each next write of the queue; none left means writes work.
    writes: Mutex<VecDeque<Write>>,
}

fn is_the_queue(name: &SecretName) -> bool {
    name.as_str().ends_with("account/revoke")
}

fn refused() -> kr_crypto::CryptoError {
    kr_crypto::CryptoError::SecretStore {
        message: "the store refused".to_owned(),
    }
}

impl OrderStore {
    fn next_write(&self, name: &SecretName) -> Write {
        if is_the_queue(name) {
            self.writes
                .lock()
                .expect("the plan")
                .pop_front()
                .unwrap_or(Write::Works)
        } else {
            Write::Works
        }
    }
}

impl SecretStore for OrderStore {
    fn set(&self, name: &SecretName, secret: &[u8]) -> kr_crypto::Result<()> {
        match self.next_write(name) {
            Write::Works => self.inner.set(name, secret),
            Write::Refused => Err(refused()),
            Write::LandsThenFails => {
                self.inner.set(name, secret)?;
                Err(refused())
            }
        }
    }

    fn get(&self, name: &SecretName) -> kr_crypto::Result<Option<kr_crypto::secret::SecretVec>> {
        if is_the_queue(name)
            && self
                .reads
                .lock()
                .expect("the plan")
                .pop_front()
                .unwrap_or(false)
        {
            return Err(refused());
        }
        self.inner.get(name)
    }

    fn delete(&self, name: &SecretName) -> kr_crypto::Result<()> {
        match self.next_write(name) {
            Write::Works => self.inner.delete(name),
            Write::Refused => Err(refused()),
            Write::LandsThenFails => {
                self.inner.delete(name)?;
                Err(refused())
            }
        }
    }

    fn describe(&self) -> String {
        self.inner.describe()
    }
}

/// A service that takes or refuses each revocation as the order says, and records the tokens it
/// took.
#[derive(Debug)]
struct Service {
    /// For each next revocation, whether the service takes it.
    takes: Mutex<VecDeque<bool>>,
    taken: Mutex<Vec<String>>,
}

impl AccountService for Service {
    fn exchange<'a>(&'a self, _grant: &'a AuthorisationGrant) -> ServiceFuture<'a, Exchanged> {
        Box::pin(async { panic!("a revocation makes no exchange") })
    }

    fn refresh<'a>(&'a self, _stored: &'a StoredGrant) -> ServiceFuture<'a, Refreshed> {
        Box::pin(async { panic!("a revocation makes no refresh") })
    }

    fn revoke<'a>(&'a self, refresh: &'a RefreshToken) -> ServiceFuture<'a, ()> {
        Box::pin(async move {
            let takes = self
                .takes
                .lock()
                .expect("the plan")
                .pop_front()
                .expect("the order says what the service does with each revocation");
            if !takes {
                return Err(ClientError::Host(ProtocolError::new(
                    ErrorCode::UpstreamUnavailable,
                    "the service cannot be reached".to_owned(),
                )));
            }
            self.taken
                .lock()
                .expect("the record")
                .push(refresh.expose().to_owned());
            Ok(())
        })
    }

    fn identity<'a>(&'a self, _access: &'a AccountToken) -> ServiceFuture<'a, AccountIdentity> {
        Box::pin(async { panic!("a revocation reads no identity") })
    }

    fn usage<'a>(&'a self, _access: &'a AccountToken) -> ServiceFuture<'a, AccountUsage> {
        Box::pin(async { panic!("a revocation reads no usage") })
    }
}

/// One order: what each next read of the queue does (true fails), what each next write of it does,
/// and whether the service takes each next revocation.
struct Order {
    reads: &'static [bool],
    writes: &'static [Write],
    service_takes: &'static [bool],
}

/// How the revocation of the token failed, as the variant says.
#[derive(Debug, PartialEq, Eq)]
enum Placed {
    Nothing,
    Queued,
    Ended,
    Held,
}

/// Whether the queue holds the token's entry afterwards, read from the store itself.
#[derive(Debug, PartialEq, Eq)]
enum Queue {
    Empty,
    Holds,
}

/// What an order came to.
struct Seen {
    commit: Commit,
    placed: Placed,
    unrevoked: Option<Unrevoked>,
    /// The whole line the daemon writes, or none where nothing failed.
    line: Option<String>,
    queue: Queue,
    /// The tokens the service took, in order.
    taken: Vec<String>,
}

const TOKEN: &str = "grant-order";

async fn run(order: &Order) -> Seen {
    let service = Arc::new(Service {
        takes: Mutex::new(order.service_takes.iter().copied().collect()),
        taken: Mutex::new(Vec::new()),
    });
    let store = Arc::new(OrderStore {
        inner: MemoryStore::new(),
        reads: Mutex::new(order.reads.iter().copied().collect()),
        writes: Mutex::new(order.writes.iter().copied().collect()),
    });
    let account = SignedInAccount::new(
        Arc::clone(&service) as Arc<dyn AccountService>,
        Arc::clone(&store) as Arc<dyn SecretStore>,
        Client::Desktop,
    );
    let (commit, unrevoked) = account
        .end_withheld(RefreshToken::new(TOKEN).expect("a token"))
        .await;
    let placed = match &unrevoked {
        None => Placed::Nothing,
        Some(Unrevoked::Queued(_)) => Placed::Queued,
        Some(Unrevoked::Ended(_)) => Placed::Ended,
        Some(Unrevoked::Held(_)) => Placed::Held,
    };
    let line = unrevoked
        .as_ref()
        .map(|unrevoked| failed_revocation_line(WITHHELD, unrevoked));
    let queue = match store
        .inner
        .get(&SecretName::new("account/revoke").expect("a name"))
        .expect("a read")
    {
        None => Queue::Empty,
        Some(bytes) => {
            let text = String::from_utf8_lossy(bytes.expose()).into_owned();
            assert_eq!(text.matches("grantId").count(), 1, "one entry: {text}");
            assert!(text.contains(TOKEN), "the entry is the token's: {text}");
            Queue::Holds
        }
    };
    let taken = service.taken.lock().expect("the record").clone();
    Seen {
        commit,
        placed,
        unrevoked,
        line,
        queue,
        taken,
    }
}

/// The error each line ends with: the failing step is named there, by the client library, so the
/// lines themselves name none.
const READ_ERROR: &str =
    "STORAGE_UNAVAILABLE: the pending revocations could not be read: the secret store failed";
const KEPT_ERROR: &str =
    "STORAGE_UNAVAILABLE: the pending revocations could not be kept: the secret store failed";
const REMOVED_ERROR: &str =
    "STORAGE_UNAVAILABLE: the pending revocations could not be removed: the secret store failed";

const QUEUED: &str = "kr-controller: a withheld sign-in's token: the queue took the token and \
     sending the queue failed, and a send of the token alone was not acknowledged; the service \
     may have taken the token, and the queue may still hold its entry";
const ENDED: &str = "kr-controller: a withheld sign-in's token: the service took the token by a \
     send of its own; the queue of revocations failed, and may still hold its entry";
const HELD: &str = "kr-controller: a withheld sign-in's token: queuing the token failed and a \
     send of the token alone was not acknowledged; a write that had begun may have left its \
     entry in place, and the service may have taken the token; the token is held in memory for \
     the next send";

async fn expect(
    order: &Order,
    commit: Commit,
    placed: Placed,
    line: Option<String>,
    queue: Queue,
    taken: &[&str],
) {
    let seen = run(order).await;
    assert_eq!(seen.commit, commit, "the commit");
    assert_eq!(seen.placed, placed, "the variant");
    assert_eq!(seen.line, line, "the whole line");
    assert_eq!(seen.queue, queue, "what the queue holds");
    assert_eq!(seen.taken, taken, "the tokens the service took");
}

/// The queue's read fails, so no write begins; the service takes nothing. Only memory holds the
/// token, and the queue holds nothing: the line says that queuing failed, and that a write that had
/// begun may have left an entry, which none did.
#[tokio::test]
async fn the_queues_read_fails_and_the_service_takes_nothing() {
    let order = Order {
        reads: &[true],
        writes: &[],
        service_takes: &[false],
    };
    expect(
        &order,
        Commit::WithheldOwing,
        Placed::Held,
        Some(format!("{HELD}: {READ_ERROR}")),
        Queue::Empty,
        &[],
    )
    .await;
}

/// The queue's read fails and the service takes the token by the send of its own.
#[tokio::test]
async fn the_queues_read_fails_and_the_service_takes_the_token_alone() {
    let order = Order {
        reads: &[true],
        writes: &[],
        service_takes: &[true],
    };
    expect(
        &order,
        Commit::Withheld,
        Placed::Ended,
        Some(format!("{ENDED}: {READ_ERROR}")),
        Queue::Empty,
        &[TOKEN],
    )
    .await;
}

/// The queue's write is refused before it lands: the queue holds nothing, and memory holds the
/// token.
#[tokio::test]
async fn the_queues_write_is_refused_before_it_lands() {
    let order = Order {
        reads: &[],
        writes: &[Write::Refused],
        service_takes: &[false],
    };
    expect(
        &order,
        Commit::WithheldOwing,
        Placed::Held,
        Some(format!("{HELD}: {KEPT_ERROR}")),
        Queue::Empty,
        &[],
    )
    .await;
}

/// The queue's write lands and its flush fails, and the service takes nothing: memory holds the
/// token and so does the queue, which is the entry the line says a write may have left.
#[tokio::test]
async fn the_queues_write_lands_and_its_flush_fails() {
    let order = Order {
        reads: &[],
        writes: &[Write::LandsThenFails],
        service_takes: &[false],
    };
    expect(
        &order,
        Commit::WithheldOwing,
        Placed::Held,
        Some(format!("{HELD}: {KEPT_ERROR}")),
        Queue::Holds,
        &[],
    )
    .await;
}

/// The send of the queue reaches the service, the clean-up lands and then fails, and the send of
/// the token alone is not taken: the queue holds nothing, though the line says that it may.
#[tokio::test]
async fn the_clean_up_lands_and_then_fails_and_the_direct_send_fails() {
    let order = Order {
        reads: &[],
        writes: &[Write::Works, Write::LandsThenFails],
        service_takes: &[true, false],
    };
    expect(
        &order,
        Commit::Withheld,
        Placed::Queued,
        Some(format!("{QUEUED}: {REMOVED_ERROR}")),
        Queue::Empty,
        &[TOKEN],
    )
    .await;
}

/// The send of the queue reaches the service, the clean-up is refused before it lands, and the
/// send of the token alone is not taken: the queue holds the entry, and the service took the token
/// once.
#[tokio::test]
async fn the_clean_up_is_refused_and_the_direct_send_fails() {
    let order = Order {
        reads: &[],
        writes: &[Write::Works, Write::Refused],
        service_takes: &[true, false],
    };
    expect(
        &order,
        Commit::Withheld,
        Placed::Queued,
        Some(format!("{QUEUED}: {REMOVED_ERROR}")),
        Queue::Holds,
        &[TOKEN],
    )
    .await;
}

/// The send of the queue fails at its own read, after the queue took the token, and the send of the
/// token alone is not taken: the queue holds the entry.
#[tokio::test]
async fn the_send_of_the_queue_fails_and_the_direct_send_fails() {
    let order = Order {
        reads: &[false, true],
        writes: &[],
        service_takes: &[false],
    };
    expect(
        &order,
        Commit::Withheld,
        Placed::Queued,
        Some(format!("{QUEUED}: {READ_ERROR}")),
        Queue::Holds,
        &[],
    )
    .await;
}

/// The send of the queue fails at its own read, and the service takes the token by the send of its
/// own: the service has the token, and the queue still holds its entry.
#[tokio::test]
async fn the_send_of_the_queue_fails_and_the_direct_send_is_taken() {
    let order = Order {
        reads: &[false, true],
        writes: &[],
        service_takes: &[true],
    };
    expect(
        &order,
        Commit::Withheld,
        Placed::Ended,
        Some(format!("{ENDED}: {READ_ERROR}")),
        Queue::Holds,
        &[TOKEN],
    )
    .await;
}

/// The service acknowledges the queue's send: nothing failed, so the daemon writes no line, and the
/// queue is empty.
#[tokio::test]
async fn the_service_acknowledges() {
    let order = Order {
        reads: &[],
        writes: &[],
        service_takes: &[true],
    };
    expect(
        &order,
        Commit::Withheld,
        Placed::Nothing,
        None,
        Queue::Empty,
        &[TOKEN],
    )
    .await;
}

/// The service refuses the queue's send: the queue holds the entry for the next send, which is not
/// a failure of the revocation, so the daemon writes no line.
#[tokio::test]
async fn the_service_refuses() {
    let order = Order {
        reads: &[],
        writes: &[],
        service_takes: &[false],
    };
    expect(
        &order,
        Commit::Withheld,
        Placed::Nothing,
        None,
        Queue::Holds,
        &[],
    )
    .await;
}

/// Each place that ends a token it does not keep begins its line with its own words, and the rest
/// of the line is the variant's: the line of the order where both the queue and the service fail,
/// whole, for each place.
#[tokio::test]
async fn each_place_that_ends_a_token_words_its_line_with_its_own_first_words() {
    let order = Order {
        reads: &[true],
        writes: &[],
        service_takes: &[false],
    };
    let seen = run(&order).await;
    let unrevoked = seen.unrevoked.expect("the revocation failed");
    let rest = format!(
        "token: queuing the token failed and a send of the token alone was not acknowledged; a \
         write that had begun may have left its entry in place, and the service may have taken \
         the token; the token is held in memory for the next send: {READ_ERROR}"
    );
    for (whose, first_words) in [
        (WITHHELD, "kr-controller: a withheld sign-in's"),
        (CALL_OPEN, "kr-controller: a call-open sign-in's"),
        (UNKEPT, "kr-controller: an unkept sign-in's"),
        (REFUSED_EXCHANGE, "kr-controller: a refused exchange's"),
    ] {
        assert_eq!(
            failed_revocation_line(whose, &unrevoked),
            format!("{first_words} {rest}")
        );
    }
}

//! Asking the gateway what became of a notification it was already given.
//!
//! One route, one identifier, no content. `POST <gateway>/api/push/deliver/status` with
//! `Authorization: Bearer <credential secret>` and a body that carries the notification identifier
//! alone; the answer is the standard envelope around the [`PushDeliveryAck`] the gateway recorded,
//! or an envelope with no decision when it holds nothing under that identifier. The gateway is the
//! one the credential names.
//!
//! # Why this is not the delivery request again
//!
//! The delivery route takes a request and may dispatch it. Reading an outcome by presenting that
//! request again therefore rests on the gateway recognising the identifier and answering from what
//! it recorded - and on the one case where it does not, an identifier it never claimed, the repeat
//! *is* a dispatch. A host cannot tell those apart from the outside, so asking the question that
//! way means every unresolved notification carries a chance of being delivered by the act of
//! asking about it. This route carries no request to dispatch.
//!
//! # What an unanswered question means
//!
//! Nothing. Section 24 reports completion only once in-flight work is reconciled, and a question
//! nobody answered has reconciled nothing: the record keeps its unknown outcome, keeps counting as
//! outstanding, and stays in the retained artifacts a person is shown. It is never settled by
//! assuming what the silence meant.
//!
//! # How many questions
//!
//! A gateway allows each host a number of status questions an hour, and each installation the
//! same number, and it counts every question whichever of the host's paths put it: a pass asking
//! about a notification the gateway is still retrying, and the sweep over outcomes nobody knows.
//! Each path asks through a [`GatewayStatus`] of its own, whose [`StatusBudget`] holds that
//! path's fixed share: [`StatusAllowance::RECEIPTS`] and [`StatusAllowance::UNKNOWN`], which
//! together stay under the gateway's limit. A question its share cannot cover is not put. Neither
//! path can spend the other's share, so a steady run of one kind of question never stops the
//! other kind being asked.

use std::sync::{Arc, Mutex};

use kr_client::services::ServiceHttpAnswer;
use kr_delivery::push::{DeliveryStatus, StatusAnswer};
use kr_protocol::ids::NotificationId;
use kr_protocol::push::{PushDeliveryAck, PushDeliveryCredential};

use super::client::bearer;
use super::transport::DeliveryTransports;

/// The route a delivery's recorded outcome is read from.
pub const STATUS_ROUTE: &str = "/api/push/deliver/status";

/// The most bytes this client reads from an answer.
pub const MAX_ANSWER_BYTES: usize = 16 * 1024;

/// How many status questions a gateway takes in an hour from one host, and about one
/// installation's notifications: its `DELIVERY_STATUS_LIMIT`, counted in fixed windows of an hour.
pub const GATEWAY_STATUS_LIMIT: u64 = 1_200;

const MS_PER_HOUR: u64 = 60 * 60 * 1_000;

/// How many status questions one of this host's paths allows itself.
///
/// The host's shares together cover both of the gateway's counts. Every question this host puts
/// about an installation's notifications is also one of the host's own, so the installation's
/// count from this host can never pass the host's. Another host asking about the same
/// installation counts there as well, which no host can see; a question the gateway refuses for
/// that reason resolves nothing, and the record is asked about again later.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatusAllowance {
    /// How many may be asked together after a quiet spell. At least one.
    pub burst: u64,
    /// How many more an hour, at an even rate. At least one.
    pub per_hour: u64,
}

impl StatusAllowance {
    /// The share for the questions a pass asks about notifications the gateway is still
    /// retrying: a burst of 70, then one about every five seconds. At most 770 in any hour.
    ///
    /// The larger share, because these are about notifications a person may be waiting on.
    pub const RECEIPTS: Self = Self {
        burst: 70,
        per_hour: 700,
    };

    /// The share for the sweep over outcomes nobody knows: a burst of 30, then one every twelve
    /// seconds. At most 330 in any hour.
    pub const UNKNOWN: Self = Self {
        burst: 30,
        per_hour: 300,
    };

    /// The most questions this allowance lets through in any hour, wherever the hour starts.
    #[must_use]
    pub const fn most_in_an_hour(self) -> u64 {
        self.burst.saturating_add(self.per_hour)
    }
}

// Both shares together: at most 1,100 in any hour, under the gateway's limit. The margin covers a
// daemon that starts again inside the hour, whose shares start with their bursts again.
const _: () = assert!(
    StatusAllowance::RECEIPTS.most_in_an_hour()
        + StatusAllowance::UNKNOWN.most_in_an_hour()
        + StatusAllowance::RECEIPTS.burst
        + StatusAllowance::UNKNOWN.burst
        <= GATEWAY_STATUS_LIMIT
);

/// The status questions one of this host's paths may still ask, within its share.
///
/// A generic cell rate: every question moves a theoretical time on by one interval, and a question
/// is refused while that time is further ahead of the clock than the burst allows. In any hour it
/// therefore lets through at most [`StatusAllowance::most_in_an_hour`], wherever the hour starts,
/// which is what a gateway counting in fixed windows needs.
///
/// It counts on a steady clock ([`Clock::steady_ms`](super::Clock::steady_ms)), which only moves
/// forward and only as time passes, and never on the host's time of day. Setting the host's clock
/// back stops no question the allowance has earned, and setting it forward, however often, earns
/// none.
#[derive(Debug)]
pub struct StatusBudget {
    interval_ms: u64,
    tolerance_ms: u64,
    theoretical_ms: Mutex<u64>,
}

impl StatusBudget {
    /// A budget that starts with its whole burst.
    #[must_use]
    pub fn new(allowance: StatusAllowance) -> Self {
        // Rounded up, so the rate is never faster than the allowance says.
        let interval_ms = MS_PER_HOUR.div_ceil(allowance.per_hour.max(1));
        Self {
            interval_ms,
            tolerance_ms: allowance
                .burst
                .max(1)
                .saturating_sub(1)
                .saturating_mul(interval_ms),
            theoretical_ms: Mutex::new(0),
        }
    }

    /// Takes one question at `steady_ms`, a reading of the steady clock, and says whether there
    /// was one to take.
    #[must_use]
    pub fn take(&self, steady_ms: u64) -> bool {
        let Ok(mut theoretical) = self.theoretical_ms.lock() else {
            return false;
        };
        let from = (*theoretical).max(steady_ms);
        if from - steady_ms > self.tolerance_ms {
            return false;
        }
        *theoretical = from.saturating_add(self.interval_ms);
        true
    }
}

/// The gateway this host asks about its own deliveries.
///
/// The HTTP exchange is the embedder's, as it is everywhere else a managed service is reached: the
/// daemon attaches the managed transport, and a test attaches a recorder. A clone asks within the
/// same budget.
#[derive(Clone, Debug)]
pub struct GatewayStatus {
    transports: Arc<dyn DeliveryTransports>,
    runtime: tokio::runtime::Handle,
    budget: Arc<StatusBudget>,
}

impl GatewayStatus {
    /// Builds a status client over the transports this host reaches its gateways through, asking
    /// within `allowance`.
    #[must_use]
    pub fn new(
        transports: Arc<dyn DeliveryTransports>,
        runtime: tokio::runtime::Handle,
        allowance: StatusAllowance,
    ) -> Self {
        Self {
            transports,
            runtime,
            budget: Arc::new(StatusBudget::new(allowance)),
        }
    }

    fn exchange(
        &self,
        credential: &PushDeliveryCredential,
        body: &[u8],
    ) -> Result<ServiceHttpAnswer, String> {
        let transport = self.transports.to(&credential.gateway_origin)?;
        let url = format!("{}{STATUS_ROUTE}", credential.gateway_origin.as_str());
        let header = format!("Bearer {}", bearer(credential.secret.expose()));
        // The delivery pass is synchronous and runs on a blocking thread, and the transport is
        // asynchronous because every other managed-service client is. The handle is the one the
        // daemon runs on, so the exchange is driven by the daemon's own reactor rather than by a
        // second runtime built for one request.
        self.runtime
            .block_on(async {
                transport
                    .post_json(&url, body, &[("authorization", header.as_str())])
                    .await
            })
            .map_err(|error| error.to_string())
    }
}

impl DeliveryStatus for GatewayStatus {
    fn reserve(&self, steady_ms: u64) -> bool {
        self.budget.take(steady_ms)
    }

    fn status(
        &self,
        credential: &PushDeliveryCredential,
        notification_id: NotificationId,
    ) -> StatusAnswer {
        let body = match serde_json::to_vec(&StatusRequest { notification_id }) {
            Ok(body) => body,
            Err(error) => {
                return StatusAnswer::Unanswered {
                    detail: format!("the question could not be encoded: {error}"),
                };
            }
        };
        let answer = match self.exchange(credential, &body) {
            Ok(answer) => answer,
            Err(detail) => {
                return StatusAnswer::Unanswered {
                    detail: format!("the gateway did not answer: {detail}"),
                };
            }
        };
        if answer.body.len() > MAX_ANSWER_BYTES {
            return StatusAnswer::Unanswered {
                detail: format!(
                    "the gateway's answer was {} bytes, past the {MAX_ANSWER_BYTES} this host \
                     reads",
                    answer.body.len()
                ),
            };
        }
        match answer.status {
            200 => match serde_json::from_slice::<Envelope>(&answer.body) {
                Ok(Envelope {
                    ok: true,
                    data: Some(ack),
                }) => StatusAnswer::Recorded(Box::new(ack)),
                // The gateway answered and holds nothing. That is a fact about its records, and
                // this host draws no conclusion about the notification from it.
                Ok(Envelope { ok: true, data: _ }) => StatusAnswer::NoRecord {
                    detail: "the gateway holds no outcome under that identifier".to_owned(),
                },
                Ok(_) => StatusAnswer::Unanswered {
                    detail: "the gateway refused the question".to_owned(),
                },
                Err(error) => StatusAnswer::Unanswered {
                    detail: format!("the gateway's answer could not be read: {error}"),
                },
            },
            404 => StatusAnswer::NoRecord {
                detail: "the gateway holds no outcome under that identifier".to_owned(),
            },
            // A refused credential is renewed rather than retried, and a question this host may
            // not ask resolves nothing. Both leave the record where it is.
            status => StatusAnswer::Unanswered {
                detail: format!("the gateway answered {status} to the question"),
            },
        }
    }
}

/// The question, which carries an identifier and nothing else.
#[derive(serde::Serialize)]
struct StatusRequest {
    notification_id: NotificationId,
}

/// The standard envelope the gateway answers with.
#[derive(serde::Deserialize)]
struct Envelope {
    ok: bool,
    data: Option<PushDeliveryAck>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_budget_lets_its_burst_through_and_then_one_question_an_interval() {
        let budget = StatusBudget::new(StatusAllowance {
            burst: 3,
            per_hour: 60,
        });
        let now = 1_700_000_000_000;
        assert!(budget.take(now));
        assert!(budget.take(now));
        assert!(budget.take(now));
        assert!(!budget.take(now), "the burst is spent");
        assert!(!budget.take(now + 59_999));
        assert!(budget.take(now + 60_000), "one more a minute");
        assert!(!budget.take(now + 60_000));
        assert!(
            budget.take(now + 10 * 60_000),
            "and after a quiet spell the burst is back"
        );
        assert!(budget.take(now + 10 * 60_000));
        assert!(budget.take(now + 10 * 60_000));
        assert!(
            !budget.take(now + 10 * 60_000),
            "but never more than the burst"
        );
    }

    /// The steady reading a budget counts on is measured from one origin, so readings taken a
    /// fraction of a millisecond apart, however many, add up to the time that passed.
    #[test]
    fn the_steady_reading_loses_no_time_however_often_it_is_read() {
        use crate::push::{Clock, SystemClock};

        let first = SystemClock.steady_ms();
        let started = std::time::Instant::now();
        let mut last = first;
        let mut readings = 0_u64;
        while started.elapsed() < std::time::Duration::from_millis(20) {
            let reading = SystemClock.steady_ms();
            assert!(reading >= last, "a steady reading never goes back");
            last = reading;
            readings += 1;
        }
        let end = SystemClock.steady_ms();
        assert!(readings > 20, "read more often than once a millisecond");
        assert!(
            end - first >= 19,
            "20 ms passed and the steady clock moved {} ms",
            end - first
        );
    }

    /// The gateway counts in fixed windows of an hour that start wherever its first question falls,
    /// so the shares have to hold for every hour, not only the hours a clock would name. Both asked
    /// as often as they allow for three hours, no hour sees more than the gateway takes.
    #[test]
    fn both_shares_together_stay_under_the_gateway_limit_in_every_hour() {
        let receipts = StatusBudget::new(StatusAllowance::RECEIPTS);
        let unknown = StatusBudget::new(StatusAllowance::UNKNOWN);
        let start = 1_700_000_000_000;
        let mut taken: Vec<u64> = Vec::new();
        for at in (0..3 * MS_PER_HOUR / 100).map(|step| start + step * 100) {
            if receipts.take(at) {
                taken.push(at);
            }
            if unknown.take(at) {
                taken.push(at);
            }
        }
        let most = StatusAllowance::RECEIPTS.most_in_an_hour()
            + StatusAllowance::UNKNOWN.most_in_an_hour();
        assert!(most < GATEWAY_STATUS_LIMIT);
        let mut busiest = 0;
        for (index, &from) in taken.iter().enumerate() {
            let within = taken[index..].partition_point(|&at| at < from + MS_PER_HOUR);
            busiest = busiest.max(within as u64);
        }
        assert!(busiest <= most, "{busiest} in one hour");
        assert!(
            busiest > StatusAllowance::RECEIPTS.per_hour + StatusAllowance::UNKNOWN.per_hour,
            "and the busiest hour had both bursts"
        );
    }
}

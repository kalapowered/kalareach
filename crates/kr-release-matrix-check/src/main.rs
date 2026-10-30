//! Whether the signed release matrix lists a tier for this build.
//!
//! A release is published only if the matrix the managed service publishes, verified under the key
//! this build pins, serves the package version this build carries: a host that runs the release
//! reads the same matrix the same way, and a matrix that lists no tier for it refuses that host a
//! new lease on the managed relay service. The program is run in the job that publishes a release
//! and nowhere else.
//!
//! `kr-release-matrix-check --origin <origin>` reads `<origin>/api/release-matrix`. The origin has
//! no default, and the key and the version have no argument: they are the ones this build carries.
//!
//! | Exit | Meaning |
//! | --- | --- |
//! | 0 | A tier serves this build. When only a later tier does, a warning says the network half of the rollout is the operator's to have deployed first. |
//! | 1 | The release is refused: no tier serves it, the reply did not verify, the service publishes no matrix, or it answered with another status that is not a fault that passes. |
//! | 2 | The service did not answer, answered with a fault that passes (408, 429, a 5xx other than 501), or answered with more than a matrix is. Asking again may mend it. |
//! | 64 | The arguments are not `--origin <origin>`. |

use std::process::ExitCode;
use std::sync::Arc;

use kr_client::services::http::HttpService;
use kr_client::services::matrix::{self, Pins, Refusal, Unread, Unsupported};
use kr_client::services::{ServiceHttp, managed_response_limits};
use kr_protocol::hello::PACKAGE_VERSION;
use kr_protocol::service::GatewayOrigin;

const USAGE: &str = "usage: kr-release-matrix-check --origin <origin>";

fn main() -> ExitCode {
    let mut arguments = std::env::args().skip(1);
    let origin = match (
        arguments.next().as_deref(),
        arguments.next(),
        arguments.next(),
    ) {
        (Some("--origin"), Some(origin), None) => origin,
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(64);
        }
    };
    let Ok(origin) = GatewayOrigin::new(&origin) else {
        eprintln!("the origin is not one this client addresses");
        return ExitCode::from(64);
    };
    let Ok(http) = HttpService::with(
        origin.clone(),
        kr_client::services::HttpDeadlines::default(),
        managed_response_limits(),
    ) else {
        eprintln!("no transport to the service can be built on this machine");
        return ExitCode::from(2);
    };
    let http: Arc<dyn ServiceHttp> = Arc::new(http);
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        eprintln!("no runtime can be built on this machine");
        return ExitCode::from(2);
    };
    let answer = runtime.block_on(matrix::check_release(
        &*http,
        &origin,
        &Pins::production(),
        PACKAGE_VERSION,
    ));
    match answer {
        Ok(supported) if supported.compatible => {
            println!(
                "release {PACKAGE_VERSION}: served by the compatible tier of the release matrix, revision {}",
                supported.revision
            );
            ExitCode::SUCCESS
        }
        Ok(supported) => {
            println!(
                "::warning::release {PACKAGE_VERSION} is served only by a later tier of the release matrix, revision {}: deploy that tier's relay and discovery versions before this release reaches hosts",
                supported.revision
            );
            ExitCode::SUCCESS
        }
        Err(refusal) => {
            println!("::error::{}", reason(refusal));
            ExitCode::from(refusal.exit_code())
        }
    }
}

/// Why the release is not supported, in words a person reads in the job's log.
fn reason(refusal: Unsupported) -> String {
    match refusal {
        Unsupported::OutsideEveryTier { revision } => format!(
            "release {PACKAGE_VERSION} is in no tier of the release matrix at revision {revision}: publish a matrix revision that lists it first"
        ),
        Unsupported::NotVerified(why) => format!(
            "the published release matrix was not accepted: {}",
            match why {
                Refusal::Unreadable => "it is not one document of a shape this build reads",
                Refusal::NewerSchema => "it is of a schema newer than this build reads",
                Refusal::Malformed => "it breaks a rule of its own",
                Refusal::Revision => "its revision is not a counter",
                Refusal::Signature => "its signature does not verify under the key this build pins",
                Refusal::Older | Refusal::Conflicts => "it conflicts with the copy held",
                Refusal::BelowFirst => "its revision is below the first this build reads",
            }
        ),
        Unsupported::Unread(why) => format!(
            "the release matrix was not read: {}",
            match why {
                Unread::Unreachable => {
                    "the service did not answer, or answered with more than a matrix is".to_owned()
                }
                Unread::NoMatrix => "the service publishes no matrix".to_owned(),
                Unread::Refused(status) => format!("the service answered with status {status}"),
            }
        ),
    }
}

//! What the deployed site says about itself.
//!
//! `/api/health` is unauthenticated and read-only, and names the exact commit the deployment is
//! running, so a run can say which build it checked. It is read through the transport a native
//! client reaches managed services with: certificate and host-name verification, finite deadlines,
//! a bounded answer and no redirects.

use kr_client::services::account::AccountHttp;
use kr_client::services::http::{HttpDeadlines, HttpService, ResponseLimits};
use kr_protocol::service::GatewayOrigin;

/// The deployment's own account of itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Health {
    /// The service that answered.
    pub service: String,
    /// The deployment environment it says it is.
    pub environment: String,
    /// The release it reports.
    pub version: String,
    /// The commit it is running: forty lower-case hexadecimal characters.
    pub commit: String,
}

/// Reads `/api/health` at `origin`.
///
/// # Errors
///
/// Returns what was wrong: no answer, an answer that is not a health report, a service that does
/// not say it is serving, or one that does not name the commit it runs.
pub async fn health(origin: &GatewayOrigin) -> Result<Health, String> {
    let transport = HttpService::with(
        origin.clone(),
        HttpDeadlines::default(),
        ResponseLimits::default(),
    )
    .map_err(|error| format!("no transport for the origin: {error}"))?;
    let address = format!("{}/api/health", origin.as_str());
    let answer = transport
        .get(&address, &[])
        .await
        .map_err(|error| format!("/api/health did not answer: {error}"))?;
    if answer.status != 200 {
        return Err(format!("/api/health answered {}", answer.status));
    }
    let report: serde_json::Value = serde_json::from_slice(&answer.body)
        .map_err(|error| format!("/api/health answered something that is not JSON: {error}"))?;
    let text = |name: &str| report[name].as_str().unwrap_or_default().to_owned();
    if text("status") != "ok" {
        return Err(format!(
            "/api/health says its status is {:?}",
            report["status"]
        ));
    }
    let commit = text("commit");
    let named = commit.len() == 40
        && commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !named {
        return Err(format!(
            "/api/health does not name the commit it runs: {:?}",
            report["commit"]
        ));
    }
    Ok(Health {
        service: text("service"),
        environment: text("environment"),
        version: text("version"),
        commit,
    })
}

//! The owner's user-verification ceremony.
//!
//! Section 10 wants a protected native ceremony on the unlocked owner device for a rights-enlarging
//! action, and says plainly what will not do: a click that desktop automation can synthesise is not
//! proof that a person was present. So the ceremony is not a dialog this application draws. On
//! macOS it is `LAContext`, which the window server presents and this process cannot drive.
//!
//! What this module returns is a *presence* result. The confirmation itself is the host's: it binds
//! the action digest, the destination keys, the host, the nonce and the expiry, and it records the
//! user-presence verification and the challenge-consumption transition in its acceptance record.
//! This is the part that has to happen on the device, and it is deliberately the only part here.

use serde::Serialize;

use crate::error::{CommandError, Result};

/// What the platform said about the person in front of the device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Presence {
    /// True only when the platform's own ceremony completed.
    pub verified: bool,
    /// Which ceremony ran, so the host's acceptance record can name it.
    pub mechanism: String,
    /// What the person was asked to authorise, repeated back.
    pub reason: String,
}

/// The longest reason this application will put in front of a person.
const MAX_REASON_LEN: usize = 200;

/// Runs the platform's user-verification ceremony.
///
/// # Errors
///
/// Returns `UNAVAILABLE` on a platform or device with no such ceremony, because a client that
/// answered "verified" without one would be making the claim section 10 forbids. Returns
/// `PERMISSION_DENIED` when the ceremony ran and the person did not complete it.
pub fn verify_owner_presence(reason: &str) -> Result<Presence> {
    let reason = reason.trim();
    if reason.is_empty() || reason.len() > MAX_REASON_LEN {
        return Err(CommandError::invalid(
            "the ceremony states what is being authorised, in one short line",
        ));
    }
    if reason.chars().any(char::is_control) {
        return Err(CommandError::invalid(
            "the ceremony's reason is one line of plain text",
        ));
    }
    platform_verify(reason)
}

#[cfg(target_os = "macos")]
#[expect(
    unsafe_code,
    reason = "the user-verification ceremony is a call into Apple's LocalAuthentication runtime; \
              this is the only function in this crate that leaves safe Rust"
)]
fn platform_verify(reason: &str) -> Result<Presence> {
    use objc2_foundation::NSString;
    use objc2_local_authentication::{LAContext, LAPolicy};

    let context = unsafe { LAContext::new() };
    let policy = LAPolicy::DeviceOwnerAuthentication;
    let localised = NSString::from_str(reason);

    // `canEvaluatePolicy` is what distinguishes a device that has no ceremony from a person who
    // declined one. Without it, both would read as a refusal and the interface could not tell the
    // owner to use a separately paired owner device instead.
    if unsafe { context.canEvaluatePolicy_error(policy) }.is_err() {
        return Err(CommandError::unavailable(
            "this device has no user-verification ceremony; confirm from a separately paired \
             owner device",
        ));
    }

    let (sender, receiver) = std::sync::mpsc::channel();
    let handler = block2::RcBlock::new(move |success: objc2::runtime::Bool, _error: *mut objc2_foundation::NSError| {
        let _ = sender.send(success.as_bool());
    });
    unsafe {
        context.evaluatePolicy_localizedReason_reply(policy, &localised, &handler);
    }
    let verified = receiver
        .recv_timeout(std::time::Duration::from_secs(120))
        .map_err(|_| {
            CommandError::unavailable("the user-verification ceremony was not completed")
        })?;

    if !verified {
        return Err(CommandError::refused(
            "the user-verification ceremony was not completed",
        ));
    }
    Ok(Presence {
        verified: true,
        mechanism: "macos.local_authentication.device_owner".to_owned(),
        reason: reason.to_owned(),
    })
}

#[cfg(not(target_os = "macos"))]
fn platform_verify(_reason: &str) -> Result<Presence> {
    // Windows Hello and the Linux desktop portals are the equivalents on the other two desktops,
    // and neither is wired up yet. Answering "verified" here would be the exact claim section 10
    // refuses, so the application says it cannot verify and the owner confirms from a device that
    // can.
    Err(CommandError::unavailable(
        "this platform has no user-verification ceremony yet; confirm from a separately paired \
         owner device",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ceremony_without_a_stated_reason_is_refused() {
        for reason in ["", "   ", "line\nbreak"] {
            let error = verify_owner_presence(reason).expect_err("a reason is required");
            assert_eq!(error.code, kr_protocol::error::ErrorCode::InvalidArgument);
        }
    }

    #[test]
    fn an_over_long_reason_is_refused() {
        let reason = "a".repeat(MAX_REASON_LEN + 1);
        let error = verify_owner_presence(&reason).expect_err("a reason is one short line");
        assert_eq!(error.code, kr_protocol::error::ErrorCode::InvalidArgument);
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn a_platform_without_a_ceremony_says_so_rather_than_claiming_presence() {
        let error = verify_owner_presence("Confirm this new device")
            .expect_err("no ceremony, no claim");
        assert_eq!(error.code, kr_protocol::error::ErrorCode::ResourceUnavailable);
    }
}

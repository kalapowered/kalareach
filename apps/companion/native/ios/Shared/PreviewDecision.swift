//
//  What the extension shows, and why.
//
//  Section 16 names four conditions under which the generic alert stands: the preview key is not
//  available, the device is locked before its first unlock, decryption fails, and the extension
//  runs out of time. They are not four code paths; they are four answers from one decision, so
//  they are written once, here, where a test can drive every one of them.
//
//  The generic alert is never replaced by anything this decision is unsure of. A preview is shown
//  only when a key opened a live envelope addressed to this device.
//

import Foundation

/// What the extension decided to show.
enum PreviewDecision: Equatable {
    /// The decrypted text, which replaces the alert body.
    case reveal(String)
    /// The generic alert the payload already carried, with the reason it stands.
    case generic(GenericReason)
}

/// Why the generic alert stands.
enum GenericReason: String, Equatable {
    /// The payload carried no preview, which is what a host sends when previews are off.
    case noPreview = "no_preview"
    /// The payload carried a preview this build could not read.
    case malformedPreview = "malformed_preview"
    /// No preview key has been provisioned on this device.
    case keyUnavailable = "key_unavailable"
    /// The device has not been unlocked since it started.
    case lockedBeforeFirstUnlock = "locked_before_first_unlock"
    /// The preview is addressed to a key this device does not hold.
    case notForThisDevice = "not_for_this_device"
    /// The preview's own lifetime has run out.
    case expired = "expired"
    /// The ciphertext did not authenticate.
    case decryptionFailed = "decryption_failed"
    /// The extension ran out of time before it finished.
    case timedOut = "timed_out"
}

/// Opens a sealed preview. The production implementation is the shared client's own primitive.
protocol PreviewOpening {
    /// Returns the plaintext, or throws when the ciphertext does not authenticate.
    func open(envelope: PreviewEnvelope, key: Data) throws -> String
}

/// Why an opener refused.
enum PreviewOpenFailure: Error, Equatable {
    /// The ciphertext did not authenticate under this key.
    case authentication
    /// This build carries no opener, so nothing can be decrypted here.
    case unavailable
}

/// The whole decision, from the payload to what is shown.
struct PreviewDecider {
    let keys: PreviewKeyReading
    let opener: PreviewOpening
    /// The key identifiers this device holds, so a preview for another device is refused early.
    let deviceKeyIDs: Set<Data>

    /// Decides what one notification shows.
    ///
    /// The order matters and it is deliberate: everything that can be decided without the key is
    /// decided first, so a locked device does not go looking in a keychain it cannot read, and a
    /// preview addressed elsewhere is never opened against a key it was not sealed to.
    func decide(userInfo: [AnyHashable: Any], nowMilliseconds: UInt64) -> PreviewDecision {
        let envelope: PreviewEnvelope
        do {
            envelope = try PreviewEnvelope.parse(userInfo: userInfo)
        } catch PreviewParseFailure.absent {
            return .generic(.noPreview)
        } catch {
            return .generic(.malformedPreview)
        }

        guard envelope.isLive(atMilliseconds: nowMilliseconds) else {
            return .generic(.expired)
        }
        guard deviceKeyIDs.isEmpty || deviceKeyIDs.contains(envelope.routing.recipientKeyID) else {
            return .generic(.notForThisDevice)
        }

        let key: Data
        do {
            key = try keys.key(forRecipient: envelope.routing.recipientKeyID)
        } catch PreviewKeyUnavailable.lockedBeforeFirstUnlock {
            return .generic(.lockedBeforeFirstUnlock)
        } catch {
            return .generic(.keyUnavailable)
        }

        do {
            let text = try opener.open(envelope: envelope, key: key)
            let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
            // An envelope that opens to nothing is not a preview. The alert the host chose stands.
            return trimmed.isEmpty ? .generic(.decryptionFailed) : .reveal(trimmed)
        } catch {
            return .generic(.decryptionFailed)
        }
    }
}

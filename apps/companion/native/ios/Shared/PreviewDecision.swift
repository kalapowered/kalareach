//
//  What the extension shows, and why.
//
//  Section 16 names four conditions under which the generic alert stands: the preview key is not
//  available, the device is locked before its first unlock, decryption fails, and the extension
//  runs out of time. They are not four code paths; they are four answers from one decision, so
//  they are written once, here, where a test can drive every one of them. Two more are told apart
//  because they mean something else to whoever reads the log: a host this device holds no key for,
//  and a preview that opened and had nothing to show.
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
    /// This device holds no key for the host the preview says it came from: its previews are off
    /// here, or this device never asked for them.
    case senderUnknown = "sender_unknown"
    /// The preview opened and authenticated, and the host had sealed nothing to show.
    case emptyPreview = "empty_preview"
}

extension PreviewDecision {
    /// A name for what was decided, which a device check reads back.
    var reasonName: String {
        switch self {
        case .reveal: return "revealed"
        case let .generic(reason): return reason.rawValue
        }
    }
}

/// What opening a sealed preview came to.
enum PreviewOpened: Equatable {
    /// The text the host sealed to show.
    case text(String)
    /// The preview was refused, for the reason the opener names (never for any of its content).
    case refused(String)
}

/// Opens a sealed preview. The production implementation is the Rust function the library carries.
protocol PreviewOpening {
    /// Opens `preview`, the text of the sealed envelope as the gateway sent it, with this device's
    /// seed and the sender's public key. `alert` is the generic alert the notification is shown
    /// with, which the sealed preview repeats and which has to match.
    func open(
        preview: String,
        alert: String,
        seed: Data,
        senderKey: Data,
        nowMilliseconds: UInt64
    ) -> PreviewOpened
}

/// The whole decision, from the payload to what is shown.
struct PreviewDecider {
    let keys: PreviewKeyReading
    let opener: PreviewOpening
    /// The key identifiers this device holds, so a preview for another device is refused early.
    let deviceKeyIDs: Set<Data>

    /// Decides what one notification shows. `alert` is the generic alert the notification is shown
    /// with (the system's own copy of it, `aps.alert.body`), which the sealed preview repeats.
    ///
    /// The order matters and it is deliberate: everything that can be decided without a key is
    /// decided first, so a locked device does not go looking in a keychain it cannot read, and a
    /// preview addressed elsewhere is never opened against a key it was not sealed to.
    func decide(
        userInfo: [AnyHashable: Any],
        alert: String,
        nowMilliseconds: UInt64
    ) -> PreviewDecision {
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

        // The host's key is asked first: a phone whose every host has previews off holds no seed
        // either, and the reason is then that no key is held for the host.
        let senderKey: Data
        do {
            senderKey = try keys.senderKey(forSender: envelope.routing.senderKeyID)
        } catch {
            return .generic(Self.reason(for: error, whenAbsent: .senderUnknown))
        }
        let seed: Data
        do {
            seed = try keys.recipientSeed(forRecipient: envelope.routing.recipientKeyID)
        } catch {
            return .generic(Self.reason(for: error, whenAbsent: .keyUnavailable))
        }

        // The envelope was read as a payload that parsed, so both members are text.
        guard let preview = userInfo["preview"] as? String else { return .generic(.malformedPreview) }
        switch opener.open(
            preview: preview,
            alert: alert,
            seed: seed,
            senderKey: senderKey,
            nowMilliseconds: nowMilliseconds
        ) {
        case let .refused(reason):
            return .generic(Self.reason(forRefusal: reason))
        case let .text(text):
            let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
            // An envelope that opens to nothing is not a preview. The alert the host chose stands.
            return trimmed.isEmpty ? .generic(.emptyPreview) : .reveal(trimmed)
        }
    }

    /// Why a key could not be had: the lock is its own reason, and a key that is not there is
    /// `whenAbsent`. Anything else the keychain said, including a build that states no shared group,
    /// is no key to be had, which is the same answer to the person and a different one to whoever
    /// configures the build.
    private static func reason(for error: Error, whenAbsent: GenericReason) -> GenericReason {
        switch error as? PreviewKeyUnavailable {
        case .lockedBeforeFirstUnlock: return .lockedBeforeFirstUnlock
        case .notProvisioned: return whenAbsent
        default: return .keyUnavailable
        }
    }

    /// The reason the generic alert stands for a refusal the opener named.
    private static func reason(forRefusal refusal: String) -> GenericReason {
        switch refusal {
        case "expired": return .expired
        case "empty_preview": return .emptyPreview
        default: return .decryptionFailed
        }
    }
}

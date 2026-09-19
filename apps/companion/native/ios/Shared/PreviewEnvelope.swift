//
//  The sealed preview an APNs payload carries, and what can be read from it before it is opened.
//
//  A notification arrives with a generic alert already in it. The ciphertext beside that alert is
//  a sealed envelope from a host this device paired with: a 24-byte nonce, the routing that names
//  the two keys and when it expires, and the padded ciphertext. Everything here is parsing and
//  checking. Nothing here decrypts, because what can be decided before decryption decides whether
//  decryption is attempted at all.
//

import Foundation

/// What the payload says about the sealed preview, before anything is opened.
struct PreviewRouting: Equatable {
    let envelopeID: String
    let recipientKeyID: Data
    let senderKeyID: Data
    let expiresAtMilliseconds: UInt64
    let sizeBucketBytes: UInt64
}

/// One sealed preview, as it arrives.
struct PreviewEnvelope: Equatable {
    let routing: PreviewRouting
    let nonce: Data
    let ciphertext: Data
}

/// Why a payload could not be read as a sealed preview.
enum PreviewParseFailure: Error, Equatable {
    /// The payload carries no preview at all, which is the ordinary case for a generic alert.
    case absent
    /// A field is missing or is not the shape the protocol declares.
    case malformed(String)
}

/// The nonce length of the sealing construction, in bytes.
let previewNonceLength = 24

/// The length of a key identifier, in bytes.
let previewKeyIDLength = 32

extension PreviewEnvelope {
    /// Reads a sealed preview out of the notification's own user info.
    ///
    /// Every failure is a reason to show the generic alert, so the parse is strict: a field that is
    /// not what the protocol declares is a malformed payload rather than something to interpret.
    static func parse(userInfo: [AnyHashable: Any]) throws -> PreviewEnvelope {
        guard let preview = userInfo["preview"] as? [String: Any] else {
            throw PreviewParseFailure.absent
        }
        guard let routing = preview["routing"] as? [String: Any] else {
            throw PreviewParseFailure.malformed("routing")
        }
        guard let nonce = base64URL(preview["nonce"]), nonce.count == previewNonceLength else {
            throw PreviewParseFailure.malformed("nonce")
        }
        guard let ciphertext = base64URL(preview["ciphertext"]), !ciphertext.isEmpty else {
            throw PreviewParseFailure.malformed("ciphertext")
        }
        guard let envelopeID = routing["envelope_id"] as? String, !envelopeID.isEmpty else {
            throw PreviewParseFailure.malformed("envelope_id")
        }
        guard
            let recipient = base64URL(routing["recipient_key_id"]),
            recipient.count == previewKeyIDLength
        else {
            throw PreviewParseFailure.malformed("recipient_key_id")
        }
        guard let sender = base64URL(routing["sender_key_id"]), sender.count == previewKeyIDLength
        else {
            throw PreviewParseFailure.malformed("sender_key_id")
        }
        guard let expires = unsigned(routing["expires_at_ms"]) else {
            throw PreviewParseFailure.malformed("expires_at_ms")
        }
        guard let bucket = unsigned(routing["size_bucket_bytes"]) else {
            throw PreviewParseFailure.malformed("size_bucket_bytes")
        }
        return PreviewEnvelope(
            routing: PreviewRouting(
                envelopeID: envelopeID,
                recipientKeyID: recipient,
                senderKeyID: sender,
                expiresAtMilliseconds: expires,
                sizeBucketBytes: bucket
            ),
            nonce: nonce,
            ciphertext: ciphertext
        )
    }

    /// Whether this preview is still within the life the host gave it.
    func isLive(atMilliseconds now: UInt64) -> Bool {
        now < routing.expiresAtMilliseconds
    }
}

/// A counter, which the protocol sends as a decimal string in JSON and as a number in some clients.
private func unsigned(_ value: Any?) -> UInt64? {
    if let text = value as? String { return UInt64(text) }
    if let number = value as? NSNumber { return number.uint64Value }
    return nil
}

/// A base64url field, which the protocol uses for every byte string in JSON.
private func base64URL(_ value: Any?) -> Data? {
    guard let text = value as? String else { return nil }
    var padded = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    while padded.count % 4 != 0 { padded.append("=") }
    return Data(base64Encoded: padded)
}

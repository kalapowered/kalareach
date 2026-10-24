//
//  The keys the notification extension may open a preview with, as the application hands them over.
//
//  The application sends the whole set each time it changes, and this application makes the shared
//  keychain group hold exactly that set: a host turned off is not in it, and a seed is in it only
//  while some host that may use it is.
//

import Foundation

/// This device's preview seeds, each by the identifier of its public half, and the public key of
/// each host that may seal a preview to it, by the identifier a sealed preview names its sender by.
struct PreviewKeySet: Equatable {
    var recipients: [Data: Data]
    var senders: [Data: Data]

    /// The length of a key identifier, a seed and a public key, in bytes.
    private static let length = 32

    /// Reads the set from a command's arguments (members of standard base64). A set with a member
    /// that is not what a key is, or that names one identifier twice, is not read: the extension is
    /// never handed half of one.
    static func parse(_ arguments: [String: Any]) -> PreviewKeySet? {
        guard
            let recipients = pairs(arguments["recipients"], secret: "seed"),
            let senders = pairs(arguments["senders"], secret: "key")
        else { return nil }
        return PreviewKeySet(recipients: recipients, senders: senders)
    }

    private static func pairs(_ value: Any?, secret: String) -> [Data: Data]? {
        guard let items = value as? [[String: Any]] else { return nil }
        var read: [Data: Data] = [:]
        for item in items {
            guard
                let id = (item["id"] as? String).flatMap({ Data(base64Encoded: $0) }),
                let key = (item[secret] as? String).flatMap({ Data(base64Encoded: $0) }),
                id.count == length, key.count == length,
                read.updateValue(key, forKey: id) == nil
            else { return nil }
        }
        return read
    }
}

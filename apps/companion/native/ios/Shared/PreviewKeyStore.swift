//
//  The limited preview key, and the four reasons it may not be usable.
//
//  The extension holds one key and no other: a key that opens a notification preview and cannot
//  open anything else. It lives in the Keychain access group both the application and this
//  extension are in, written by the application after its own authentication and read here.
//
//  It is stored with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`. Before the first unlock
//  after a restart the item is unreadable by design, and that is not an error: it is the device
//  saying it has not been opened yet, and the right answer is the generic alert.
//

import Foundation
import Security

/// Why the preview key is not available.
enum PreviewKeyUnavailable: Error, Equatable {
    /// No key has been provisioned for this device yet.
    case notProvisioned
    /// The device has not been unlocked since it started, so protected items cannot be read.
    case lockedBeforeFirstUnlock
    /// The keychain refused for another reason, which is reported with its own status.
    case refused(OSStatus)
}

/// Where a preview key is kept and how it is found.
struct PreviewKeyLocation {
    /// The access group both the application and the extension are entitled to.
    let accessGroup: String
    /// The service the item is filed under.
    let service: String

    /// The location this build uses.
    static let shared = PreviewKeyLocation(
        accessGroup: "$(AppIdentifierPrefix)to.kala.reach.companion.shared",
        service: "to.kala.reach.companion.notification-preview"
    )
}

/// Reads the limited preview key.
protocol PreviewKeyReading {
    func key(forRecipient recipientKeyID: Data) throws -> Data
}

/// The keychain-backed reader the extension uses.
struct KeychainPreviewKeyStore: PreviewKeyReading {
    let location: PreviewKeyLocation

    init(location: PreviewKeyLocation = .shared) {
        self.location = location
    }

    func key(forRecipient recipientKeyID: Data) throws -> Data {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: location.service,
            kSecAttrAccount as String: recipientKeyID.base64EncodedString(),
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        query[kSecAttrAccessGroup as String] = location.accessGroup

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            guard let data = result as? Data else { throw PreviewKeyUnavailable.refused(status) }
            return data
        case errSecItemNotFound:
            throw PreviewKeyUnavailable.notProvisioned
        case errSecInteractionNotAllowed:
            // The device is locked and has not been unlocked since it started.
            throw PreviewKeyUnavailable.lockedBeforeFirstUnlock
        default:
            throw PreviewKeyUnavailable.refused(status)
        }
    }
}

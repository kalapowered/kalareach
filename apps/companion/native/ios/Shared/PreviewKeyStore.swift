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
    /// This build states no shared access group, so there is nowhere to look.
    case groupNotConfigured
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
    ///
    /// Nil when this build did not state one, which is a build that has not been configured rather
    /// than a device with no key: every read then refuses by name instead of quietly searching the
    /// process's own default group and finding nothing.
    let accessGroup: String?
    /// The service the item is filed under.
    let service: String

    /// The key the build writes the shared group under.
    static let groupKey = "KRSharedKeychainGroup"

    /// The key the build writes this application's own group under.
    static let privateGroupKey = "KRPrivateKeychainGroup"

    /// The location this build uses.
    ///
    /// The group carries the team prefix, which only the build knows: Swift does not expand a
    /// build variable inside a string literal, so the expanded value is read from the description
    /// the build wrote rather than written here and silently left unexpanded.
    static let shared = PreviewKeyLocation(
        accessGroup: resolvedGroup(),
        service: "to.kala.reach.companion.notification-preview"
    )

    /// Reads the group the build resolved, refusing anything still carrying a build variable.
    static func resolvedGroup(bundle: Bundle = .main) -> String? {
        group(named: groupKey, in: bundle)
    }

    /// Reads this application's own group, which the extension is not entitled to.
    static func resolvedPrivateGroup(bundle: Bundle = .main) -> String? {
        group(named: privateGroupKey, in: bundle)
    }

    private static func group(named key: String, in bundle: Bundle) -> String? {
        guard let stated = bundle.object(forInfoDictionaryKey: key) as? String,
            !stated.isEmpty,
            !stated.contains("$(")
        else {
            return nil
        }
        return stated
    }
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
        guard let group = location.accessGroup else {
            // Searching without a group would search this process's own default group, find
            // nothing, and report a device with no key. This build simply has no group.
            throw PreviewKeyUnavailable.groupNotConfigured
        }
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: location.service,
            kSecAttrAccount as String: recipientKeyID.base64EncodedString(),
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        query[kSecAttrAccessGroup as String] = group

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

//
//  Keys on the device, in the place the platform keeps them.
//
//  Two properties matter and both are chosen rather than defaulted. An item is readable only after
//  the device has been unlocked once since it started, which is what makes a notification
//  extension able to read a preview key on a device in a pocket and unable to read one on a device
//  that has not been opened since it restarted. And an item never leaves this device: no backup,
//  no keychain synchronisation, no transfer to a new phone.
//
//  The application writes; the extension only reads. That asymmetry is the whole point of the
//  shared access group: one limited key crosses the boundary and nothing else does.
//

import Foundation
import Security

/// What a stored key is for.
enum StoredKeyPurpose: String {
    /// The limited key the notification extension reads.
    case notificationPreview = "to.kala.reach.companion.notification-preview"
    /// This device's own authorisation key, which the extension is not entitled to.
    case deviceAuthorisation = "to.kala.reach.companion.device-authorisation"
}

/// Writes and removes keys the application owns.
struct SecureKeys {
    /// The group the extension shares, or nil when this build states none.
    let accessGroup: String?

    init(accessGroup: String? = PreviewKeyLocation.shared.accessGroup) {
        self.accessGroup = accessGroup
    }

    /// Stores one key, replacing whatever was filed under the same account.
    @discardableResult
    func store(_ key: Data, purpose: StoredKeyPurpose, account: String) -> OSStatus {
        var item: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: purpose.rawValue,
            kSecAttrAccount as String: account,
            kSecValueData as String: key,
            // After the first unlock, and only on this device. A key that syncs is a key on a
            // machine nobody authorised.
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        // Only the preview key is shared with the extension. The authorisation key stays in the
        // application's own keychain, where an extension cannot reach it at all.
        if purpose == .notificationPreview {
            guard let accessGroup else {
                // Writing it into this process's own group would put a key where the extension
                // cannot read it, and the person would see generic alerts with no explanation.
                return errSecMissingEntitlement
            }
            item[kSecAttrAccessGroup as String] = accessGroup
        }
        SecItemDelete(item as CFDictionary)
        return SecItemAdd(item as CFDictionary, nil)
    }

    /// Removes every key of one purpose, which is what signing out does.
    @discardableResult
    func removeAll(purpose: StoredKeyPurpose) -> OSStatus {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: purpose.rawValue,
        ]
        if purpose == .notificationPreview, let accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        return SecItemDelete(query as CFDictionary)
    }
}

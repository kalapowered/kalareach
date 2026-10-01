//
//  What the notification extension reports about itself when a device check asks it to.
//
//  A check sends a notification carrying a nonce and the name of the application's private group.
//  The extension answers inside the notification it hands the system: why it showed what it
//  showed, whether it could read the item the check filed in the shared group, and what the
//  keychain said when it tried the private one, which it is not entitled to. The application reads
//  that back from its own delivered notifications. Compiled into debug builds only.
//

#if DEBUG
import CryptoKit
import Foundation
import Security

/// The items a check files, and the names the extension finds them by.
enum ProbeFixture {
    /// The service the application files its own authorisation key under.
    static let privateService = "to.kala.reach.device-authorisation"

    /// The 32-byte identifier a check files its items under, derived from its nonce.
    static func recipientKeyID(nonce: String) -> Data {
        Data(SHA256.hash(data: Data("recipient:\(nonce)".utf8)))
    }

    /// The account, as the extension's own key lookup spells one.
    static func account(nonce: String) -> String {
        recipientKeyID(nonce: nonce).base64EncodedString()
    }

    /// The value a check files, which the extension has to read back unchanged.
    static func value(nonce: String) -> Data {
        Data(SHA256.hash(data: Data("value:\(nonce)".utf8)))
    }
}

/// Reads one keychain item from one named group.
protocol ProbeKeychainReading {
    func read(group: String, service: String, account: String) -> (status: OSStatus, data: Data?)
}

/// The keychain-backed reader.
struct KeychainProbeReader: ProbeKeychainReading {
    func read(group: String, service: String, account: String) -> (status: OSStatus, data: Data?) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: group,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        return (status, result as? Data)
    }
}

/// Builds what the extension adds to a notification a check sent.
struct ExtensionProbe {
    /// How the shared item is read: the product's own reader.
    let keys: PreviewKeyReading
    /// How the private one is tried.
    let `private`: ProbeKeychainReading

    /// The facts to add to the notification's user info, or nil when no check sent it.
    func additions(for userInfo: [AnyHashable: Any], reason: String) -> [String: Any]? {
        guard let nonce = userInfo["kr_probe_nonce"] as? String else { return nil }
        var added: [String: Any] = ["kr_ext_reason": reason]

        do {
            let value = try keys.key(forRecipient: ProbeFixture.recipientKeyID(nonce: nonce))
            added["kr_ext_shared_match"] = value == ProbeFixture.value(nonce: nonce)
        } catch {
            added["kr_ext_shared_match"] = false
            added["kr_ext_shared_unavailable"] = Self.name(of: error)
        }

        if let group = userInfo["kr_probe_group"] as? String {
            let attempt = `private`.read(
                group: group,
                service: ProbeFixture.privateService,
                account: ProbeFixture.account(nonce: nonce)
            )
            added["kr_ext_private_status"] = Int(attempt.status)
            added["kr_ext_private_data"] = attempt.data != nil
        } else {
            added["kr_ext_private_status"] = Int(errSecParam)
            added["kr_ext_private_data"] = false
        }
        return added
    }

    private static func name(of error: Error) -> String {
        guard let unavailable = error as? PreviewKeyUnavailable else { return "unexpected" }
        switch unavailable {
        case .groupNotConfigured: return "groupNotConfigured"
        case .notProvisioned: return "notProvisioned"
        case .lockedBeforeFirstUnlock: return "lockedBeforeFirstUnlock"
        case let .refused(status): return "refused(\(status))"
        }
    }
}
#endif

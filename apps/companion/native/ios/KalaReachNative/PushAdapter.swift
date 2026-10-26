//
//  What the platform plugin asks of this application about notifications.
//
//  The plugin's package cannot see this target, so it finds the adapter by the name of its class and
//  sends it a request by selector (`PushLink`), as it does the voice call. The adapter answers each
//  command from what only this process knows: where the person's answer to the system's question
//  stands, the token the provider gave this installation, the record of the registration being
//  waited for, the limited key store the notification extension reads, and the screen a tap on a
//  notification opened the application on.
//
//  The decisions are the application's, in Rust. This reports facts and carries out requests.
//

import Foundation
import Security
import UserNotifications

/// Where the person's answer to the system's notification question stands, and asking it.
protocol NotificationPermissions {
    /// The answer as it stands, read without asking.
    func current(then: @escaping (PushPermission) -> Void)
    /// Asks the person when they have not answered, and says what the answer is.
    func ask(then: @escaping (PushPermission) -> Void)
}

/// Files the limited preview keys where the notification extension reads them.
protocol LimitedKeyWriting {
    /// Makes the place the extension reads hold exactly `keys`. False when the keychain refused.
    func replace(with keys: PreviewKeySet) -> Bool
}

/// The token the provider gave this installation. Whether a registration still names it is the
/// application's to compare, by the token's digest, each time it looks.
final class PushTokenStore {
    static let tokenKey = "to.kala.reach.push.token"

    private let defaults: UserDefaults

    init(defaults: UserDefaults = .standard) { self.defaults = defaults }

    func token() -> String? { defaults.string(forKey: Self.tokenKey) }

    /// Keeps a token the provider gave, replacing the one held.
    func given(_ token: String) {
        if defaults.string(forKey: Self.tokenKey) != token {
            defaults.set(token, forKey: Self.tokenKey)
        }
    }
}

/// The adapter the plugin finds by name.
@objc(KRPushAdapter)
public final class PushAdapter: NSObject {
    /// The names the plugin reaches this by.
    enum Link {
        static let command = "command"
        static let arguments = "arguments"
        static let reply = "reply"
    }

    private typealias Reply = @convention(block) (NSString?, NSString?, NSString?) -> Void

    private static let product = PushAdapter(
        permissions: ProductPermissions(),
        tokens: PushTokenStore(),
        record: PendingFile.inApplicationSupport(),
        keys: ProductLimitedKeys(),
        route: .shared
    )

    /// The one adapter, which the plugin asks for by `krShared`.
    @objc(krShared)
    public static func krShared() -> PushAdapter { product }

    private let permissions: NotificationPermissions
    private let tokens: PushTokenStore
    private let record: PendingFile?
    private let keys: LimitedKeyWriting
    private let route: NotificationRoute
    private let clock: () -> UInt64
    private let permissionRead: (PushPermission) -> Void

    /// `permissionRead` is told every answer the system is read for, so the registration goes on from
    /// what the system says now: a person who agreed in the system's settings, after refusing, has the
    /// APNs token handed on without being asked again.
    init(
        permissions: NotificationPermissions,
        tokens: PushTokenStore,
        record: PendingFile?,
        keys: LimitedKeyWriting,
        route: NotificationRoute,
        clock: @escaping () -> UInt64 = { UInt64(Date().timeIntervalSince1970 * 1000) },
        permissionRead: @escaping (PushPermission) -> Void = { permission in
            DispatchQueue.main.async { PushRegistration.shared.permissionKnown(permission) }
        }
    ) {
        self.permissions = permissions
        self.tokens = tokens
        self.record = record
        self.keys = keys
        self.route = route
        self.clock = clock
        self.permissionRead = permissionRead
        super.init()
    }

    /// Takes one request: the command, its arguments as JSON text and a block that answers once.
    @objc(krCall:)
    public func krCall(_ request: NSDictionary) {
        guard
            let command = request[Link.command] as? String,
            let arguments = request[Link.arguments] as? String,
            let replying = request[Link.reply] as AnyObject?
        else { return }
        let reply = unsafeBitCast(replying, to: Reply.self)
        run(command, arguments) { result, code, message in
            reply(result.map { $0 as NSString }, code.map { $0 as NSString }, message.map { $0 as NSString })
        }
    }

    /// Carries out one command and answers with its result as JSON text, or a code and a message.
    func run(_ command: String, _ arguments: String, then reply: @escaping (String?, String?, String?) -> Void) {
        let args = (try? JSONSerialization.jsonObject(with: Data(arguments.utf8))) as? [String: Any] ?? [:]
        func answer(_ object: [String: Any]) { reply(Self.text(object), nil, nil) }
        func refuse(_ message: String) { reply(nil, "engine", message) }

        switch command {
        case "pushPermission":
            permissions.current { [permissionRead] in
                permissionRead($0)
                answer(["state": Self.word($0)])
            }
        case "pushAskPermission":
            permissions.ask { [permissionRead] in
                permissionRead($0)
                answer(["state": Self.word($0)])
            }
        case "pushToken":
            answer(["token": tokens.token() ?? NSNull()])
        case "pushPendingSet":
            guard let record, let kept = args["record"] as? [String: Any],
                let text = Self.text(kept), (try? record.write(text)) != nil
            else { return refuse("the pending registration could not be kept") }
            answer([:])
        case "pushPendingGet":
            guard let record else { return refuse("the pending registration could not be read") }
            let text = record.read(nowMilliseconds: clock())
            let parsed = text.flatMap { try? JSONSerialization.jsonObject(with: Data($0.utf8)) }
            answer(["record": parsed ?? NSNull()])
        case "pushPendingClear":
            guard let record, (try? record.clear()) != nil else {
                return refuse("the pending registration could not be removed")
            }
            answer([:])
        case "pushPreviewKeys":
            guard let set = PreviewKeySet.parse(args) else { return refuse("the preview keys are not keys") }
            guard keys.replace(with: set) else { return refuse("the preview keys could not be filed") }
            answer([:])
        case "pushRoute":
            answer(["route": route.take() ?? NSNull()])
        default:
            reply(nil, "unavailable", "the application has no such notification command")
        }
    }

    private static func word(_ permission: PushPermission) -> String {
        switch permission {
        case .granted: return "granted"
        case .refused: return "denied"
        case .unknown: return "unknown"
        }
    }

    private static func text(_ object: [String: Any]) -> String? {
        guard let data = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }
}

/// The system's own question, and the registration it leads to.
private struct ProductPermissions: NotificationPermissions {
    func current(then: @escaping (PushPermission) -> Void) {
        UNUserNotificationCenter.current().getNotificationSettings { settings in
            then(PushPermission(status: settings.authorizationStatus))
        }
    }

    func ask(then: @escaping (PushPermission) -> Void) {
        current { permission in
            guard permission == .unknown else { return then(permission) }
            DispatchQueue.main.async { PushRegistration.shared.start(then: then) }
        }
    }
}

/// The shared keychain group the extension reads, written the way `SecureKeys` writes every key.
private struct ProductLimitedKeys: LimitedKeyWriting {
    func replace(with keys: PreviewKeySet) -> Bool {
        let store = SecureKeys()
        let parts: [(StoredKeyPurpose, [Data: Data])] = [
            (.notificationPreview, keys.recipients),
            (.notificationPreviewSender, keys.senders),
        ]
        // What is no longer wanted goes first: a key removed is the direction that matters, and a
        // failure to add one after it leaves the generic alert, never a preview that was turned off.
        for (purpose, wanted) in parts {
            guard let held = store.accounts(purpose: purpose) else { return false }
            let wantedAccounts = Set(wanted.keys.map { $0.base64EncodedString() })
            for account in held where !wantedAccounts.contains(account) {
                guard store.remove(purpose: purpose, account: account) == errSecSuccess else { return false }
            }
        }
        for (purpose, wanted) in parts {
            for (id, key) in wanted {
                guard store.store(key, purpose: purpose, account: id.base64EncodedString()) == errSecSuccess
                else { return false }
            }
        }
        return true
    }
}

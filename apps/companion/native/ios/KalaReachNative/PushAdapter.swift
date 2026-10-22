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
import UserNotifications

/// Where the person's answer to the system's notification question stands, and asking it.
protocol NotificationPermissions {
    /// The answer as it stands, read without asking.
    func current(then: @escaping (PushPermission) -> Void)
    /// Asks the person when they have not answered, and says what the answer is.
    func ask(then: @escaping (PushPermission) -> Void)
}

/// Files the limited preview key where the notification extension reads it.
protocol LimitedKeyWriting {
    /// Files `seed` under the recipient identifier (the key identifier in standard base64). False when
    /// the keychain refused.
    func write(recipientKeyID: String, seed: Data) -> Bool
}

/// The token the provider gave this installation, and whether it changed since it was last asked.
final class PushTokenStore {
    static let tokenKey = "to.kala.reach.push.token"
    static let changedKey = "to.kala.reach.push.token-changed"

    private let defaults: UserDefaults

    init(defaults: UserDefaults = .standard) { self.defaults = defaults }

    func token() -> String? { defaults.string(forKey: Self.tokenKey) }

    /// Keeps a token the provider gave, and notes that it changed when it is not the one held.
    func given(_ token: String) {
        if defaults.string(forKey: Self.tokenKey) != token {
            defaults.set(token, forKey: Self.tokenKey)
            defaults.set(true, forKey: Self.changedKey)
        }
    }

    /// Whether the token changed since this was last asked. Asking clears it.
    func takeChanged() -> Bool {
        let changed = defaults.bool(forKey: Self.changedKey)
        if changed { defaults.set(false, forKey: Self.changedKey) }
        return changed
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

    init(
        permissions: NotificationPermissions,
        tokens: PushTokenStore,
        record: PendingFile?,
        keys: LimitedKeyWriting,
        route: NotificationRoute,
        clock: @escaping () -> UInt64 = { UInt64(Date().timeIntervalSince1970 * 1000) }
    ) {
        self.permissions = permissions
        self.tokens = tokens
        self.record = record
        self.keys = keys
        self.route = route
        self.clock = clock
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
            permissions.current { answer(["state": Self.word($0)]) }
        case "pushAskPermission":
            permissions.ask { answer(["state": Self.word($0)]) }
        case "pushToken":
            answer(["token": tokens.token() ?? NSNull()])
        case "pushTokenChanged":
            answer(["changed": tokens.takeChanged()])
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
        case "pushLimitedKey":
            guard let id = args["recipient_key_id"] as? String,
                let seed = (args["seed"] as? String).flatMap({ Data(base64Encoded: $0) }),
                keys.write(recipientKeyID: id, seed: seed)
            else { return refuse("the preview key could not be filed") }
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
    func write(recipientKeyID: String, seed: Data) -> Bool {
        SecureKeys().store(seed, purpose: .notificationPreview, account: recipientKeyID) == errSecSuccess
    }
}

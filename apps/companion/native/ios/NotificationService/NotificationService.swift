//
//  The Notification Service Extension.
//
//  This is the half of the product that runs when nothing else does. The application may be
//  suspended, terminated or never started since the device restarted, and no JavaScript context
//  exists anywhere: the system starts this extension, gives it the payload and a few hundred
//  milliseconds, and shows whatever it is handed.
//
//  So the rule is the one the specification states: the generic alert the payload already carries
//  is what is shown unless a preview was opened. The extension's own deadline is honoured by
//  handing back the untouched content in `serviceExtensionTimeWillExpire`, which is the system
//  telling this process its time is up.
//

import UserNotifications

/// What the extension reads keys from, opens a preview with, and tells the time by. The system builds
/// the extension itself, so a test cannot hand it these: it replaces them here, in one place.
struct ExtensionParts {
    var keys: PreviewKeyReading
    var opener: PreviewOpening
    var nowMilliseconds: () -> UInt64

    /// The shared keychain group, the Rust library's opener and the system clock.
    static let production = ExtensionParts(
        keys: KeychainPreviewKeyStore(),
        opener: RustPreviewOpener(),
        nowMilliseconds: { UInt64(Date().timeIntervalSince1970 * 1000) }
    )
}

/// The one completion the extension owes the system for one notification. `didReceive` and the
/// system's call that the time is up each hand content to it, and whichever comes first is the only
/// one that reaches the system: the other finds nothing to complete. The system makes the expiry
/// call from another thread while `didReceive` may still be opening a preview, so the two meet here
/// under one lock.
final class OneCompletion {
    private let lock = NSLock()
    private var handler: ((UNNotificationContent) -> Void)?
    private let original: UNNotificationContent

    /// Takes the content as it arrived and the handler the system gave for it.
    init(original: UNNotificationContent, handler: @escaping (UNNotificationContent) -> Void) {
        self.original = original
        self.handler = handler
    }

    /// Hands `content` to the system, unless something already completed the notification.
    func complete(with content: UNNotificationContent) {
        lock.lock()
        let taken = handler
        handler = nil
        lock.unlock()
        taken?(content)
    }

    /// The time is up: the content as it arrived goes to the system, unless something already
    /// completed the notification.
    func expire() {
        complete(with: original)
    }
}

/// The extension the system starts for every notification this application receives.
final class NotificationService: UNNotificationServiceExtension {
    /// The parts the extension is built from.
    static var parts = ExtensionParts.production

    /// The completion of the notification being served, for the system's call that the time is up.
    /// Each `didReceive` makes its own and finishes through it, so an instance the system serves a
    /// second notification with never completes that one with the first's handler.
    private let lock = NSLock()
    private var current: OneCompletion?

    override func didReceive(
        _ request: UNNotificationRequest,
        withContentHandler contentHandler: @escaping (UNNotificationContent) -> Void
    ) {
        let completion = OneCompletion(original: request.content, handler: contentHandler)
        lock.lock()
        current = completion
        lock.unlock()

        let parts = Self.parts
        let decider = PreviewDecider(keys: parts.keys, opener: parts.opener, deviceKeyIDs: [])
        // The generic alert the notification is shown with is the one the sealed preview repeats.
        let decision = decider.decide(
            userInfo: request.content.userInfo,
            alert: request.content.body,
            nowMilliseconds: parts.nowMilliseconds()
        )

        switch decision {
        case let .reveal(text):
            guard let content = request.content.mutableCopy() as? UNMutableNotificationContent else {
                handBack(request.content, for: request, decision: decision, through: completion)
                return
            }
            content.body = text
            handBack(content, for: request, decision: decision, through: completion)
        case .generic:
            // The alert the host chose is already in the content. It is handed back unchanged
            // rather than rewritten, so nothing this extension knows leaks into a generic alert.
            handBack(request.content, for: request, decision: decision, through: completion)
        }
    }

    /// Hands the content to the system, if the time has not run out first. A debug build answers a
    /// device check first, inside the notification it hands back; every other build hands back
    /// exactly what was decided.
    private func handBack(
        _ content: UNNotificationContent,
        for request: UNNotificationRequest,
        decision: PreviewDecision,
        through completion: OneCompletion
    ) {
        #if DEBUG
        // A device run reads this to see that the extension ran: the reason it showed what it showed,
        // and nothing of the notification.
        NSLog("KalaReachExtension: ran, %@", decision.reasonName)
        let probe = ExtensionProbe(keys: Self.parts.keys, private: KeychainProbeReader())
        if let added = probe.additions(for: request.content.userInfo, reason: decision.reasonName),
            let answered = content.mutableCopy() as? UNMutableNotificationContent
        {
            var info = answered.userInfo
            for (key, value) in added { info[key] = value }
            answered.userInfo = info
            completion.complete(with: answered)
            return
        }
        #endif
        completion.complete(with: content)
    }

    override func serviceExtensionTimeWillExpire() {
        // Out of time. Whatever was going to be decided is not decided, and the generic alert is
        // what the person sees, which is exactly the specified behaviour rather than a fallback.
        // A decision that finishes after this finds the notification already completed.
        lock.lock()
        let serving = current
        lock.unlock()
        serving?.expire()
    }
}

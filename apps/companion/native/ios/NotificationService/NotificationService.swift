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

/// The extension the system starts for every notification this application receives.
final class NotificationService: UNNotificationServiceExtension {
    private var deliver: ((UNNotificationContent) -> Void)?
    private var original: UNNotificationContent?

    override func didReceive(
        _ request: UNNotificationRequest,
        withContentHandler contentHandler: @escaping (UNNotificationContent) -> Void
    ) {
        deliver = contentHandler
        original = request.content

        let decider = PreviewDecider(
            keys: KeychainPreviewKeyStore(),
            opener: SharedClientPreviewOpener(),
            deviceKeyIDs: []
        )
        let decision = decider.decide(
            userInfo: request.content.userInfo,
            nowMilliseconds: UInt64(Date().timeIntervalSince1970 * 1000)
        )

        switch decision {
        case let .reveal(text):
            guard let content = request.content.mutableCopy() as? UNMutableNotificationContent else {
                contentHandler(request.content)
                return
            }
            content.body = text
            contentHandler(content)
        case .generic:
            // The alert the host chose is already in the content. It is handed back unchanged
            // rather than rewritten, so nothing this extension knows leaks into a generic alert.
            contentHandler(request.content)
        }
    }

    override func serviceExtensionTimeWillExpire() {
        // Out of time. Whatever was going to be decided is not decided, and the generic alert is
        // what the person sees, which is exactly the specified behaviour rather than a fallback.
        if let deliver, let original {
            deliver(original)
        }
        deliver = nil
        original = nil
    }
}

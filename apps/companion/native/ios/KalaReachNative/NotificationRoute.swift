//
//  Where a tap on a notification goes.
//
//  The system tells the application when the person opened it by tapping a notification. What the
//  application keeps is one word, the screen to open, and it hands it to the page once, when the
//  page asks. It is never a session, a request or anything the payload said: what needs the person
//  is on the screen the word names.
//

import Foundation
import UserNotifications

/// The one screen a tap opens, kept until it is asked for.
final class NotificationRoute {
    /// The one this application uses.
    static let shared = NotificationRoute()

    /// The screen that holds what needs the person.
    static let attention = "attention"

    private let lock = NSLock()
    private var waiting: String?

    /// Notes that the application was opened on `route`.
    func opened(on route: String) {
        lock.lock()
        defer { lock.unlock() }
        waiting = route
    }

    /// The screen the application was opened on since this was last asked, once.
    func take() -> String? {
        lock.lock()
        defer { lock.unlock() }
        defer { waiting = nil }
        return waiting
    }
}

/// Hears the tap, and nothing else: a notification arriving while the application is in front is
/// left to the system's own rules.
final class NotificationRouter: NSObject, UNUserNotificationCenterDelegate {
    /// The one that is the notification centre's delegate, held for the life of the process because
    /// the centre does not keep its delegate alive.
    static let shared = NotificationRouter()

    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping () -> Void
    ) {
        if response.actionIdentifier == UNNotificationDefaultActionIdentifier {
            NotificationRoute.shared.opened(on: NotificationRoute.attention)
        }
        completionHandler()
    }
}

//
//  Registering this device for notifications, without a JavaScript context.
//
//  The system asks for a device token at launch, and the answer arrives on a delegate callback
//  that has nothing to do with the interface. If registration waited for the page to load and ask
//  for it, a launch straight into the background — which is most launches on a phone — would
//  register nothing.
//
//  So this runs from the application's own start, records the token it is given, and leaves the
//  gateway registration to whoever asks for the token next. Nothing here talks to a network.
//

import Foundation
import UIKit
import UserNotifications

/// What this device's registration looks like right now.
enum PushRegistrationState: Equatable {
    /// Nothing has been asked for yet.
    case idle
    /// The person has not answered the system's permission prompt.
    case awaitingPermission
    /// The person refused. The application works; it just cannot raise a notification.
    case refused
    /// The system gave this device a token.
    case registered(token: String)
    /// The system refused to register, with its own reason.
    case failed(reason: String)
}

/// Asks the system for a token and records what comes back.
final class PushRegistration: NSObject {
    /// The one this application uses.
    static let shared = PushRegistration()

    private(set) var state: PushRegistrationState = .idle

    /// Asks for permission and, if it is given, for a token.
    ///
    /// Called at launch rather than from the page: a launch into the background has no page.
    func start(center: UNUserNotificationCenter = .current()) {
        state = .awaitingPermission
        center.requestAuthorization(options: [.alert, .sound, .badge]) { [weak self] granted, _ in
            guard let self else { return }
            guard granted else {
                self.state = .refused
                return
            }
            DispatchQueue.main.async {
                UIApplication.shared.registerForRemoteNotifications()
            }
        }
    }

    /// Records the token the system produced.
    func registered(deviceToken: Data) {
        state = .registered(token: deviceToken.map { String(format: "%02x", $0) }.joined())
    }

    /// Records why the system would not register this device.
    func failed(with error: Error) {
        state = .failed(reason: error.localizedDescription)
    }
}

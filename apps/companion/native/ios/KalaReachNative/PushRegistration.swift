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

/// Where the person's answer to the notification permission stands.
enum PushPermission: Equatable {
    /// Not known yet: the person has not been asked, or the answer has not been read.
    case unknown
    /// The person agreed.
    case granted
    /// The person said no, or took a yes back.
    case refused
}

/// Asks the system for a token and records what comes back.
final class PushRegistration: NSObject {
    /// The one this application uses.
    static let shared = PushRegistration()

    private(set) var state: PushRegistrationState = .idle

    /// Where the person's answer stands.
    private(set) var permission: PushPermission = .unknown

    /// The APNs token the system gave, held until the person has agreed.
    private var apnsToken: Data?

    /// Called with the APNs token when it may go to Firebase, which makes an installation and a
    /// registration token of its own from it.
    ///
    /// Registering for a token needs no agreement, so the token can arrive before the person has
    /// answered, and goes on only once they have agreed. Called again for a token that changes.
    var onTokenUsable: ((Data) -> Void)?

    /// Whether Firebase has been given this device's APNs token, which is what a registration token
    /// needs before it can be asked for: one made earlier was made for an APNs token that may since
    /// have changed, and a message sent to it cannot be delivered. Withdrawn when the person takes
    /// their agreement back and when the system refuses to register; given again with a new token.
    ///
    /// Nothing here keeps a registration token. The one a message is sent to is asked of Firebase
    /// when this is true, so it is always made for the APNs token that is current.
    private(set) var tokenHandedToFirebase = false

    /// Asks for permission and, if it is given, for a token.
    ///
    /// Not called by the application's own launch: asking belongs where the person can see why.
    /// What it records, it records on the main thread, where the system's token callbacks arrive.
    func start(center: UNUserNotificationCenter = .current()) {
        state = .awaitingPermission
        center.requestAuthorization(options: [.alert, .sound, .badge]) { [weak self] granted, _ in
            DispatchQueue.main.async {
                guard let self else { return }
                self.permissionKnown(granted ? .granted : .refused)
                guard granted else {
                    self.state = .refused
                    return
                }
                UIApplication.shared.registerForRemoteNotifications()
            }
        }
    }

    /// Records where the person's answer stands, however it was learnt.
    func permissionKnown(_ answer: PushPermission) {
        permission = answer
        if answer != .granted { tokenHandedToFirebase = false }
        offerTokenToFirebase()
    }

    /// Records the token the system produced.
    func registered(deviceToken: Data) {
        apnsToken = deviceToken
        tokenHandedToFirebase = false
        state = .registered(token: deviceToken.map { String(format: "%02x", $0) }.joined())
        offerTokenToFirebase()
    }

    private func offerTokenToFirebase() {
        guard permission == .granted, let token = apnsToken, let hand = onTokenUsable else { return }
        hand(token)
        tokenHandedToFirebase = true
    }

    /// Records why the system would not register this device.
    func failed(with error: Error) {
        apnsToken = nil
        tokenHandedToFirebase = false
        state = .failed(reason: error.localizedDescription)
    }
}

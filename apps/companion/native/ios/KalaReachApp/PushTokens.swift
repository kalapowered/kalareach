//
//  Keeping the registration token Firebase gives.
//
//  Firebase makes a registration token from the APNs token once the person has agreed to
//  notifications, and gives a new one when it replaces it. The application keeps the token where the
//  platform plugin reads it, and each look the application makes compares the digest of it with
//  the digest each host registered with, so the registration the person asked for is repeated for
//  a new token. Nothing here sends the token anywhere.
//

import FirebaseMessaging
import Foundation

final class PushTokens: NSObject, MessagingDelegate {
    /// The one this application uses, held for the life of the process because Firebase does not
    /// keep its delegate alive.
    static let shared = PushTokens()

    func messaging(_ messaging: Messaging, didReceiveRegistrationToken fcmToken: String?) {
        if let fcmToken { PushTokenStore().given(fcmToken) }
    }
}

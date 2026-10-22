//
//  A device run's way to hand the application a push the simulator will not.
//
//  `xcrun simctl push` delivers an alert to the system, which shows it, and hands a push that only
//  wakes the application to nobody: the delegate's method for it is never called. The registration
//  challenge is such a push. So a run puts the message's data in a file of the application's own data
//  directory and posts a notification, and this calls the delegate's method for a push that woke the
//  application, the one the system would call, with that data. What it shows is the application's
//  receiver from that method on: the decision, the key, the signature and the post to the gateway. It
//  does not show that the system calls the method, which a real device does.
//
//  Compiled into debug builds only. A release build has neither the listener nor the file.
//

#if DEBUG
import Foundation
import UIKit

enum PushDeviceRun {
    private static let name = "to.kala.reach.probe.push-message" as CFString

    /// Listens for a run's message.
    static func listen() {
        CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(), nil, { _, _, _, _, _ in
            DispatchQueue.main.async { PushDeviceRun.deliver() }
        }, name, nil, .deliverImmediately)
    }

    /// Calls the delegate's method for a push that woke the application, with the data a run left.
    private static func deliver() {
        guard
            let support = try? FileManager.default.url(
                for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: false),
            let delegate = UIApplication.shared.delegate as? NSObject
        else { return }
        let file = support.appendingPathComponent(Bundle.main.bundleIdentifier ?? "to.kala.reach")
            .appendingPathComponent("kr-probe").appendingPathComponent("push-message.json")
        guard
            let bytes = try? Data(contentsOf: file),
            let data = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any]
        else { return }
        try? FileManager.default.removeItem(at: file)

        let selector = Selector(("application:didReceiveRemoteNotification:fetchCompletionHandler:"))
        guard delegate.responds(to: selector) else {
            NSLog("KalaReach: the delegate does not answer for a push that woke the application")
            return
        }
        typealias Call = @convention(c) (AnyObject, Selector, AnyObject, NSDictionary, @escaping @convention(block) (UInt) -> Void) -> Void
        let call = unsafeBitCast(delegate.method(for: selector), to: Call.self)
        call(delegate, selector, UIApplication.shared, data as NSDictionary) { _ in }
    }
}
#endif

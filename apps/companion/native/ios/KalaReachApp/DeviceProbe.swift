//
//  The checks a debug build can be started to run on a device.
//
//  A test starts the application with `-KRDeviceProbe <mode>`. Each mode does one native thing in
//  the real signed process, leaves its result as an accessibility element (`ProbeSurface`) and as a
//  file in the application's own container, and never reads or keeps anything outside the
//  application. Compiled into debug builds only.
//

#if DEBUG
import CryptoKit
import FirebaseCore
import FirebaseMessaging
import Foundation
import Security
import UIKit
import UserNotifications

/// Runs one check.
enum DeviceProbe {
    /// Starts the mode a debug build was asked for.
    static func run(_ name: String) {
        guard let mode = ProbeMode(rawValue: name) else { return }
        // A check runs for a long while with nobody touching the phone, and a locked screen would
        // end it.
        UIApplication.shared.isIdleTimerDisabled = true
        switch mode {
        case .count: count()
        case .sweep: sweep()
        case .keychain: keychain()
        case .push: push()
        case .pushRead: pushRead()
        case .shots: Shots.start()
        case .audio:
            // Not part of this build of the checks.
            finish(mode, ["error": "audio is not built"])
        }
    }

    /// Makes the application's windows light or dark when the check was started to ask for it.
    static func applyColourMode() {
        guard let mode = ProbeArguments.colourMode(from: CommandLine.arguments) else { return }
        let style: UIUserInterfaceStyle = mode == .dark ? .dark : .light
        func apply(tries: Int) {
            let windows = UIApplication.shared.windows
            if windows.isEmpty, tries < 100 {
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) { apply(tries: tries + 1) }
                return
            }
            windows.forEach { $0.overrideUserInterfaceStyle = style }
            let resolved = windows.first?.traitCollection.userInterfaceStyle == .dark ? "dark" : "light"
            ProbeSurface.shared.show("colour", resolved)
        }
        DispatchQueue.main.async { apply(tries: 0) }
    }

    // MARK: Where results go

    private static func container() -> URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    }

    /// Writes a mode's result to its file and shows it.
    private static func finish(_ mode: ProbeMode, _ facts: [String: String]) {
        var report = ProbeReport()
        facts.forEach { report.set($0.key, $0.value) }
        let text = report.text
        try? text.write(to: container().appendingPathComponent("probe-\(mode.rawValue).txt"), atomically: true, encoding: .utf8)
        ProbeSurface.shared.show(mode.rawValue, text.replacingOccurrences(of: "\n", with: ";"))
    }

    // MARK: The keychain

    /// The two groups, or nil when this build names only one: a count of one says nothing about the
    /// other.
    private static func groups() -> [String]? {
        KeychainAnswer.groupsToCount(shared: PreviewKeyLocation.shared.accessGroup, private: PreviewKeyLocation.resolvedPrivateGroup())
    }

    /// How many items each query finds, by attributes alone, and which queries could not be answered.
    ///
    /// A query that failed is not an empty group: only "found some" and "not found" count.
    private static func counted(_ plan: KeychainSweepPlan) -> (total: Int, failures: [String], facts: [String: String]) {
        var total = 0
        var failures: [String] = []
        var facts: [String: String] = [:]
        for each in plan.countQueries() {
            var result: CFTypeRef?
            let status = SecItemCopyMatching(each.query as CFDictionary, &result)
            let found = status == errSecSuccess ? ((result as? [[String: Any]])?.count ?? 0) : 0
            let itemClass = each.query[kSecClass as String].map { "\($0)" } ?? "?"
            switch KeychainAnswer.counted(status: status, found: found) {
            case .found(let count):
                total += count
                facts["count.\(each.group).\(itemClass)"] = "\(count) status=\(status)"
            case .failed:
                failures.append("\(each.group).\(itemClass)=\(status)")
                facts["count.\(each.group).\(itemClass)"] = "failed status=\(status)"
            }
        }
        return (total, failures, facts)
    }

    private static func count() {
        guard let named = groups() else {
            finish(.count, ["error": "this build does not name both keychain groups", "ok": "0"])
            return
        }
        let counts = counted(KeychainSweepPlan(groups: named))
        var facts = counts.facts
        facts["total"] = String(counts.total)
        facts["groups"] = named.joined(separator: ",")
        facts["ok"] = counts.failures.isEmpty ? "1" : "0"
        if !counts.failures.isEmpty { facts["failed"] = counts.failures.joined(separator: ",") }
        finish(.count, facts)
    }

    private static func sweep() {
        guard let named = groups() else {
            finish(.sweep, ["error": "this build does not name both keychain groups", "ok": "0"])
            return
        }
        let plan = KeychainSweepPlan(groups: named)
        var facts: [String: String] = [:]
        var failures: [String] = []
        for each in plan.deleteQueries() {
            let status = SecItemDelete(each.query as CFDictionary)
            let itemClass = each.query[kSecClass as String].map { "\($0)" } ?? "?"
            facts["delete.\(each.group).\(itemClass)"] = "status=\(status)"
            if !KeychainAnswer.deleteLeftNothing(status: status) { failures.append("delete.\(each.group).\(itemClass)=\(status)") }
        }
        let remaining = counted(plan)
        facts.merge(remaining.facts) { current, _ in current }
        failures += remaining.failures
        facts["remaining"] = String(remaining.total)
        // Clean only when nothing is left and every answer was an answer: a refusal is not an empty
        // group.
        facts["ok"] = remaining.total == 0 && failures.isEmpty ? "1" : "0"
        if !failures.isEmpty { facts["failed"] = failures.joined(separator: ",") }
        finish(.sweep, facts)
    }

    /// Files the two fixtures a check reads back, and reads them.
    private static func fileFixtures(nonce: String) -> [String: String] {
        let keys = SecureKeys()
        let value = ProbeFixture.value(nonce: nonce)
        let account = ProbeFixture.account(nonce: nonce)
        var facts: [String: String] = [:]
        facts["shared.write"] = String(keys.store(value, purpose: .notificationPreview, account: account))
        facts["private.write"] = String(keys.store(value, purpose: .deviceAuthorisation, account: account))
        let reader = KeychainProbeReader()
        if let shared = keys.sharedGroup {
            let read = reader.read(group: shared, service: PreviewKeyLocation.shared.service, account: account)
            facts["shared.read"] = String(read.status)
            facts["shared.match"] = read.data == value ? "1" : "0"
        }
        if let own = keys.privateGroup {
            let read = reader.read(group: own, service: ProbeFixture.privateService, account: account)
            facts["private.read"] = String(read.status)
            facts["private.match"] = read.data == value ? "1" : "0"
        }
        return facts
    }

    private static func keychain() {
        let nonce = UUID().uuidString
        var facts = fileFixtures(nonce: nonce)

        // A group under the team's prefix that this application is not entitled to: the keychain
        // has to refuse the write itself, and an add that succeeds is removed and fails the check.
        if let own = PreviewKeyLocation.resolvedPrivateGroup() {
            let prefix = String(own.dropLast("to.kala.reach".count))
            let foreign = "\(prefix)to.kala.foreign"
            let item: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: "to.kala.reach.probe-foreign",
                kSecAttrAccount as String: nonce,
                kSecValueData as String: Data([0]),
                kSecAttrAccessGroup as String: foreign,
                kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            ]
            let status = SecItemAdd(item as CFDictionary, nil)
            facts["foreign.write"] = String(status)
            facts["foreign.refused"] = status == errSecMissingEntitlement ? "1" : "0"
            if status == errSecSuccess { SecItemDelete(item as CFDictionary) }
        }

        // The fixtures were only for this check.
        let keys = SecureKeys()
        facts["shared.remove"] = String(keys.removeAll(purpose: .notificationPreview))
        facts["private.remove"] = String(keys.removeAll(purpose: .deviceAuthorisation))
        finish(.keychain, facts)
    }

    // MARK: Push

    private static func push() {
        guard FirebaseApp.app() != nil else {
            finish(.push, ["firebase": "skipped"])
            return
        }
        NotificationRecorder.install()
        let nonce = UUID().uuidString
        var facts = fileFixtures(nonce: nonce)
        facts["nonce.digest"] = SHA256.hash(data: Data(nonce.utf8)).prefix(4).map { String(format: "%02x", $0) }.joined()

        // The test asks for the permission here, which the product does not at launch.
        PushRegistration.shared.start()
        waitForToken(tries: 0, nonce: nonce, facts: facts, fetching: false)
    }

    /// Set once the check has reported, so that a late answer or a timeout cannot report again.
    private static var pushReported = false

    private static func reportPush(_ facts: [String: String]) {
        guard !pushReported else { return }
        pushReported = true
        finish(.push, facts)
    }

    private static func waitForToken(tries: Int, nonce: String, facts: [String: String], fetching: Bool) {
        guard !pushReported else { return }
        var facts = facts
        var fetching = fetching
        let registration = PushRegistration.shared
        if registration.permission == .refused || registration.state == .refused {
            facts["permission"] = "refused"
            reportPush(facts)
            return
        }
        // Only the person's own answer starts this: the launch has registered for a token already,
        // and that says nothing about the permission.
        if registration.permission == .granted, case .registered = registration.state, !fetching {
            fetching = true
            facts["permission"] = "granted"
            // Agreed, so Firebase may make a registration token on its own from now on. The one this
            // check sends to is asked for after the APNs token has gone to Firebase, and arrives once
            // Firebase has the mapping.
            Messaging.messaging().isAutoInitEnabled = true
            let known = facts
            Messaging.messaging().token { token, error in
                DispatchQueue.main.async {
                    var facts = known
                    guard let token, error == nil else {
                        let failure = error as NSError?
                        facts["token"] = "error"
                        facts["token.error"] = failure.map { "\($0.domain)/\($0.code)" } ?? "none"
                        reportPush(facts)
                        return
                    }
                    let file: [String: String] = [
                        "nonce": nonce,
                        "group": PreviewKeyLocation.resolvedPrivateGroup() ?? "",
                        "fcm_token": token,
                    ]
                    if let data = try? JSONSerialization.data(withJSONObject: file) {
                        try? data.write(to: container().appendingPathComponent("probe-push.json"))
                    }
                    facts["token"] = "ready"
                    reportPush(facts)
                }
            }
        }
        guard tries < 240 else {
            facts["token"] = "timeout"
            facts["state"] = "\(registration.state)"
            facts["permission"] = "\(registration.permission)"
            reportPush(facts)
            return
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
            waitForToken(tries: tries + 1, nonce: nonce, facts: facts, fetching: fetching)
        }
    }

    private static func pushRead() {
        // The nonce of the send being read, which the push check filed with its token.
        let filed = (try? Data(contentsOf: container().appendingPathComponent("probe-push.json")))
            .flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: String] }
        let nonce = filed?["nonce"]
        UNUserNotificationCenter.current().getDeliveredNotifications { delivered in
            let sorted = DeliveredMarks.sort(delivered.map { $0.request.content.userInfo }, nonce: nonce)
            var facts: [String: String] = ["delivered": String(delivered.count)]
            for (offset, info) in sorted.matching.enumerated() {
                for key in ["kr_ext_reason", "kr_ext_shared_match", "kr_ext_shared_unavailable", "kr_ext_private_status", "kr_ext_private_data"] {
                    if let value = info[key] { facts["n\(offset + 1).\(key)"] = "\(value)" }
                }
            }
            facts["marked"] = String(sorted.matching.count)
            facts["other_marked"] = String(sorted.otherMarked)
            facts["nonce.known"] = nonce == nil ? "0" : "1"
            facts["presented_in_front"] = String(NotificationRecorder.presented())
            UNUserNotificationCenter.current().removeAllDeliveredNotifications()
            DispatchQueue.main.async { finish(.pushRead, facts) }
        }
    }
}

/// Records a notification that arrives while the application is in front, which the system does not
/// show or list unless the application says to, so a late arrival can be told from none.
final class NotificationRecorder: NSObject, UNUserNotificationCenterDelegate {
    private static let shared = NotificationRecorder()
    private static let file = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        .appendingPathComponent("probe-presented.txt")

    static func install() {
        UNUserNotificationCenter.current().delegate = shared
    }

    static func presented() -> Int {
        ((try? String(contentsOf: file, encoding: .utf8)) ?? "").split(separator: "\n").count
    }

    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        let line = notification.request.identifier + "\n"
        if let handle = try? FileHandle(forWritingTo: Self.file) {
            handle.seekToEndOfFile()
            handle.write(Data(line.utf8))
            try? handle.close()
        } else {
            try? line.write(to: Self.file, atomically: true, encoding: .utf8)
        }
        completionHandler([])
    }
}

/// Renders the application's own windows to files when a test asks.
///
/// The request is a Darwin notification the test posts, so the test needs no screenshot of its own
/// and no image can hold anything but this application: another application's banner or the lock
/// screen are not in its windows. The keyboard is a window of its own and is left out.
enum Shots {
    private static var taken = 0
    private static let name = "to.kala.reach.probe.shot" as CFString

    static func start() {
        let center = CFNotificationCenterGetDarwinNotifyCenter()
        CFNotificationCenterAddObserver(center, nil, { _, _, _, _, _ in
            DispatchQueue.main.async { Shots.capture() }
        }, name, nil, .deliverImmediately)
        ProbeSurface.shared.show("shots", "0")
    }

    private static func capture() {
        let windows = UIApplication.shared.windows
            .filter { !String(describing: type(of: $0)).contains("Keyboard") && !String(describing: type(of: $0)).contains("TextEffects") }
            .sorted { $0.windowLevel < $1.windowLevel }
        guard let first = windows.first else { return }
        let image = UIGraphicsImageRenderer(bounds: first.bounds).image { _ in
            for window in windows {
                window.drawHierarchy(in: window.bounds, afterScreenUpdates: true)
            }
        }
        let directory = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0].appendingPathComponent("shots")
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        taken += 1
        let file = directory.appendingPathComponent(String(format: "shot-%02d.png", taken))
        try? image.pngData()?.write(to: file)
        ProbeSurface.shared.show("shots", String(taken))
    }
}
#endif

import LocalAuthentication
import UIKit

/// Which ceremony this iPhone or iPad offers its owner, in the words the plugin's Rust half reads.
///
/// Face ID or Touch ID when one is set up, the passcode when the device has one and no biometric,
/// and none when the device has no passcode: a device that is not locked cannot check that its
/// owner is the one holding it.
enum OwnerPresenceKind: String {
  case faceID = "face_id"
  case touchID = "touch_id"
  case passcode
  case none

  static func offered() -> OwnerPresenceKind {
    let context = LAContext()
    var error: NSError?
    if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
      // The type is valid once the policy has been asked about.
      switch context.biometryType {
      case .faceID: return .faceID
      case .touchID: return .touchID
      default: break
      }
    }
    return context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) ? .passcode : .none
  }
}

/// One run of the ceremony: an alert that says what is being confirmed, then the system's own
/// Face ID, Touch ID or passcode prompt, both inside one deadline.
///
/// Face ID starts when it is asked and completes when the face is seen, so a tap that only opens it
/// would be enough to confirm by looking at the phone. The alert makes the person choose to go on,
/// with the words of what they confirm in front of them. A "Continue" that comes after the deadline
/// starts nothing, because the alert is gone by then and the run has answered.
///
/// Everything here runs on the main queue. The run answers once: with the outcome of the system's
/// prompt, with "not confirmed" when the person cancels, the deadline passes, or the application
/// goes to the background, and with "unavailable" when the device has no ceremony to run. A person
/// who leaves the application and comes back finds the request unanswered, and starts it again.
final class OwnerPresenceRun {
  private var reply: ((String) -> Void)?
  private var alert: UIAlertController?
  private var context: LAContext?
  private var deadline: DispatchWorkItem?
  private var background: NSObjectProtocol?
  private let reason: String
  private let within: TimeInterval

  init(reason: String, within: TimeInterval, reply: @escaping (String) -> Void) {
    self.reason = reason
    self.within = within
    self.reply = reply
  }

  /// Whether the run is still waiting for the person: it has not answered.
  var isRunning: Bool { reply != nil }

  /// Shows the alert over `presenter` and starts the clock.
  func begin(over presenter: UIViewController) {
    let expiry = DispatchWorkItem { [weak self] in self?.finish("not_confirmed") }
    deadline = expiry
    DispatchQueue.main.asyncAfter(deadline: .now() + max(0, within), execute: expiry)
    // Before the system's prompt starts there is no context for the system to cancel when the
    // application leaves, so the run watches for that itself, and ends with the alert.
    background = NotificationCenter.default.addObserver(
      forName: UIApplication.didEnterBackgroundNotification, object: nil, queue: .main
    ) { [weak self] _ in self?.finish("not_confirmed") }

    let alert = UIAlertController(
      title: "Confirm on this device", message: reason, preferredStyle: .alert)
    alert.addAction(
      UIAlertAction(title: "Cancel", style: .cancel) { [weak self] _ in
        self?.finish("not_confirmed")
      })
    alert.addAction(
      UIAlertAction(title: "Continue", style: .default) { [weak self] _ in
        self?.evaluate()
      })
    self.alert = alert
    presenter.present(alert, animated: true)
  }

  private func evaluate() {
    // A "Continue" that arrives once the run has answered starts nothing.
    guard reply != nil else { return }
    let context = LAContext()
    var error: NSError?
    guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
      finish("unavailable")
      return
    }
    self.context = context
    context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) {
      [weak self] success, _ in
      DispatchQueue.main.async { self?.finish(success ? "confirmed" : "not_confirmed") }
    }
  }

  private func finish(_ outcome: String) {
    guard let answer = reply else { return }
    reply = nil
    deadline?.cancel()
    deadline = nil
    if let watching = background { NotificationCenter.default.removeObserver(watching) }
    background = nil
    // The system's prompt goes with the run: a late reply lands on an invalidated context.
    context?.invalidate()
    context = nil
    if let shown = alert, shown.presentingViewController != nil {
      shown.dismiss(animated: false)
    }
    alert = nil
    answer(outcome)
  }
}

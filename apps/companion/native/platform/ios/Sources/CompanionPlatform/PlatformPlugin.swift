import AVFoundation
import AuthenticationServices
import CompanionCallLink
import CompanionSession
import SwiftRs
import Tauri
import UIKit
import WebKit

/// What one attempt asks for: the address to open and how the answer comes back.
struct SessionArguments: Decodable {
  let attempt: String
  let url: String
  let mode: String
  let httpsHost: String
  let httpsPath: String
  let scheme: String
}

/// A directory the application keeps something in.
struct PathArguments: Decodable {
  let path: String
}

#if DEBUG
  /// The notification a debug build on a simulator is asked to post.
  struct NotificationArguments: Decodable {
    let name: String
  }
#endif

/// Which attempt a call is about.
struct AttemptArguments: Decodable {
  let attempt: String
}

/// Whether the screen is kept on.
struct KeepAwakeArguments: Decodable {
  let on: Bool
}

/// What the ceremony is asked: the words of what is being confirmed, and how long it has.
struct PresenceArguments: Decodable {
  let reason: String
  let withinMs: Double
}

/// What opening a call takes: its name, and the channel its news is sent on.
struct CallOpenArguments: Decodable {
  let call: String
  let events: Channel
}

/// What the device can do, reported as facts; the plugin's Rust crate decides what they mean.
struct Capabilities: Encodable {
  let httpsCallback: Bool
  let privateKeychainGroup: String?
}

/// One result, in the platform's own terms, with the attempt it belongs to.
struct SessionEvent: Encodable {
  let attempt: String
  let kind: String
  var url: String? = nil
  var domain: String? = nil
  var code: Int? = nil
  var reason: String? = nil
}

/// The browser-backed authentication session.
///
/// The session runs in a system process, shows the origin in its own header and gives this
/// application no scripting bridge into the page. It catches the navigation to its callback itself
/// and hands the address to its completion once; the callback page never loads. An ephemeral
/// session shares no cookies with Safari, so every sign-in is a ceremony of its own.
class PlatformPlugin: Plugin, ASWebAuthenticationPresentationContextProviding {
  private var session: ASWebAuthenticationSession?
  private var waiting: Invoke?
  private let attempts = SessionAttempts()
  private let protection = ProtectedData()
  private let background = BackgroundWatch()

  /// The window is made on the main thread once the application object exists, which is when
  /// what the system says about protected data can first be read.
  override public func load(webview: WKWebView) {
    protection.refresh()
  }

  @objc public func capabilities(_ invoke: Invoke) {
    let httpsCallback = takesHttpsCallback(ProcessInfo.processInfo.operatingSystemVersion)
    let group = Bundle.main.object(forInfoDictionaryKey: "KRPrivateKeychainGroup") as? String
    invoke.resolve(Capabilities(httpsCallback: httpsCallback, privateKeychainGroup: group))
  }

  /// Marks a directory as not to be backed up, and answers only when the system says it is: the
  /// records in it mean something only beside keys that a backup does not carry to another phone.
  @objc public func keepOutOfBackup(_ invoke: Invoke) throws {
    let arguments = try invoke.parseArgs(PathArguments.self)
    var url = URL(fileURLWithPath: arguments.path, isDirectory: true)
    do {
      var values = URLResourceValues()
      values.isExcludedFromBackup = true
      try url.setResourceValues(values)
      // Asked of a new URL: one that set a value may answer from what it keeps of it.
      let asked = URL(fileURLWithPath: arguments.path, isDirectory: true)
      let kept = try asked.resourceValues(forKeys: [.isExcludedFromBackupKey])
      guard kept.isExcludedFromBackup == true else {
        invoke.reject("the system does not say that \(arguments.path) is excluded from the backup")
        return
      }
      invoke.resolve(["done": true])
    } catch {
      invoke.reject("\(arguments.path) could not be excluded from the backup: \(error.localizedDescription)")
    }
  }

  /// Whether the system says a directory is excluded from the backup.
  @objc public func backupExclusion(_ invoke: Invoke) throws {
    let arguments = try invoke.parseArgs(PathArguments.self)
    let url = URL(fileURLWithPath: arguments.path, isDirectory: true)
    do {
      let kept = try url.resourceValues(forKeys: [.isExcludedFromBackupKey])
      invoke.resolve(["excluded": kept.isExcludedFromBackup == true])
    } catch {
      invoke.reject("\(arguments.path) could not be asked about the backup: \(error.localizedDescription)")
    }
  }

  /// Whether the device's protected data can be read now, as far as the system has said.
  @objc public func protectedData(_ invoke: Invoke) {
    invoke.resolve(["available": protection.available])
  }

  /// Has the system's news that protected data became readable sent on a channel, each time.
  @objc public func watchProtectedData(_ invoke: Invoke) throws {
    protection.watch(try invoke.parseArgs(WatchArguments.self).events)
    invoke.resolve(["done": true])
  }

  /// Has the application's going to the background sent on a channel, each time.
  @objc public func watchBackground(_ invoke: Invoke) throws {
    background.watch(try invoke.parseArgs(WatchArguments.self).events)
    invoke.resolve(["done": true])
  }

  #if DEBUG
    /// Posts one of the notifications the system posts when the device is unlocked, for a debug
    /// build on a simulator, which never locks: the device is modelled as locked and then unlocked.
    @objc public func postSystemNotification(_ invoke: Invoke) throws {
      let name: Notification.Name
      switch try invoke.parseArgs(NotificationArguments.self).name {
      case "protectedDataDidBecomeAvailable":
        name = UIApplication.protectedDataDidBecomeAvailableNotification
      case "willEnterForeground":
        name = UIApplication.willEnterForegroundNotification
      default:
        invoke.reject("only the unlock and foreground notifications are posted")
        return
      }
      DispatchQueue.main.async {
        NotificationCenter.default.post(name: name, object: nil)
        invoke.resolve(["done": true])
      }
    }
  #endif

  @objc public func authenticate(_ invoke: Invoke) throws {
    let arguments = try invoke.parseArgs(SessionArguments.self)
    guard let url = URL(string: arguments.url) else {
      invoke.reject("the sign-in address does not parse")
      return
    }
    DispatchQueue.main.async {
      // One attempt at a time: a newer one ends the older one's wait.
      if let earlier = self.attempts.inProgress {
        self.session?.cancel()
        self.finish(SessionEvent(attempt: earlier, kind: "cancelled"))
      }
      let attempt = arguments.attempt
      _ = self.attempts.begin(attempt)
      self.waiting = invoke
      guard
        let configuration = sessionConfiguration(
          mode: arguments.mode, httpsHost: arguments.httpsHost, httpsPath: arguments.httpsPath,
          scheme: arguments.scheme,
          httpsTaken: takesHttpsCallback(ProcessInfo.processInfo.operatingSystemVersion))
      else {
        self.finish(SessionEvent(attempt: attempt, kind: "ended", code: -1))
        return
      }
      let completion: ASWebAuthenticationSession.CompletionHandler = { [weak self] callback, error in
        guard let self = self else { return }
        if let callback = callback {
          self.finish(
            SessionEvent(attempt: attempt, kind: "redirected", url: callback.absoluteString))
        } else {
          let failure = error as NSError?
          self.finish(
            SessionEvent(
              attempt: attempt, kind: "ended", domain: failure?.domain, code: failure?.code,
              reason: failure?.localizedFailureReason))
        }
      }
      let session: ASWebAuthenticationSession
      switch configuration.callback {
      case .https(let host, let path):
        guard #available(iOS 17.4, *) else {
          // The rules above take the HTTPS callback only from iOS 17.4, so this is not reached.
          self.finish(SessionEvent(attempt: attempt, kind: "ended", code: -1))
          return
        }
        session = ASWebAuthenticationSession(
          url: url, callback: .https(host: host, path: path), completionHandler: completion)
      case .scheme(let scheme):
        session = ASWebAuthenticationSession(
          url: url, callbackURLScheme: scheme, completionHandler: completion)
      }
      session.prefersEphemeralWebBrowserSession = configuration.ephemeral
      session.presentationContextProvider = self
      self.session = session
      if !session.start() {
        self.finish(SessionEvent(attempt: attempt, kind: "ended", code: -1))
      }
    }
  }

  @objc public func nextEvent(_ invoke: Invoke) throws {
    // The session delivers one result and ends; there is never a next one.
    invoke.reject("the authentication session delivers one result")
  }

  @objc public func cancel(_ invoke: Invoke) throws {
    let arguments = try invoke.parseArgs(AttemptArguments.self)
    DispatchQueue.main.async {
      if self.attempts.inProgress == arguments.attempt {
        // Cancelling from here dismisses the sheet without calling the completion, so the waiting
        // call is answered here.
        self.session?.cancel()
        self.finish(SessionEvent(attempt: arguments.attempt, kind: "cancelled"))
      }
      invoke.resolve(["done": true])
    }
  }

  // MARK: Reading a QR code

  /// The scan that is open, when one is: one at a time, so a newer request ends the older one.
  private var scanning: OpenScan?

  /// One request to read a code, answered once: with its outcome, or with the cancel a newer
  /// request or the scanner's own end gives.
  private final class OpenScan {
    private var invoke: Invoke?
    /// What runs once the request has its answer, which is after its scanner or picker has gone from
    /// the screen: the plugin forgets the request, and a newer request that waited goes on.
    private var afterwards: [() -> Void] = []
    /// Closes the scanner or the picker the request opened, answering it with a cancel once it has
    /// gone from the screen.
    var close: (() -> Void)?

    init(_ invoke: Invoke) { self.invoke = invoke }

    func answer(_ outcome: ScanOutcome) {
      guard let waiting = invoke else { return }
      invoke = nil
      waiting.resolve(ScanAnswer(outcome))
      let next = afterwards
      afterwards = []
      for step in next { step() }
    }

    /// Ends the request with a cancel, and runs `then` once it is answered.
    func end(then: @escaping () -> Void) {
      afterwards.append(then)
      if let close = close { close() } else { answer(.cancelled) }
    }

    /// Runs `then` once the request is answered, at once when it already is.
    func whenAnswered(_ then: @escaping () -> Void) {
      if invoke == nil { then() } else { afterwards.append(then) }
    }
  }

  /// Which sources this device reads a code from: its camera, when it has one, and the picker.
  @objc public func scanSources(_ invoke: Invoke) {
    invoke.resolve(["camera": AVCaptureDevice.default(for: .video) != nil, "photo": true])
  }

  /// What the system says of this application's use of the camera: `granted`, `denied` when the
  /// person refused it or a restriction does (the system asks no more), and `prompt` before the
  /// first use. The attachment picker asks this before it offers the camera.
  @objc public func cameraAccess(_ invoke: Invoke) {
    let access: String
    switch AVCaptureDevice.authorizationStatus(for: .video) {
    case .authorized: access = "granted"
    case .notDetermined: access = "prompt"
    default: access = "denied"
    }
    invoke.resolve(["access": access])
  }

  /// Shows the scanner and answers when it closes.
  @objc public func scanCamera(_ invoke: Invoke) {
    beginScan(invoke) { presenter, scan in
      let handle = CodeScannerViewController.scan(from: presenter) { outcome in scan.answer(outcome) }
      scan.close = { handle.cancel() }
    }
  }

  /// Shows the system's picker and answers with the code in the picture the person chose.
  @objc public func scanPhoto(_ invoke: Invoke) {
    beginScan(invoke) { presenter, scan in
      let reader = PhotoReader()
      scan.close = { reader.cancel() }
      reader.pick(from: presenter) { outcome in
        // The reader is held until its answer, by this closure.
        withExtendedLifetime(reader) { scan.answer(outcome) }
      }
    }
  }

  /// Keeps the screen on while a value the person compares with another device's shows, and lets
  /// it sleep again afterwards.
  @objc public func keepAwake(_ invoke: Invoke) throws {
    let arguments = try invoke.parseArgs(KeepAwakeArguments.self)
    DispatchQueue.main.async {
      UIApplication.shared.isIdleTimerDisabled = arguments.on
      invoke.resolve(["done": true])
    }
  }

  // MARK: The owner's presence

  /// The ceremony that is running, when one is: one at a time. A request that comes while one runs
  /// is not confirmed, and the one running is left alone, so what the person answers is never taken
  /// for an answer to the other request.
  private var presenting: OwnerPresenceRun?

  /// Which ceremony this device offers its owner.
  @objc public func presenceKind(_ invoke: Invoke) {
    invoke.resolve(["kind": OwnerPresenceKind.offered().rawValue])
  }

  /// Runs the ceremony for the words it is given, inside the time it is given, and answers once.
  @objc public func presence(_ invoke: Invoke) throws {
    let arguments = try invoke.parseArgs(PresenceArguments.self)
    DispatchQueue.main.async {
      if self.presenting?.isRunning == true {
        invoke.resolve(["outcome": "not_confirmed"])
        return
      }
      guard OwnerPresenceKind.offered() != .none, let presenter = self.topViewController() else {
        invoke.resolve(["outcome": "unavailable"])
        return
      }
      let run = OwnerPresenceRun(
        reason: arguments.reason, within: arguments.withinMs / 1000
      ) { outcome in invoke.resolve(["outcome": outcome]) }
      self.presenting = run
      run.begin(over: presenter)
    }
  }

  /// Opens this application's own page in the system's settings, where the camera is allowed.
  @objc public func openSettings(_ invoke: Invoke) {
    DispatchQueue.main.async {
      guard let url = URL(string: UIApplication.openSettingsURLString) else {
        invoke.reject("the settings page could not be named")
        return
      }
      UIApplication.shared.open(url) { _ in invoke.resolve(["done": true]) }
    }
  }

  private func beginScan(_ invoke: Invoke, _ open: @escaping (UIViewController, OpenScan) -> Void) {
    DispatchQueue.main.async {
      let begin = {
        guard let presenter = self.topViewController() else {
          invoke.reject("there is no screen to show the scanner on")
          return
        }
        let scan = OpenScan(invoke)
        self.scanning = scan
        scan.whenAnswered { if self.scanning === scan { self.scanning = nil } }
        open(presenter, scan)
      }
      // One at a time: a newer request ends the older one with a cancel, and shows its own only
      // once the older one's scanner or picker is off the screen, so it never finds the one that is
      // still leaving as the top of the stack.
      if let earlier = self.scanning {
        earlier.end(then: begin)
      } else {
        begin()
      }
    }
  }

  private func topViewController() -> UIViewController? {
    var top = manager.viewController
    while let presented = top?.presentedViewController { top = presented }
    return top
  }

  // MARK: The voice call

  // The call is the application's own, in a target this package cannot see, so each command is
  // handed to the application's adapter by name (`CallLink`) and answered when the adapter answers.

  @objc public func callOpen(_ invoke: Invoke) throws {
    let channel = try invoke.parseArgs(CallOpenArguments.self).events
    forward(invoke, news: { json in
      if let object = PlatformPlugin.object(of: json as String) { channel.send(object) }
    })
  }

  @objc public func callOffer(_ invoke: Invoke) { forward(invoke) }
  @objc public func callAccept(_ invoke: Invoke) { forward(invoke) }
  @objc public func callPermit(_ invoke: Invoke) { forward(invoke) }
  @objc public func callMute(_ invoke: Invoke) { forward(invoke) }
  @objc public func callStop(_ invoke: Invoke) { forward(invoke) }
  @objc public func callState(_ invoke: Invoke) { forward(invoke) }
  @objc public func callAlive(_ invoke: Invoke) { forward(invoke) }

  /// Hands one command to the application's call and answers `invoke` with what it answers.
  private func forward(_ invoke: Invoke, news: CallLink.News? = nil) {
    let reply: CallLink.Reply = { result, code, message in
      if let result = result as String?, let object = PlatformPlugin.object(of: result) {
        invoke.resolve(object)
      } else {
        invoke.reject(
          (message as String?) ?? "the call could not do that", code: (code as String?) ?? "engine")
      }
    }
    let taken = CallLink.send(invoke.command, arguments: invoke.getRawArgs(), news: news, reply: reply)
    if !taken { invoke.reject("this build holds no voice call", code: "unavailable") }
  }

  // MARK: Notifications

  // What a phone knows about its notifications is the application's own, in a target this package
  // cannot see, so each command is handed to the application's adapter by name (`PushLink`) and
  // answered when the adapter answers.

  @objc public func pushPermission(_ invoke: Invoke) { forwardPush(invoke) }
  @objc public func pushAskPermission(_ invoke: Invoke) { forwardPush(invoke) }
  @objc public func pushToken(_ invoke: Invoke) { forwardPush(invoke) }
  @objc public func pushPendingSet(_ invoke: Invoke) { forwardPush(invoke) }
  @objc public func pushPendingGet(_ invoke: Invoke) { forwardPush(invoke) }
  @objc public func pushPendingClear(_ invoke: Invoke) { forwardPush(invoke) }
  @objc public func pushPreviewKeys(_ invoke: Invoke) { forwardPush(invoke) }
  @objc public func pushRoute(_ invoke: Invoke) { forwardPush(invoke) }

  /// Hands one command to the application's notification adapter and answers `invoke` with what it
  /// answers.
  private func forwardPush(_ invoke: Invoke) {
    let reply: PushLink.Reply = { result, code, message in
      if let result = result as String?, let object = PlatformPlugin.object(of: result) {
        invoke.resolve(object)
      } else {
        invoke.reject(
          (message as String?) ?? "notifications could not do that", code: (code as String?) ?? "engine")
      }
    }
    let taken = PushLink.send(invoke.command, arguments: invoke.getRawArgs(), reply: reply)
    if !taken { invoke.reject("this build holds no notification adapter", code: "unavailable") }
  }

  /// A JSON object as the text the application's call speaks it in.
  private static func object(of json: String) -> JsonObject? {
    guard
      let data = json.data(using: .utf8),
      let parsed = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
    else { return nil }
    return parsed.mapValues { Optional($0) }
  }

  /// Answers the waiting call with the attempt's one result; a result for any other attempt is
  /// late, and dropped.
  private func finish(_ event: SessionEvent) {
    guard attempts.end(event.attempt) else { return }
    let waiting = self.waiting
    self.waiting = nil
    self.session = nil
    waiting?.resolve(event)
  }

  func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
    let windows = UIApplication.shared.connectedScenes
      .compactMap { $0 as? UIWindowScene }
      .flatMap { $0.windows }
    return windows.first { $0.isKeyWindow } ?? windows.first ?? ASPresentationAnchor()
  }
}

@_cdecl("init_plugin_companion_platform")
func initPlugin() -> Plugin {
  return PlatformPlugin()
}

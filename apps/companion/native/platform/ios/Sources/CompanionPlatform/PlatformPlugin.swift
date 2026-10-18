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

/// Which attempt a call is about.
struct AttemptArguments: Decodable {
  let attempt: String
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

  #if DEBUG
    /// Posts the notification the system posts when protected data becomes available, for a debug
    /// build on a simulator, which never locks: the device is modelled as locked and then unlocked.
    @objc public func postProtectedDataAvailable(_ invoke: Invoke) {
      DispatchQueue.main.async {
        NotificationCenter.default.post(
          name: UIApplication.protectedDataDidBecomeAvailableNotification, object: nil)
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

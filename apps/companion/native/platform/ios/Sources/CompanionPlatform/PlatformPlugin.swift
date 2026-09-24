import AuthenticationServices
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

/// Which attempt a call is about.
struct AttemptArguments: Decodable {
  let attempt: String
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
  private var attempt: String?

  @objc public func capabilities(_ invoke: Invoke) {
    var httpsCallback = false
    if #available(iOS 17.4, *) {
      httpsCallback = true
    }
    let group = Bundle.main.object(forInfoDictionaryKey: "KRPrivateKeychainGroup") as? String
    invoke.resolve(Capabilities(httpsCallback: httpsCallback, privateKeychainGroup: group))
  }

  @objc public func authenticate(_ invoke: Invoke) throws {
    let arguments = try invoke.parseArgs(SessionArguments.self)
    guard let url = URL(string: arguments.url) else {
      invoke.reject("the sign-in address does not parse")
      return
    }
    DispatchQueue.main.async {
      // One attempt at a time: a newer one ends the older one's wait.
      if let earlier = self.attempt {
        self.session?.cancel()
        self.finish(SessionEvent(attempt: earlier, kind: "cancelled"))
      }
      let attempt = arguments.attempt
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
      if arguments.mode == "sessionHttps", #available(iOS 17.4, *) {
        session = ASWebAuthenticationSession(
          url: url,
          callback: .https(host: arguments.httpsHost, path: arguments.httpsPath),
          completionHandler: completion)
      } else {
        session = ASWebAuthenticationSession(
          url: url, callbackURLScheme: arguments.scheme, completionHandler: completion)
      }
      session.prefersEphemeralWebBrowserSession = true
      session.presentationContextProvider = self
      self.session = session
      self.waiting = invoke
      self.attempt = attempt
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
      if self.attempt == arguments.attempt {
        // Cancelling from here dismisses the sheet without calling the completion, so the waiting
        // call is answered here.
        self.session?.cancel()
        self.finish(SessionEvent(attempt: arguments.attempt, kind: "cancelled"))
      }
      invoke.resolve(["done": true])
    }
  }

  private func finish(_ event: SessionEvent) {
    guard self.attempt == event.attempt, let waiting = self.waiting else { return }
    self.waiting = nil
    self.session = nil
    self.attempt = nil
    waiting.resolve(event)
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

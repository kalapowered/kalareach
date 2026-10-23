//
//  A registration challenge, answered where it arrives.
//
//  The gateway sends the challenge through the provider to a token before it binds the token to an
//  installation, as a push with content that wakes the application in the background. The
//  application's delegate is given the method the system calls for that (`DelegateMethods`), and
//  hands the message here. The decision and the signature are made by one function of the Rust
//  library, linked into this application, which reads the installation's key itself from the
//  application's own keychain group and signs nothing else; this reads the record, posts what the
//  function returns to the gateway the record names, and says it is finished within the time the
//  system gives a background push.
//
//  A message that is not a challenge is none of its business, and the system's `finished` is called
//  for it at once.
//

import Foundation

// The library's three functions, by their C names. Declared here, in the application's own target,
// because the unit tests build the receiver's order without linking the library; they are exported
// by `companion-platform` and kept by it.
@_silgen_name("kr_push_classify")
private func krPushClassify(_ input: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?

@_silgen_name("kr_push_sign")
private func krPushSign(_ input: UnsafePointer<CChar>, _ group: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?

@_silgen_name("kr_push_free")
private func krPushFree(_ pointer: UnsafeMutablePointer<CChar>?)

/// The Rust half's two functions, over JSON text, with the key read from this application's own
/// keychain group.
private struct RustChallengeCrypto: ChallengeCrypto {
    let group: String

    func classify(_ input: String) -> String {
        call(input) { krPushClassify($0) }
    }

    func sign(_ input: String) -> String {
        group.withCString { group in
            call(input) { krPushSign($0, group) }
        }
    }

    private func call(_ input: String, _ function: (UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?) -> String {
        input.withCString { pointer in
            guard let answered = function(pointer) else { return "" }
            defer { krPushFree(answered) }
            return String(cString: answered)
        }
    }
}

/// Refuses every redirect: the answer is signed for the address the record names, and a redirect would
/// send the same signed body to another one.
private final class NoRedirects: NSObject, URLSessionTaskDelegate {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}

/// One POST over the platform's own connection.
private struct SessionPost: GatewayPost {
    private static let session = URLSession(
        configuration: .ephemeral, delegate: NoRedirects(), delegateQueue: nil)

    func post(url: String, body: Data, then: @escaping (PostResult) -> Void) {
        guard let address = URL(string: url) else { return then(.unreachable) }
        var request = URLRequest(url: address, timeoutInterval: 8)
        request.httpMethod = "POST"
        request.httpBody = body
        request.setValue("application/json", forHTTPHeaderField: "content-type")
        Self.session.dataTask(with: request) { _, response, error in
            if let http = response as? HTTPURLResponse, error == nil {
                then(.status(http.statusCode))
            } else {
                // The kind of failure and nothing of the request: a code names why the post did not
                // get there, such as a transport the system refused.
                NSLog("KalaReach: the registration answer did not reach the gateway (%@ %ld)",
                    (error as NSError?)?.domain ?? "no error", (error as NSError?)?.code ?? 0)
                then(.unreachable)
            }
        }.resume()
    }
}

/// The receiver of a registration challenge.
final class PushChallenge {
    /// The one this application uses.
    static let shared = PushChallenge()

    /// Answers a message the system woke the application with, and calls `finished` when it is done,
    /// whatever became of it: the system waits for it and gives a few seconds.
    func received(userInfo: [AnyHashable: Any], finished: @escaping () -> Void) {
        // How many keys the system handed over, and nothing of what they hold.
        NSLog("KalaReach: the system handed the delegate a push with %ld keys", userInfo.count)
        var data: [String: String] = [:]
        for (key, value) in userInfo {
            if let key = key as? String, let value = value as? String { data[key] = value }
        }
        guard data[ChallengeKeys.challenge] != nil else { return finished() }
        guard
            let record = PendingFile.inApplicationSupport(),
            let group = PreviewKeyLocation.resolvedPrivateGroup()
        else {
            NSLog("KalaReach: a registration challenge arrived and this build cannot answer it")
            return finished()
        }
        let answerer = ChallengeAnswerer(record: record, crypto: RustChallengeCrypto(group: group), gateway: SessionPost())
        DispatchQueue.global(qos: .userInitiated).async {
            answerer.answer(data) { outcome in
                NSLog("KalaReach: a registration challenge was %@", String(describing: outcome))
                finished()
            }
        }
    }
}

/// The data key whose presence says a message is a registration challenge.
enum ChallengeKeys {
    static let challenge = "kr_challenge"
}

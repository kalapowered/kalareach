//
//  What the receiver hands the Rust opener and reads back.
//
//  The opener is one function of the Rust library, over JSON text, so a sealed preview is read in
//  one place. This is the shape it reads and answers, written once and held by a test against the
//  preview the host's own code sealed.
//

import Foundation

/// The opener's input and answer, as JSON text.
enum PreviewOpenerJson {
    /// The input for one preview: the members the Rust opener reads, and no others. Nil only when
    /// the text cannot be encoded.
    static func input(preview: String, senderKey: Data, alert: String, nowMilliseconds: UInt64) -> String? {
        let object: [String: Any] = [
            "preview": preview,
            "sender_key": senderKey.base64EncodedString(),
            "alert": alert,
            "now_ms": nowMilliseconds,
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }

    /// What the opener's answer says. An answer that is not one of its two shapes is a refusal.
    static func answer(_ text: String) -> PreviewOpened {
        guard let object = (try? JSONSerialization.jsonObject(with: Data(text.utf8))) as? [String: Any]
        else { return .refused("answer") }
        if object["ok"] as? Bool == true, let shown = object["text"] as? String {
            return .text(shown)
        }
        return .refused(object["reason"] as? String ?? "answer")
    }
}

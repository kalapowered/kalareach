//
//  A device run's way of making the system take the application's scene away.
//
//  The system disconnects a scene on its own when it reclaims one, and connects one again when the
//  person comes back, in the same process. A run cannot wait for that, so a debug build started with
//  `-KRSceneProbe watch` answers four requests a run posts as Darwin notifications, and writes
//  every scene event and every answer to the log and to a file in the application's own container:
//
//    to.kala.reach.scene-probe.report    the process, each scene with its windows and web views, the
//                                        anchor a sign-in would use, and what the page answers
//    to.kala.reach.scene-probe.destroy   asks the system to destroy each scene session
//    to.kala.reach.scene-probe.draft     keeps a draft through the page's own command
//    to.kala.reach.scene-probe.picker    asks for the system's picker through the page's own command
//                                        and says which view controller it is shown on
//
//  A launch of the application after a destroy brings it forward, and the log tells the same process
//  from a new one. Compiled into debug builds only.
//

#if DEBUG
import Foundation
import UIKit
import WebKit

enum SceneProbe {
    private static let prefix = "to.kala.reach.scene-probe."

    /// What each request does, by the name it is posted under.
    private static let requests: [String: () -> Void] = [
        "report": { report("report") },
        "destroy": { destroy() },
        "draft": { keepDraft() },
        "picker": { showPicker() },
    ]

    static func startIfRequested() {
        guard CommandLine.arguments.contains("-KRSceneProbe") else { return }
        let names: [Notification.Name] = [
            UIScene.willConnectNotification, UIScene.didActivateNotification,
            UIScene.willDeactivateNotification, UIScene.willEnterForegroundNotification,
            UIScene.didEnterBackgroundNotification, UIScene.didDisconnectNotification,
        ]
        for name in names {
            NotificationCenter.default.addObserver(forName: name, object: nil, queue: .main) { note in
                log("\(name.rawValue) scene=\(identifier(of: note.object as? UIScene)) \(summary())")
            }
        }
        for name in requests.keys {
            let center = CFNotificationCenterGetDarwinNotifyCenter()
            CFNotificationCenterAddObserver(
                center, nil,
                { _, _, name, _, _ in
                    guard let word = (name?.rawValue as String?)?.dropFirst(SceneProbe.prefix.count) else { return }
                    DispatchQueue.main.async { SceneProbe.requests[String(word)]?() }
                },
                (prefix + name) as CFString, nil, .deliverImmediately)
        }
        log("started \(summary())")
    }

    // MARK: Requests

    private static func destroy() {
        for session in UIApplication.shared.openSessions {
            log("destroying scene=\(session.persistentIdentifier)")
            UIApplication.shared.requestSceneSessionDestruction(session, options: nil) { error in
                log("destruction refused: \(error.localizedDescription)")
            }
        }
    }

    private static func keepDraft() {
        let save = """
            const draft = await window.__TAURI_INTERNALS__.invoke('device_draft_save', { params: {
              id: null, expectedRevision: null, sessionId: '8a7b6c50-22bb-4c3d-8e4f-000000000101',
              applicationInstanceId: null, agentBindingRevision: null, state: 'open',
              text: 'a draft kept before the scene went', attachments: [] } });
            return { saved: JSON.stringify(draft) };
            """
        page(save) { facts in log("draft \(facts)") }
    }

    /// Asks for the picker the way the page does, which shows it on the view controller the
    /// platform plugin holds, then says what that controller presents and ends the pairing step.
    private static func showPicker() {
        page("window.__TAURI_INTERNALS__.invoke('pairing_scan_photo').catch(() => {}); return { asked: true };") { _ in
            DispatchQueue.main.asyncAfter(deadline: .now() + 4) {
                let roots = scenes().compactMap { $0.windows.first { $0.isKeyWindow } ?? $0.windows.first }
                for window in roots {
                    var chain: [String] = []
                    var top = window.rootViewController
                    while let controller = top {
                        chain.append(String(describing: type(of: controller)))
                        top = controller.presentedViewController
                    }
                    log("picker presenting chain=\(chain.joined(separator: " > "))")
                }
                page("await window.__TAURI_INTERNALS__.invoke('pairing_stop'); return { stopped: true };") { _ in }
            }
        }
    }

    // MARK: Answers

    /// The process and each scene, then what the page answers through its own commands.
    private static func report(_ what: String) {
        log("\(what) \(summary())")
        for scene in scenes() {
            let windows = scene.windows.map { window in
                "\(type(of: window))(key=\(window.isKeyWindow),root=\(window.rootViewController.map { String(describing: type(of: $0)) } ?? "-"),inWindow=\(window.rootViewController?.view.window != nil))"
            }
            log("scene \(scene.session.persistentIdentifier) state=\(scene.activationState.rawValue) windows=\(windows.joined(separator: ";"))")
        }
        let all = scenes().flatMap { $0.windows }
        let anchor = all.first { $0.isKeyWindow } ?? all.first
        log("anchor \(anchor.map { String(describing: type(of: $0)) } ?? "none") key=\(anchor?.isKeyWindow ?? false)")
        let facts = """
            const invoke = window.__TAURI_INTERNALS__ && window.__TAURI_INTERNALS__.invoke;
            const out = { href: location.href, visibility: document.visibilityState, tauri: !!invoke };
            out.text = ((document.body && document.body.innerText) || '').replace(/\\s+/g, ' ').trim().slice(0, 240);
            out.buttons = Array.from(document.querySelectorAll('button')).map((b) =>
              (b.getAttribute('aria-label') || b.innerText || '').trim()).filter(Boolean).slice(0, 24).join(' | ');
            const ask = async (name) => { try { return JSON.stringify(await invoke(name)); }
              catch (error) { return 'error: ' + String((error && error.message) || error); } };
            if (invoke) {
              out.call = (await ask('voice_call_state')).slice(0, 400);
              out.pairing = (await ask('pairing_view')).slice(0, 400);
              out.drafts = (await ask('device_drafts')).slice(0, 400);
            }
            return out;
            """
        page(facts) { answer in
            for (key, value) in answer.sorted(by: { $0.key < $1.key }) { log("page \(key)=\(value)") }
        }
    }

    // MARK: Scenes, windows, the page

    private static func scenes() -> [UIWindowScene] {
        UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
    }

    private static func webViews(in view: UIView) -> [WKWebView] {
        (view as? WKWebView).map { [$0] } ?? view.subviews.flatMap { webViews(in: $0) }
    }

    /// Runs `body` in the page of the application's web view and gives its answer to `done`. The
    /// body may await; it returns an object.
    private static func page(_ body: String, _ done: @escaping ([String: Any]) -> Void) {
        let views = scenes().flatMap { $0.windows }.flatMap { webViews(in: $0) }
        guard let web = views.first else {
            log("no web view to ask")
            done(["error": "no web view"])
            return
        }
        web.callAsyncJavaScript(body, arguments: [:], in: nil, in: .page) { result in
            switch result {
            case .success(let value): done(value as? [String: Any] ?? ["value": String(describing: value)])
            case .failure(let error): done(["error": error.localizedDescription])
            }
        }
    }

    private static func identifier(of scene: UIScene?) -> String {
        scene?.session.persistentIdentifier ?? "-"
    }

    /// One line of the process and of what the application holds.
    private static func summary() -> String {
        let windows = scenes().map { String($0.windows.count) }.joined(separator: ",")
        let webs = scenes().flatMap { $0.windows }.flatMap { webViews(in: $0) }.count
        let ids = scenes().map { $0.session.persistentIdentifier }.joined(separator: ",")
        let state = UIApplication.shared.applicationState.rawValue
        return "pid=\(ProcessInfo.processInfo.processIdentifier) app=\(state) scenes=\(scenes().count) ids=[\(ids)] windows=[\(windows)] webviews=\(webs)"
    }

    /// Writes one line to the system's log and to the container's own file, which a run reads back.
    private static func log(_ line: String) {
        NSLog("KalaReach scene probe: %@", line)
        let file = FileManager.default.temporaryDirectory.appendingPathComponent("kr-scene-probe.log")
        let stamp = ISO8601DateFormatter().string(from: Date())
        guard let data = "\(stamp) \(line)\n".data(using: .utf8) else { return }
        if let handle = try? FileHandle(forWritingTo: file) {
            handle.seekToEndOfFile()
            handle.write(data)
            try? handle.close()
        } else {
            try? data.write(to: file)
        }
    }
}
#endif

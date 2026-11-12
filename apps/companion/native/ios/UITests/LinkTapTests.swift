//
//  Taps on the links of a message, made on the glass as a finger makes them.
//
//  A link's box and the message's controls are the page's own: the browser's click names the link or
//  the control that a tap lands on, and nothing stops or redirects it. Where a tap's click lands on
//  plain text near a link's words, the page gives the link a click of its own. Which element WebKit
//  names for a tap, and whether it sends a click for plain text at all, no browser test on a desktop
//  engine can show. These tests tap the web view by coordinates, through UIKit and not through the
//  page's own events, at the points a person touches, and read what the page saw (the harness's tap
//  record: each event's type, target, pointer number, pointer type and point) and what the scripted
//  host opened.
//
//  The tap record is the harness's own: a strip control starts it, fills the first session with the
//  messages the taps need, and shows the events, the links' rectangles and the links opened as text
//  that this reads.
//

import XCTest

final class LinkTapTests: HarnessTestCase {
    private static let largest = "UICTContentSizeCategoryAccessibilityXXXL"

    // MARK: What the page records

    /// One event the page saw, in the order it saw it.
    private struct Seen {
        let order: Int
        let type: String
        let target: String
        let trusted: Bool
        let detail: Int
        let point: CGPoint
        /// The event's class (a pointer event or a mouse event), its pointer number and its pointer type.
        let kind: String
        let pointer: String
        let pointerType: String
    }

    /// One link of the conversation as the page lays it out now: its box and the rectangles of its words.
    private struct Link {
        let name: String
        let box: CGRect
        let words: [CGRect]
        let line: CGFloat
    }

    private func recordText(_ prefix: String) -> String {
        let element = app.staticTexts.matching(NSPredicate(format: "label BEGINSWITH %@", prefix)).firstMatch
        XCTAssertTrue(element.waitForExistence(timeout: 20), "the tap record shows no \(prefix) line")
        return element.label
    }

    private func floats(_ tokens: ArraySlice<Substring>) -> [CGFloat] {
        tokens.compactMap { Double($0) }.map { CGFloat($0) }
    }

    /// The events of the record, oldest first.
    private func events() -> [Seen] {
        recordText("TAPLOG").dropFirst("TAPLOG".count).components(separatedBy: " ; ").compactMap { part in
            let fields = part.split(separator: " ")
            guard fields.count >= 11, fields[0] == "E", let order = Int(fields[1]), let detail = Int(fields[5]),
                let x = Double(fields[6]), let y = Double(fields[7])
            else { return nil }
            return Seen(
                order: order, type: String(fields[2]), target: String(fields[3]), trusted: fields[4] == "1", detail: detail,
                point: CGPoint(x: x, y: y), kind: String(fields[8]), pointer: String(fields[9]), pointerType: String(fields[10])
            )
        }
    }

    /// The links of the conversation, in the page's own units: a point of the page is a point of the screen.
    private func links() -> [Link] {
        recordText("TAPLINKS").dropFirst("TAPLINKS".count).components(separatedBy: " ; ").compactMap { part in
            let fields = part.split(separator: " ")
            guard fields.count >= 12, fields[0] == "L", let wordsAt = fields.firstIndex(of: "words"), let lineAt = fields.firstIndex(of: "line") else { return nil }
            let box = floats(fields[3..<7])
            let words = floats(fields[(wordsAt + 1)..<lineAt])
            guard box.count == 4, words.count >= 4, words.count % 4 == 0, let line = Double(fields[lineAt + 1]) else { return nil }
            let rects = stride(from: 0, to: words.count, by: 4).map {
                CGRect(x: words[$0], y: words[$0 + 1], width: words[$0 + 2] - words[$0], height: words[$0 + 3] - words[$0 + 1])
            }
            return Link(
                name: String(fields[1]),
                box: CGRect(x: box[0], y: box[1], width: box[2] - box[0], height: box[3] - box[1]),
                words: rects,
                line: CGFloat(line)
            )
        }
    }

    /// The room the conversation has on the page, how far it is scrolled and how far it can be.
    private func pane() -> (room: CGRect, top: CGFloat, most: CGFloat) {
        for part in recordText("TAPLINKS").dropFirst("TAPLINKS".count).components(separatedBy: " ; ") {
            let fields = part.split(separator: " ")
            guard fields.count == 7, fields[0] == "P" else { continue }
            let box = floats(fields[1...6])
            if box.count == 6 { return (CGRect(x: box[0], y: box[1], width: box[2] - box[0], height: box[3] - box[1]), box[4], box[5]) }
        }
        return (.zero, 0, 0)
    }

    /// The addresses the scripted host has opened, in order.
    private func opened() -> [String] {
        let text = recordText("TAPOPENED").dropFirst("TAPOPENED".count)
        return text.split(separator: " ").dropFirst().map(String.init)
    }

    private func link(_ name: String) -> Link {
        guard let found = links().first(where: { $0.name == name }) else {
            XCTFail("the page lays out no link \(name)")
            return Link(name: name, box: .zero, words: [.zero], line: 0)
        }
        return found
    }

    /// The names the page's record gives the links, and the labels their buttons have on the screen.
    private static let labels = [
        "table-1": "first notes",
        "table-2": "second notes",
        "docs": "docs",
        "reconnect": "the reconnect notes",
        "upper": "the upper link",
        "lower": "the lower link",
        "under-image": "a link under the image",
    ]

    /// Where the page's coordinates lie on the screen: the button a link is has a frame the system
    /// reports, and the page says where the same button is in its own coordinates.
    private func offset(of reference: Link) -> CGVector {
        let button = app.buttons[Self.labels[reference.name] ?? reference.name].firstMatch
        XCTAssertTrue(button.waitForExistence(timeout: 10), "the screen shows no button for \(reference.name)")
        let frame = button.frame
        return CGVector(dx: frame.minX - reference.box.minX, dy: frame.minY - reference.box.minY)
    }

    // MARK: Taps

    /// What one tap did, as the page saw it.
    private struct Result {
        let label: String
        let events: [Seen]
        let opened: [String]
        let focus: String
    }

    private func screenPoint(_ point: CGPoint, _ shift: CGVector) -> XCUICoordinate {
        app.coordinate(withNormalizedOffset: .zero).withOffset(CGVector(dx: point.x + shift.dx, dy: point.y + shift.dy))
    }

    /// Taps a point of the page, or holds a finger on it for `hold` seconds, and reports what happened after the last
    /// event the record had before.
    private func tap(_ label: String, at point: CGPoint, shift: CGVector, hold: TimeInterval = 0) -> Result {
        let before = events().last?.order ?? 0
        let openedBefore = opened().count
        if hold > 0 {
            screenPoint(point, shift).press(forDuration: hold)
        } else {
            screenPoint(point, shift).tap()
        }
        Thread.sleep(forTimeInterval: 1.2)
        let seen = events().filter { $0.order > before }
        let now = opened()
        let result = Result(label: label, events: seen, opened: Array(now.dropFirst(openedBefore)), focus: recordText("TAPFOCUS"))
        report(result, at: point)
        return result
    }

    /// Drags from a point of the page to another, slowly enough for the page to scroll with the finger.
    private func drag(_ label: String, from point: CGPoint, by distance: CGVector, shift: CGVector) -> Result {
        let before = events().last?.order ?? 0
        let openedBefore = opened().count
        let start = screenPoint(point, shift)
        let end = screenPoint(CGPoint(x: point.x + distance.dx, y: point.y + distance.dy), shift)
        // A swipe at the system's own speed, which the page takes for a scroll.
        start.press(forDuration: 0.05, thenDragTo: end, withVelocity: .default, thenHoldForDuration: 0)
        Thread.sleep(forTimeInterval: 1.2)
        let seen = events().filter { $0.order > before }
        let result = Result(label: label, events: seen, opened: Array(opened().dropFirst(openedBefore)), focus: "\(recordText("TAPFOCUS")) scrolled \(Int(pane().top))")
        report(result, at: point)
        return result
    }

    /// Says what one tap did, one line, where the run's log can be read for it.
    private func report(_ result: Result, at point: CGPoint) {
        let list = result.events.map {
            "\($0.type)(\($0.target),\($0.trusted ? "trusted" : "synthetic"),detail \($0.detail),\($0.kind) pointer \($0.pointer) \($0.pointerType),at \(Int($0.point.x)) \(Int($0.point.y)))"
        }.joined(separator: " ")
        say("LINKTAP \(result.label) at (\(Int(point.x)), \(Int(point.y))): \(list.isEmpty ? "no events" : list) | the click named: \(named(result)) | opened: \(result.opened.isEmpty ? "nothing" : result.opened.joined(separator: " ")) | \(result.focus)")
    }

    /// What the system's click named, and whether the page added a click of its own: `button` (the link's own, by the
    /// platform's adjustment or because the tap landed on it), `text` (plain text, then the page's click follows),
    /// `none` (no click came).
    private func named(_ result: Result) -> String {
        guard let click = result.events.first(where: { $0.type == "click" && $0.trusted }) else { return "none" }
        let added = result.events.contains { $0.type == "click" && !$0.trusted }
        return (click.target.contains("md-link") ? "the link's button" : "plain text (\(click.target))") + (added ? ", with the page's click on the link" : ", no click added by the page")
    }

    /// A tap that opens a link: one trusted click with detail 1 after the pointer's release, and the link opened once.
    private func expectOpened(_ result: Result, _ name: String, file: StaticString = #filePath, line: UInt = #line) {
        let types = result.events.map(\.type)
        // The page's own redirected click is the one that is not the system's: only the system's is counted.
        let clicks = result.events.filter { $0.type == "click" && $0.trusted }
        XCTAssertEqual(clicks.count, 1, "\(result.label): the system's clicks that came: \(types)", file: file, line: line)
        if let click = clicks.first {
            XCTAssertTrue(click.trusted, "\(result.label): the click was not the system's own", file: file, line: line)
            XCTAssertEqual(click.detail, 1, "\(result.label): the click's detail", file: file, line: line)
            if let up = result.events.first(where: { $0.type == "pointerup" }) {
                XCTAssertGreaterThan(click.order, up.order, "\(result.label): the click came before the pointer's release", file: file, line: line)
            } else {
                XCTFail("\(result.label): no pointerup before the click: \(types)", file: file, line: line)
            }
        }
        XCTAssertEqual(result.opened.count, 1, "\(result.label): the links that opened: \(result.opened)", file: file, line: line)
        XCTAssertTrue(result.opened.first?.hasSuffix(name) ?? false, "\(result.label): opened \(result.opened), expected \(name)", file: file, line: line)
    }

    // MARK: Starting

    /// Starts the harness at a text size, starts the tap record and opens the session that it filled.
    private func start(size: String?) {
        var arguments = ["-KRColourMode", "light"]
        if let size { arguments += ["-UIPreferredContentSizeCategoryName", size] }
        launchHarness(arguments)
        strip("Link taps")
        openFirstSession()
        Thread.sleep(forTimeInterval: 1.5)
        XCTAssertTrue(app.buttons["first notes"].waitForExistence(timeout: 20) || app.buttons["docs"].waitForExistence(timeout: 20), "the record's messages are not on the conversation")
    }

    /// Scrolls the conversation until a link's words lie near the middle of the screen, and reads the link again.
    private func scroll(to name: String) -> Link {
        for _ in 0..<10 {
            let current = link(name)
            let shift = offset(of: current)
            let room = pane().room
            let screenY = (current.words.first?.midY ?? 0) + shift.dy
            // The middle of the pane as it is now, which the keyboard can have made short.
            let distance = screenY - (room.midY + shift.dy)
            if abs(distance) < 60 { return current }
            // A drag from the middle of the pane moves the content with the finger; a drag that starts on a link scrolls too.
            let start = screenPoint(CGPoint(x: room.midX, y: room.midY), shift)
            let end = start.withOffset(CGVector(dx: 0, dy: -max(min(distance, 300), -300)))
            start.press(forDuration: 0.05, thenDragTo: end, withVelocity: .slow, thenHoldForDuration: 0.3)
            Thread.sleep(forTimeInterval: 1.0)
        }
        return link(name)
    }

    // MARK: The taps

    /// The taps at one text size. Each is made with the finger on the glass; the page reports what it saw.
    private func runTaps(size: String?, named: String) {
        continueAfterFailure = true
        start(size: size)
        say("LINKTAP size \(named)")

        // On the words of a link.
        var table1 = scroll(to: "table-1")
        var shift = offset(of: table1)
        let wordsOfTable1 = table1.words[0]
        expectOpened(
            tap("\(named): on the words", at: CGPoint(x: wordsOfTable1.midX, y: wordsOfTable1.midY), shift: shift),
            "table-1"
        )

        // 3 px under the upper link of two table rows: the upper link's.
        table1 = link("table-1")
        shift = offset(of: table1)
        let under = table1.words[0]
        expectOpened(
            tap("\(named): 3 px under the upper link of two table rows", at: CGPoint(x: under.midX, y: under.maxY + 3), shift: shift),
            "table-1"
        )

        // 4 px above a link's words: the half-leading of its line at the largest size.
        table1 = link("table-1")
        shift = offset(of: table1)
        let above = table1.words[0]
        expectOpened(
            tap("\(named): 4 px above the words", at: CGPoint(x: above.midX, y: above.minY - 4), shift: shift),
            "table-1"
        )

        // Plain text after a link, 16 to 20 px past its words: inside the link's reach. The click that the
        // system sends names the link's button (the platform's own adjustment) or the plain text (and then
        // the page gives the link a click); the report line of each tap says which.
        _ = scroll(to: "docs")
        for beside in [16, 18, 20] as [CGFloat] {
            let docs = link("docs")
            let words = docs.words[docs.words.count - 1]
            expectOpened(
                tap("\(named): on plain text after the link, \(Int(beside)) px past its words", at: CGPoint(x: words.maxX + beside, y: words.midY), shift: offset(of: docs)),
                "docs"
            )
        }

        // One line away from every link, beyond the reach: nothing opens.
        let all = links()
        let room = pane().room
        let shiftNow = offset(of: link("docs"))
        var away: CGPoint?
        var y = room.minY + 12
        while y < room.maxY - 12, away == nil {
            let candidate = CGPoint(x: room.midX, y: y)
            if all.allSatisfy({ !$0.box.insetBy(dx: -40, dy: -(40 + $0.line)).contains(candidate) }) { away = candidate }
            y += 6
        }
        if let away {
            let result = tap("\(named): one line away from every link", at: away, shift: shiftNow)
            XCTAssertTrue(result.opened.isEmpty, "\(result.label): opened \(result.opened)")
        } else {
            XCTFail("no point of the conversation lies a line away from every link: \(room)")
        }

        // A paragraph with a link on the next line: the upper link's words, and the lower part of them, are the upper link's.
        var upper = scroll(to: "upper")
        expectOpened(
            tap("\(named): on the upper link's words, a link on the next line", at: CGPoint(x: upper.words[0].minX + min(12, upper.words[0].width / 2), y: upper.words[0].midY), shift: offset(of: upper)),
            "upper"
        )
        upper = link("upper")
        let lastLine = upper.words[upper.words.count - 1]
        expectOpened(
            tap("\(named): on the lower part of the upper link's words, a link on the next line", at: CGPoint(x: lastLine.minX + min(12, lastLine.width / 2), y: lastLine.maxY - 2), shift: offset(of: upper)),
            "upper"
        )

        // The control of an image that has not been loaded, 2 px inside its lower edge, with a link on the next line:
        // one click of the control, and no link opens.
        let underImage = scroll(to: "under-image")
        let control = app.buttons["Load this image"].firstMatch
        XCTAssertTrue(control.waitForExistence(timeout: 10), "the screen shows no Load this image control")
        let controlShift = offset(of: underImage)
        let controlFrame = control.frame
        let onControl = tap(
            "\(named): 2 px inside the lower edge of Load this image",
            at: CGPoint(x: controlFrame.midX - controlShift.dx, y: controlFrame.maxY - 2 - controlShift.dy),
            shift: controlShift
        )
        let controlClicks = onControl.events.filter { $0.type == "click" && $0.trusted }
        XCTAssertEqual(controlClicks.count, 1, "\(onControl.label): the system's clicks that came: \(onControl.events.map(\.type))")
        XCTAssertTrue(
            (controlClicks.first?.target.hasPrefix("button") ?? false) && !(controlClicks.first?.target.contains("md-link") ?? true),
            "\(onControl.label): the click named \(controlClicks.first?.target ?? "nothing"), not the control"
        )
        XCTAssertFalse(onControl.events.contains { $0.type == "click" && !$0.trusted }, "\(onControl.label): the page added a click")
        XCTAssertTrue(onControl.opened.isEmpty, "\(onControl.label): opened \(onControl.opened)")

        // A press of one second on a link's words: what the platform does with it stands, and the page adds nothing.
        let pressed = scroll(to: "table-2")
        let held = tap(
            "\(named): a press of one second on a link's words",
            at: CGPoint(x: pressed.words[0].midX, y: pressed.words[0].midY),
            shift: offset(of: pressed),
            hold: 1.0
        )
        let heldClicks = held.events.filter { $0.type == "click" && $0.trusted }.count
        XCTAssertEqual(held.opened.count, heldClicks, "\(held.label): \(heldClicks) clicks of the system's, \(held.opened.count) links opened")
        XCTAssertFalse(held.events.contains { $0.type == "click" && !$0.trusted }, "\(held.label): the page added a click")

        // A drag that scrolls, started on a link's words: pointercancel, no click, nothing opened.
        let dragged = scroll(to: "table-2")
        let draggedShift = offset(of: dragged)
        let draggedWords = dragged.words[0]
        // Toward the end of the conversation if it has room that way, and toward its start if not.
        let place = pane()
        let by: CGFloat = place.top + 180 <= place.most ? -180 : 180
        say("LINKTAP \(named): the conversation before the drag: room \(place.room), scrolled \(Int(place.top)) of \(Int(place.most))")
        let result = drag("\(named): a drag that scrolls, started on a link", from: CGPoint(x: draggedWords.midX, y: draggedWords.midY), by: CGVector(dx: 0, dy: by), shift: draggedShift)
        // WebKit ends a pan with pointercancel at some sizes and with pointerup at others; what matters is that the page scrolled.
        XCTAssertTrue(
            result.events.contains { $0.type == "pointercancel" } || abs(pane().top - place.top) > 20,
            "\(result.label): the page did not scroll and no pointercancel came: \(result.events.map(\.type))"
        )
        XCTAssertFalse(result.events.contains { $0.type == "click" }, "\(result.label): a click came")
        XCTAssertTrue(result.opened.isEmpty, "\(result.label): opened \(result.opened)")

        // A link tapped while the composer has focus: the link opens once, and the report says where the focus is
        // and whether the keyboard is still up.
        composer.tap()
        Thread.sleep(forTimeInterval: 1.5)
        let keyboardBefore = app.keyboards.count
        let reference = scroll(to: "reconnect")
        let withKeyboard = offset(of: reference)
        let words = reference.words[0]
        let focused = tap("\(named): a link while the composer has focus", at: CGPoint(x: words.midX, y: words.midY), shift: withKeyboard)
        say("LINKTAP \(named): composer focus: keyboards before \(keyboardBefore), after \(app.keyboards.count); opened \(focused.opened); \(focused.focus)")
        XCTAssertGreaterThan(keyboardBefore, 0, "\(focused.label): the keyboard was not up before the tap")
        expectOpened(focused, "reconnect")
    }

    func testTapsAtTheDefaultTextSize() {
        runTaps(size: nil, named: "default size")
    }

    func testTapsAtTheLargestTextSize() {
        runTaps(size: Self.largest, named: "largest size")
    }
}

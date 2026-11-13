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
        /// At a pointer down: the name of the link that the page's press handling had lit by then, or nil.
        let lit: String?
    }

    /// One link of the conversation as the page lays it out now: its box, the rectangles of its words and its view,
    /// the part of the page that every box clipping the link leaves of it.
    private struct Link {
        let name: String
        let box: CGRect
        let words: [CGRect]
        let line: CGFloat
        let view: CGRect
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
            let lit = fields.count > 11 && fields[11].hasPrefix("lit=") ? String(fields[11].dropFirst(4)) : "-"
            return Seen(
                order: order, type: String(fields[2]), target: String(fields[3]), trusted: fields[4] == "1", detail: detail,
                point: CGPoint(x: x, y: y), kind: String(fields[8]), pointer: String(fields[9]), pointerType: String(fields[10]),
                lit: lit == "-" ? nil : lit
            )
        }
    }

    /// The links of the conversation, in the page's own units: a point of the page is a point of the screen.
    private func links() -> [Link] {
        recordText("TAPLINKS").dropFirst("TAPLINKS".count).components(separatedBy: " ; ").compactMap { part in
            let fields = part.split(separator: " ")
            guard fields.count >= 19, fields[0] == "L", let wordsAt = fields.firstIndex(of: "words"), let lineAt = fields.firstIndex(of: "line"), let viewAt = fields.firstIndex(of: "view") else { return nil }
            let box = floats(fields[3..<7])
            let words = floats(fields[(wordsAt + 1)..<lineAt])
            let view = floats(fields[(viewAt + 1)...])
            guard box.count == 4, view.count == 4, words.count >= 4, words.count % 4 == 0, let line = Double(fields[lineAt + 1]) else { return nil }
            let rects = stride(from: 0, to: words.count, by: 4).map {
                CGRect(x: words[$0], y: words[$0 + 1], width: words[$0 + 2] - words[$0], height: words[$0 + 3] - words[$0 + 1])
            }
            return Link(
                name: String(fields[1]),
                box: CGRect(x: box[0], y: box[1], width: box[2] - box[0], height: box[3] - box[1]),
                words: rects,
                line: CGFloat(line),
                view: CGRect(x: view[0], y: view[1], width: view[2] - view[0], height: view[3] - view[1])
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
            return Link(name: name, box: .zero, words: [.zero], line: 0, view: .zero)
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
        "middle": "it",
        "at-start": "1",
        "at-end": "2",
        "last-line": "a link",
        "short-last": "a short link",
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
    ///
    /// `within` holds the page's own pointer point to the requested point: the tap fails where the page saw the pointer farther
    /// from the point than that on either axis, so a calibration that is wrong fails the tap and does not move the samples.
    /// `clickExpected` is false for a press that the platform may leave without a click (a long press).
    private func tap(_ label: String, at point: CGPoint, shift: CGVector, hold: TimeInterval = 0, clickExpected: Bool = true, within tolerance: CGFloat? = nil) -> Result {
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
        if let tolerance {
            if let down = seen.first(where: { $0.type == "pointerdown" }) {
                XCTAssertLessThanOrEqual(abs(down.point.x - point.x), tolerance, "\(label): the page saw the pointer at x \(down.point.x), the requested point is x \(point.x)")
                XCTAssertLessThanOrEqual(abs(down.point.y - point.y), tolerance, "\(label): the page saw the pointer at y \(down.point.y), the requested point is y \(point.y)")
            } else {
                XCTFail("\(label): the page saw no pointer down")
            }
        }
        if let disagreement = lookDisagreement(result, clickExpected: clickExpected) { XCTFail("\(label): the pressed look and the click disagree: \(disagreement)") }
        return result
    }

    /// How far the page's own pointer point may lie from the requested point on either axis, in points, for the taps of a
    /// link's boundary. The inside taps lie 1 point inside an edge and the outside taps 3 points outside it, and a first
    /// tap sets the screen offset, so a tap that lands farther than this from its point is not a sample of that boundary.
    private static let pointerTolerance: CGFloat = 1.5

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
            "\($0.type)(\($0.target),\($0.trusted ? "trusted" : "synthetic"),detail \($0.detail),\($0.kind) pointer \($0.pointer) \($0.pointerType),at \(String(format: "%.1f %.1f", $0.point.x, $0.point.y)))"
        }.joined(separator: " ")
        say("LINKTAP \(result.label) at (\(Int(point.x)), \(Int(point.y))): \(list.isEmpty ? "no events" : list) | the click named: \(named(result)) | lit at the press: \(result.events.first(where: { $0.type == "pointerdown" })?.lit ?? "nothing") | press-to-click(\(clickKind(result))): \(away(result).map { String(format: "%.1f", $0) } ?? "no click") | pointer point off by \(pointerOff(result, at: point)) | opened: \(result.opened.isEmpty ? "nothing" : result.opened.joined(separator: " ")) | \(result.focus)")
    }

    /// What the system's click landed on, for the two distances that are logged apart: `element` (a link's button or another
    /// control, where the platform's adjustment or the tap itself chose it) and `plain text` (where only the page decides).
    private func clickKind(_ result: Result) -> String {
        guard let click = result.events.first(where: { $0.type == "click" && $0.trusted }) else { return "none" }
        return click.target.contains("md-link") || click.target.hasPrefix("button") ? "element" : "plain text"
    }

    /// How far the page's own pointer point lay from the point that was requested, as two signed numbers.
    private func pointerOff(_ result: Result, at point: CGPoint) -> String {
        guard let down = result.events.first(where: { $0.type == "pointerdown" }) else { return "-" }
        return String(format: "%.1f %.1f", down.point.x - point.x, down.point.y - point.y)
    }

    /// How far the system's click lay from the press that made it, in points, or nil where no click came.
    private func away(_ result: Result) -> CGFloat? {
        guard let down = result.events.first(where: { $0.type == "pointerdown" }), let click = result.events.first(where: { $0.type == "click" && $0.trusted }) else { return nil }
        return hypot(click.point.x - down.point.x, click.point.y - down.point.y)
    }

    /// The name that an element's description carries between its parentheses, the link's own name.
    private func linkName(of target: String) -> String? {
        guard let open = target.lastIndex(of: "("), target.hasSuffix(")") else { return nil }
        return String(target[target.index(after: open)..<target.index(before: target.endIndex)])
    }

    /// The look at the press against what the tap did, or nil where they agree. A tap with no trusted click of the system's
    /// does not agree (unless `clickExpected` is false). Where the system's click names plain
    /// text the page decided, and the look at the press is the open at the release; where it names a link's button or
    /// another control, the system decided, and the look lit nothing or that same link.
    private func lookDisagreement(_ result: Result, clickExpected: Bool = true) -> String? {
        // Without the system's click there is nothing to hold the look to: a tap that gets none fails, since the look
        // would then pass whatever it lit.
        guard let click = result.events.first(where: { $0.type == "click" && $0.trusted }) else { return clickExpected ? "no trusted click arrived" : nil }
        let lit = result.events.first(where: { $0.type == "pointerdown" })?.lit
        if click.target.contains("md-link") {
            let name = linkName(of: click.target)
            return lit == nil || lit == name ? nil : "lit \(lit ?? "nothing"), the click named the button of \(name ?? "a link")"
        }
        if click.target.hasPrefix("button") { return lit == nil ? nil : "lit \(lit ?? "") on a control" }
        let opened = result.opened.last.map { String($0.split(separator: "/").last ?? "") }
        return lit == opened ? nil : "lit \(lit ?? "nothing"), opened \(opened ?? "nothing")"
    }

    /// What the system's click named, and whether the page added a click of its own: `button` (the link's own, by the
    /// platform's adjustment or because the tap landed on it), `text` (plain text, then the page's click follows),
    /// `none` (no click came).
    private func named(_ result: Result) -> String {
        guard let click = result.events.first(where: { $0.type == "click" && $0.trusted }) else { return "none" }
        let added = result.events.contains { $0.type == "click" && !$0.trusted }
        let what = click.target.contains("md-link") ? "the link's button" : click.target.hasPrefix("button") ? "a control (\(click.target))" : "plain text (\(click.target))"
        return what + (added ? ", with the page's click on the link" : ", no click added by the page")
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

    /// Opens the second session, the one whose conversation is short before the record adds to it.
    private func openSecondSession() {
        app.buttons["Sessions"].tap()
        let row = app.buttons.matching(NSPredicate(format: "label CONTAINS 'Session 2'")).firstMatch
        XCTAssertTrue(row.waitForExistence(timeout: 20), "no second session in the list")
        row.tap()
        XCTAssertTrue(composer.waitForExistence(timeout: 20), "the session did not open")
    }

    /// Starts the harness at a text size, starts the tap record and opens the session that it filled.
    private func start(size: String?, short: Bool = false) {
        var arguments = ["-KRColourMode", "light"]
        if let size { arguments += ["-UIPreferredContentSizeCategoryName", size] }
        launchHarness(arguments)
        strip(short ? "Short link taps" : "Link taps")
        if short { openSecondSession() } else { openFirstSession() }
        Thread.sleep(forTimeInterval: 1.5)
        XCTAssertTrue(
            app.buttons[short ? "a short link" : "first notes"].waitForExistence(timeout: 20) || app.buttons["docs"].waitForExistence(timeout: 20),
            "the record's messages are not on the conversation"
        )
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

    /// Taps the outer boundary of the area that the page gives a link: the corners and the middle of each side, one point
    /// inside the area's own edge and one step (three points) outside it, and the words' middle. The area is
    /// what the rule gives: the words grown to the least size and to 22 points beside them, held to the link's view (the
    /// pane and the message that clips it), a cut on one side given to the other. A tap inside opens the link once. A
    /// tap outside opens nothing by the page; where the platform's own adjustment opens the link there, or the tap lands
    /// on the link's own button (which is taller than its words at the largest size and lights by design), the system's
    /// click names the link's button.
    private func tapAround(_ edge: Link, named: String) {
        var edgeShift = offset(of: edge)
        let room = pane().room
        let words = edge.words[0]
        let area = Self.areaOf(words, in: edge.view)
        let (left, top, right, bottom) = (area.minX, area.minY, area.maxX, area.maxY)
        say("LINKTAP \(named): \(edge.name) words \(words), pane \(room), view \(edge.view), box \(edge.box), area \(left) \(top) \(right) \(bottom)")
        let inset: CGFloat = 1
        let step: CGFloat = 3
        let xs = [left, (left + right) / 2, right]
        let ys = [top, (top + bottom) / 2, bottom]
        // The first tap sets the screen offset, and fails where the page saw the pointer 4 points or more from the point:
        // that is a wrong frame, not an offset to calibrate by.
        let centre = tap("\(named): \(edge.name), the words' middle", at: CGPoint(x: words.midX, y: words.midY), shift: edgeShift, within: 4)
        // The system's frame of a link's button is not its page box to the point, and a tap at the area's edge is
        // within a point of the page's own area: the first tap's own position says where the page's coordinates lie.
        if let down = centre.events.first(where: { $0.type == "pointerdown" }) {
            let miss = CGVector(dx: words.midX - down.point.x, dy: words.midY - down.point.y)
            say("LINKTAP \(named): \(edge.name), the first tap landed \(miss.dx) \(miss.dy) points from the words' middle")
            edgeShift = CGVector(dx: edgeShift.dx + miss.dx, dy: edgeShift.dy + miss.dy)
        }
        expectOpened(centre, edge.name)
        for (row, y) in ys.enumerated() {
            for (column, x) in xs.enumerated() where !(row == 1 && column == 1) {
                // Inward is the direction from the side toward the area's middle: plus at the left and top.
                let toward = CGVector(dx: column == 0 ? 1 : column == 2 ? -1 : 0, dy: row == 0 ? 1 : row == 2 ? -1 : 0)
                let label = "\(named): \(edge.name), the area's \(["top", "middle", "bottom"][row]) \(["left", "centre", "right"][column])"
                let onEdge = tap("\(label), at its edge", at: CGPoint(x: x + toward.dx * inset, y: y + toward.dy * inset), shift: edgeShift, within: Self.pointerTolerance)
                expectOpened(onEdge, edge.name)
                let outside = CGPoint(x: x - toward.dx * step, y: y - toward.dy * step)
                // A step outside a side that is the pane's own edge lies outside the pane: no tap there.
                if !room.contains(outside) { continue }
                let beyond = tap("\(label), one step outside", at: outside, shift: edgeShift, within: Self.pointerTolerance)
                if edge.box.intersection(edge.view).contains(outside) {
                    expectOnTheLinksButton(beyond, edge.name)
                } else {
                    expectNotOpenedByThePage(beyond, edge.name)
                }
            }
        }
        if edge.name == "at-end" {
            let outermost = tap("\(named): \(edge.name), the pane's right-most column", at: CGPoint(x: room.maxX - 1, y: words.midY), shift: edgeShift, within: Self.pointerTolerance)
            expectOpened(outermost, edge.name)
        }
    }

    /// The area of the rule for one rectangle of a link's words held to the link's view: the words grown to the least
    /// size (44 points) and to 22 points beside them; where an edge of the view cuts one side of that and the words are
    /// wholly in view on that axis, the other side grows by what was cut; where the edge cuts through the words, only
    /// the part in view stays.
    private static func areaOf(_ words: CGRect, in view: CGRect) -> CGRect {
        let least: CGFloat = 44
        let beside: CGFloat = 22
        let wide = max(least, words.width + 2 * beside)
        let tall = max(least, words.height)
        func span(_ low: CGFloat, _ high: CGFloat, _ min: CGFloat, _ max: CGFloat, whole: Bool) -> (CGFloat, CGFloat) {
            var from = low
            var to = high
            if whole {
                if from < min { to += min - from; from = min }
                if to > max { from -= to - max; to = max }
            }
            return (Swift.max(from, min), Swift.min(to, max))
        }
        let across = span(words.midX - wide / 2, words.midX + wide / 2, view.minX, view.maxX, whole: words.minX >= view.minX && words.maxX <= view.maxX)
        let down = span(words.midY - tall / 2, words.midY + tall / 2, view.minY, view.maxY, whole: words.minY >= view.minY && words.maxY <= view.maxY)
        return CGRect(x: across.0, y: down.0, width: across.1 - across.0, height: down.1 - down.0)
    }

    /// A tap outside the area that lands on the link's own button: the system's click names the button, the page adds
    /// no click, and the look lit nothing or that link, as for any press on a link's own element.
    private func expectOnTheLinksButton(_ result: Result, _ name: String, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertFalse(result.events.contains { $0.type == "click" && !$0.trusted }, "\(result.label): the page added a click on the link's own button", file: file, line: line)
        if let disagreement = lookDisagreement(result) { XCTFail("\(result.label): \(disagreement)", file: file, line: line) }
        XCTAssertEqual(result.opened.count, 1, "\(result.label): the links that opened: \(result.opened), expected \(name) once", file: file, line: line)
        XCTAssertTrue(result.opened.allSatisfy { $0.hasSuffix(name) }, "\(result.label): opened \(result.opened), expected only \(name)", file: file, line: line)
    }

    /// A tap outside the area: the page adds no click and lights nothing; where the platform's own adjustment opens the
    /// link there, the system's click names the link's button.
    private func expectNotOpenedByThePage(_ result: Result, _ name: String, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertFalse(result.events.contains { $0.type == "click" && !$0.trusted }, "\(result.label): the page added a click outside the area", file: file, line: line)
        XCTAssertNil(result.events.first(where: { $0.type == "pointerdown" })?.lit, "\(result.label): the look lit outside the area", file: file, line: line)
        if !result.opened.isEmpty {
            let click = result.events.first { $0.type == "click" && $0.trusted }
            XCTAssertTrue(click?.target.contains("md-link") ?? false, "\(result.label): opened \(result.opened) with a click that named \(click?.target ?? "none")", file: file, line: line)
            XCTAssertEqual(result.opened.count, 1, "\(result.label): the links that opened: \(result.opened), expected \(name) once", file: file, line: line)
            XCTAssertTrue(result.opened.allSatisfy { $0.hasSuffix(name) }, "\(result.label): opened \(result.opened), expected only \(name)", file: file, line: line)
        }
    }

    /// Scrolls the conversation to its end, a drag at a time.
    private func scrollToEnd() {
        let shift = offset(of: link("table-1"))
        for _ in 0..<60 {
            let place = pane()
            if place.top >= place.most - 2 { return }
            let start = screenPoint(CGPoint(x: place.room.midX, y: place.room.midY), shift)
            start.press(forDuration: 0.05, thenDragTo: start.withOffset(CGVector(dx: 0, dy: -300)), withVelocity: .slow, thenHoldForDuration: 0.3)
            Thread.sleep(forTimeInterval: 1.0)
        }
    }

    /// A conversation shorter than the pane: the link alone, so the link's area is whole and the pane's bare area lies
    /// under it. A tap there gets the system's click on the pane itself, which opens nothing and lights nothing. This
    /// runs at both sizes.
    private func runShort(size: String?, named: String) {
        continueAfterFailure = true
        start(size: size, short: true)
        say("LINKTAP \(named): the record: \(recordText("TAPLINKS"))")
        say("LINKTAP size \(named)")
        let last = link("short-last")
        tapAround(last, named: named)
        let shift = offset(of: last)
        let room = pane().room
        let words = last.words[0]
        XCTAssertLessThanOrEqual(pane().most, 1, "\(named): the short conversation is taller than the pane")
        // The lowest point that the link's area or its own button reaches.
        let lowest = max(Self.areaOf(words, in: last.view).maxY, last.box.intersection(last.view).maxY)
        for below in [12, 40, 120, 300] as [CGFloat] {
            let y = min(lowest + below, room.maxY - 2)
            let bare = tap("\(named): the pane's bare area \(Int(below)) points under the link's area", at: CGPoint(x: words.midX, y: y), shift: shift)
            XCTAssertTrue(bare.events.contains { $0.type == "click" && $0.trusted }, "\(bare.label): the system sent no click to the bare area: \(bare.events.map(\.type))")
            XCTAssertFalse(bare.events.contains { $0.type == "click" && !$0.trusted }, "\(bare.label): the page added a click")
            XCTAssertTrue(bare.opened.isEmpty, "\(bare.label): opened \(bare.opened)")
            XCTAssertNil(bare.events.first(where: { $0.type == "pointerdown" })?.lit, "\(bare.label): the look lit")
        }
        let atBottom = tap("\(named): the pane's bottom row", at: CGPoint(x: words.midX, y: room.maxY - 1), shift: shift)
        XCTAssertTrue(atBottom.opened.isEmpty, "\(atBottom.label): opened \(atBottom.opened)")
    }

    /// The link on the conversation's last line, at the end of the conversation: the pane's bottom cuts the area under its words.
    private func runLastLine(size: String?, named: String) {
        continueAfterFailure = true
        start(size: size)
        say("LINKTAP size \(named)")
        scrollToEnd()
        tapAround(link("last-line"), named: named)
    }


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
        _ = scroll(to: "under-image")
        let control = app.buttons["Load this image"].firstMatch
        XCTAssertTrue(control.waitForExistence(timeout: 10), "the screen shows no Load this image control")
        // The control's frame is the screen's own, so the point is a screen point: no shift. The placeholder's row does not
        // wrap (the page's own layout), so at the largest size the control can lie wholly beyond the screen's edge: then no
        // finger can reach it, and it is said and not tapped.
        let controlFrame = control.frame.intersection(app.frame)
        if controlFrame.isNull || controlFrame.width < 20 {
            say("LINKTAP \(named): Load this image lies beyond the screen at this size (frame \(control.frame)): not tapped")
        } else {
            let onControl = tap(
                "\(named): 2 px inside the lower edge of Load this image",
                at: CGPoint(x: controlFrame.midX, y: controlFrame.maxY - 2),
                shift: .zero
            )
            let controlClicks = onControl.events.filter { $0.type == "click" && $0.trusted }
            XCTAssertEqual(controlClicks.count, 1, "\(onControl.label): the system's clicks that came: \(onControl.events.map(\.type))")
            XCTAssertTrue(
                (controlClicks.first?.target.hasPrefix("button") ?? false) && !(controlClicks.first?.target.contains("md-link") ?? true),
                "\(onControl.label): the click named \(controlClicks.first?.target ?? "nothing"), not the control"
            )
            XCTAssertFalse(onControl.events.contains { $0.type == "click" && !$0.trusted }, "\(onControl.label): the page added a click")
            XCTAssertTrue(onControl.opened.isEmpty, "\(onControl.label): opened \(onControl.opened)")
        }

        // The edge of the area in which a tap opens a link, in each of the four directions, for a link in the middle of
        // a line with no other link near. The area is what the page gives the words: grown by half the least size beside
        // them and to the least size in height (so, from the words' frame, 22 points beside the words and a height of 44
        // about their middle), and the link's own button box, which is the page's. A tap 2 points inside an edge opens the
        // link once; a tap just outside it (4 points, or 16 where the edge is the button's own box) opens nothing.
        let middle = scroll(to: "middle")
        let middleShift = offset(of: middle)
        let around = middle.words[0]
        let least: CGFloat = 44
        let halfTall = max(least, around.height) / 2
        let areaLeft = min(around.minX - least / 2, middle.box.minX)
        let areaRight = max(around.maxX + least / 2, middle.box.maxX)
        let areaTop = min(around.midY - halfTall, middle.box.minY)
        let areaBottom = max(around.midY + halfTall, middle.box.maxY)
        // Where the page's own button box is the edge (a tall line at the largest size), the system's own adjustment of a tap
        // to a button reaches a little beyond it, so the tap outside is made past that reach: 16 points. Where the edge is
        // the page's area for the words, it is 4 points.
        let leftGap: CGFloat = middle.box.minX <= around.minX - least / 2 ? 16 : 4
        let rightGap: CGFloat = middle.box.maxX >= around.maxX + least / 2 ? 16 : 4
        let topGap: CGFloat = middle.box.minY <= around.midY - halfTall ? 16 : 4
        let bottomGap: CGFloat = middle.box.maxY >= around.midY + halfTall ? 16 : 4
        let edges: [(String, CGPoint, CGPoint, CGFloat)] = [
            ("left", CGPoint(x: areaLeft + 2, y: around.midY), CGPoint(x: areaLeft - leftGap, y: around.midY), leftGap),
            ("right", CGPoint(x: areaRight - 2, y: around.midY), CGPoint(x: areaRight + rightGap, y: around.midY), rightGap),
            ("top", CGPoint(x: around.midX, y: areaTop + 2), CGPoint(x: around.midX, y: areaTop - topGap), topGap),
            ("bottom", CGPoint(x: around.midX, y: areaBottom - 2), CGPoint(x: around.midX, y: areaBottom + bottomGap), bottomGap),
        ]
        for (edge, inside, outside, gap) in edges {
            expectOpened(tap("\(named): the \(edge) edge of the area, 2 points inside", at: inside, shift: middleShift), "middle")
            let beyond = tap("\(named): the \(edge) edge of the area, \(Int(gap)) points outside", at: outside, shift: middleShift)
            XCTAssertTrue(beyond.opened.isEmpty, "\(beyond.label): opened \(beyond.opened)")
        }

        // The links at the pane's edges. A tap at each of nine points of the least-size square about the words, slid into the
        // pane (the corners and the middles of its sides, 2 points inside), opens the link once, the outermost points of the
        // area included; so does a tap at the pane's right-most column on the words' row, where the simulator shows whether
        // the system sends a click that far.
        for name in ["at-start", "at-end"] { tapAround(scroll(to: name), named: named) }

        // A press of one second on a link's words: what the platform does with it stands, and the page adds nothing.
        let pressed = scroll(to: "table-2")
        let held = tap(
            "\(named): a press of one second on a link's words",
            at: CGPoint(x: pressed.words[0].midX, y: pressed.words[0].midY),
            shift: offset(of: pressed),
            hold: 1.0,
            clickExpected: false
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
        // WebKit's own press moves the focus to the conversation (its tabindex) before the click, and the keyboard goes
        // with the composer's focus: the focus is on the conversation or on the link, never left in the composer.
        XCTAssertTrue(
            focused.focus.contains("active=div.m-pane") || focused.focus.contains("active=button.md-link(reconnect)"),
            "\(focused.label): the focus is \(focused.focus)"
        )
    }

    func testTapsAtTheDefaultTextSize() {
        runTaps(size: nil, named: "default size")
    }

    func testTapsAtTheLargestTextSize() {
        runTaps(size: Self.largest, named: "largest size")
    }

    func testAShortConversationAtTheDefaultTextSize() {
        runShort(size: nil, named: "short, default size")
    }

    func testAShortConversationAtTheLargestTextSize() {
        runShort(size: Self.largest, named: "short, largest size")
    }

    func testTheLastLineAtTheDefaultTextSize() {
        runLastLine(size: nil, named: "default size")
    }

    func testTheLastLineAtTheLargestTextSize() {
        runLastLine(size: Self.largest, named: "largest size")
    }
}

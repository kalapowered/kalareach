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

// BEGIN RULES
// What a link tap must do, as plain functions of the page's record. They use no UIKit and no XCTest, so the lines of a session can be
// held to them on a Mac with no simulator: everything between BEGIN RULES and END RULES compiles alone with Foundation.

enum LinkTapRules {
    /// One event the page saw, in the order it saw it.
    struct Seen {
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
        /// At a pointer down, a pointer up and a click: every link that had the look by then, by name, joined with commas, or nil
        /// where none had. A press on plain text lights nothing, and the look at a click is the one link that opens.
        let lit: String?
        /// The page's clock when the record read the event, in milliseconds: the clock of the page's own press handling.
        let at: Double?
        /// The page's clock when the event itself was made, in milliseconds: a click's own time, which no load on the page delays.
        let born: Double?
    }

    /// One change of the pressed look that the page saw: a link got it (`on`) or lost it, after the event with the
    /// number `after`, at `at` milliseconds on the page's clock.
    struct Look: Hashable {
        let after: Int
        let on: Bool
        let name: String
        let at: Double
    }

    /// What one tap did, as the page saw it, and the links that were lit when it began.
    struct Tap {
        let label: String
        let events: [Seen]
        let looks: [Look]
        let opened: [String]
        let focus: String
        let litBefore: [String]
    }

    private static func time(_ field: Substring, _ prefix: String) -> Double? {
        field.hasPrefix(prefix) ? Double(field.dropFirst(prefix.count)) : nil
    }

    /// The text of the page's `TAPLOG` line without its label: its events and the changes of the look, oldest first.
    static func parse(_ text: String) -> (events: [Seen], looks: [Look]) {
        var events: [Seen] = []
        var looks: [Look] = []
        for part in text.components(separatedBy: " ; ") {
            let fields = part.split(separator: " ")
            if fields.count == 5, fields[0] == "V", let after = Int(fields[1]), let at = time(fields[4], "t=") {
                looks.append(Look(after: after, on: fields[2] == "on", name: String(fields[3]), at: at))
                continue
            }
            guard fields.count >= 11, fields[0] == "E", let order = Int(fields[1]), let detail = Int(fields[5]),
                let x = Double(fields[6]), let y = Double(fields[7])
            else { continue }
            let lit = fields.count > 11 && fields[11].hasPrefix("lit=") ? String(fields[11].dropFirst(4)) : "-"
            events.append(Seen(
                order: order, type: String(fields[2]), target: String(fields[3]), trusted: fields[4] == "1", detail: detail,
                point: CGPoint(x: x, y: y), kind: String(fields[8]), pointer: String(fields[9]), pointerType: String(fields[10]),
                lit: lit == "-" ? nil : lit,
                at: fields.count > 12 ? time(fields[12], "t=") : nil,
                born: fields.count > 13 ? time(fields[13], "e=") : nil
            ))
        }
        return (events, looks)
    }

    /// The text of a `TAPLIT` line without its label: the links that are lit, by name; none for `-`.
    static func parseLit(_ text: String) -> [String] {
        let names = text.trimmingCharacters(in: .whitespaces)
        return names.isEmpty || names == "-" ? [] : names.split(separator: ",").map(String.init)
    }

    /// The name that an element's description carries between its parentheses, the link's own name: every element in a link has it.
    static func linkName(of target: String) -> String? {
        guard let open = target.lastIndex(of: "("), target.hasSuffix(")") else { return nil }
        return String(target[target.index(after: open)..<target.index(before: target.endIndex)])
    }

    /// The link's name at the end of an address the host opened.
    static func name(ofAddress address: String) -> String {
        String(address.split(separator: "/").last ?? "")
    }

    static func pressOf(_ tap: Tap) -> Seen? { tap.events.first { $0.type == "pointerdown" } }
    static func releaseOf(_ tap: Tap) -> Seen? { tap.events.first { $0.type == "pointerup" } }
    static func clickOf(_ tap: Tap) -> Seen? { tap.events.first { $0.type == "click" && $0.trusted } }

    /// What the system's click named: `none`, `link` (a link's own element), `control` (another button), `composer` (the text
    /// field) or `plain text` (the pane, a message or anything else, where only the page decides).
    static func clickKind(_ tap: Tap) -> String {
        guard let click = clickOf(tap) else { return "none" }
        if linkName(of: click.target) != nil { return "link" }
        if click.target.hasPrefix("button") { return "control" }
        return click.target.hasPrefix("textarea") ? "composer" : "plain text"
    }

    /// The links that have the look at a time on the page's clock: those lit when the tap began, then every change that the
    /// record's look lines made up to that time.
    static func lit(_ tap: Tap, at time: Double) -> Set<String> {
        var set = Set(tap.litBefore)
        for look in tap.looks where look.at <= time {
            if look.on { set.insert(look.name) } else { set.remove(look.name) }
        }
        return set
    }

    /// The least slack, in milliseconds, between the page's clock at an event's own time and at the record's read of a look change:
    /// the two clocks are read apart and the engine rounds both, so a look that is `on` within this of a click's time came with the click.
    static let clockSlack = 2.0

    /// The look against what the tap did, or nil where they agree. The four rules, at every tap and for the WHOLE press:
    /// (0) No link is lit when a tap starts.
    /// (1) AT THE CLICK the lit link is the link that opens, with no exception: where the system's click names a link's
    /// element, that link, and the record's list of the links opened is exactly that link; where it names plain text, the one link
    /// the page opens from it, or none; where it names a control, none, and nothing opens. A click line has its times.
    /// (2) AT THE PRESS AND UNTIL THE CLICK (or, where no click comes, until the tap's end) nothing is lit after a press on plain text
    /// or on a control, and after a press on a link's own element only that link is lit.
    /// (3) Where the press lit another link than the click opens, that first link's look is OFF at the click: never two links lit,
    /// never the first left lit, read from the record's look lines and from the lines' `lit=` lists.
    /// (4) No link opens that is not lit at its click, and where no click comes nothing opens.
    /// A tap that gets no trusted click fails unless `clickExpected` is false; a tap whose pointer the page never saw fails unless
    /// `pointerExpected` is false.
    static func disagreement(_ tap: Tap, clickExpected: Bool = true, pointerExpected: Bool = true) -> String? {
        if !tap.litBefore.isEmpty { return "lit before the tap began: \(tap.litBefore.joined(separator: ","))" }
        let down = pressOf(tap)
        if down == nil, pointerExpected { return "the page saw no pointer down: \(tap.events.map(\.type))" }
        let clicked = clickOf(tap)
        if let clicked, clicked.at == nil || clicked.born == nil { return "the click's line has no time (t= and e=): \(clicked.target)" }
        let own = down.flatMap { linkName(of: $0.target) }
        let pressedOn = down?.target ?? "no pointer down"
        // (2) The press and the release: the links lit then are none, or the link whose own element the pointer named.
        for event in [down, releaseOf(tap)].compactMap({ $0 }) {
            if let lit = event.lit, lit != own { return "\(lit) lit at the \(event.type == "pointerdown" ? "press" : "release") on \(pressedOn)" }
        }
        // (2) The whole press: no look comes on before the click (or at all where no click comes), but the own link's.
        let until = clicked?.born.map { $0 - clockSlack } ?? .infinity
        for look in tap.looks where look.on && look.at < until {
            if look.name != own {
                return "\(look.name) lit at \(look.at) ms, \(clicked == nil ? "in a tap that got no click" : "before the click"), after a press on \(pressedOn)"
            }
        }
        guard let click = clicked, let at = click.at else {
            if !tap.opened.isEmpty { return "\(tap.opened) opened and no trusted click came" }
            return clickExpected ? "no trusted click arrived" : nil
        }
        // (1) What the click opens, and the record's list of the links opened.
        let opens: String?
        if let named = linkName(of: click.target) {
            guard tap.opened.count == 1, name(ofAddress: tap.opened[0]) == named else {
                return "the click named \(click.target), the links that opened: \(tap.opened)"
            }
            opens = named
        } else if click.target.hasPrefix("button") {
            guard tap.opened.isEmpty else { return "the click named the control \(click.target), the links that opened: \(tap.opened)" }
            opens = nil
        } else {
            guard tap.opened.count <= 1 else { return "the click named plain text \(click.target), the links that opened: \(tap.opened)" }
            opens = tap.opened.last.map(name(ofAddress:))
        }
        if click.lit != opens { return "the click named \(click.target), lit \(click.lit ?? "nothing") at the click, the link that opens is \(opens ?? "none")" }
        // (3) and (4) The links lit at the click, from the record's look lines.
        let set = lit(tap, at: at)
        if set != Set(opens.map { [$0] } ?? []) { return "the links lit at the click: \(set.sorted()), the link that opens: \(opens ?? "none")" }
        for address in tap.opened where !set.contains(name(ofAddress: address)) { return "\(address) opened and was not lit at the click" }
        return nil
    }

    /// A press in the gap below the pane. The page's rule reads the press's point, so a press there lights nothing and opens nothing,
    /// whether the engine gives no click or moves a click onto plain text or the composer inside the pane. A click that the
    /// engine moves onto the last link's own element opens it once; `disagreement` holds that only it is lit.
    static func gapDisagreement(_ tap: Tap, paneBottom: CGFloat) -> String? {
        guard let down = pressOf(tap) else { return "the page saw no pointer down: \(tap.events.map(\.type))" }
        if down.point.y <= paneBottom { return "the press was at y \(down.point.y), not below the pane's edge at \(paneBottom)" }
        if linkName(of: down.target) != nil { return "the press named a link's element \(down.target)" }
        let clicked = clickOf(tap)
        if let clicked, let named = linkName(of: clicked.target) {
            guard tap.opened.count == 1, name(ofAddress: tap.opened[0]) == named else {
                return "the click named \(clicked.target) and the links that opened are \(tap.opened)"
            }
            return nil
        }
        if let look = tap.looks.first(where: \.on) { return "\(look.name) was lit by a press in the gap (the click named \(clicked?.target ?? "none"))" }
        if !tap.opened.isEmpty { return "\(tap.opened) opened by a press in the gap (the click named \(clicked?.target ?? "none"))" }
        return nil
    }

    /// The least time, in milliseconds, that the look stays after a click: the hold is 150 ms from the click, and the clock is
    /// read to a millisecond.
    static let leastHold = 149.0

    /// A tap on plain text that opens a link: the look is not on before the release, and it ends at least `leastHold` after the click's
    /// own time (not the record's read of the click, which a loaded page delays).
    static func releaseDisagreement(_ tap: Tap, _ name: String) -> String? {
        guard let down = pressOf(tap), let up = releaseOf(tap)?.at, let born = clickOf(tap)?.born else {
            return "the record has no press, release or click with a time"
        }
        guard let on = tap.looks.first(where: { $0.on && $0.name == name }) else { return "the look never went on for \(name): \(tap.looks)" }
        if linkName(of: down.target) == nil, on.at < up { return "the look went on at \(on.at) ms, before the release at \(up) ms, after a press on plain text" }
        guard let off = tap.looks.first(where: { !$0.on && $0.name == name && $0.at > born }) else {
            return "the look did not end after the click: \(tap.looks)"
        }
        if off.at - born < leastHold { return "the look ended \(off.at - born) ms after the click's own time" }
        return nil
    }

    // MARK: The band between two stacked links

    /// One tap of the walk across the border of two links: the touch row the page saw the pointer in (the simulator puts a touch on the
    /// pixel grid, a third of a point), the link whose element the pointer-down named and the link the click named.
    struct BandStep: Equatable {
        let row: Int
        let down: String?
        let click: String?
    }

    /// The touch row of a page coordinate.
    static func row(of y: CGFloat) -> Int { Int((Double(y) * 3).rounded()) }

    /// A tap as a step of the walk, or nil where the page saw no pointer down.
    static func bandStep(of tap: Tap) -> BandStep? {
        guard let down = pressOf(tap) else { return nil }
        return BandStep(row: row(of: down.point.y), down: linkName(of: down.target), click: clickOf(tap).flatMap { linkName(of: $0.target) })
    }

    /// Whether the pointer-down and the click named different links.
    static func differs(_ step: BandStep) -> Bool {
        guard let down = step.down, let click = step.click else { return false }
        return down != click
    }

    /// Where the opened link changes in a sweep: the first two neighbouring rows that opened two different links, as the points
    /// that bound the change and the link before it; nil where the sweep shows no change.
    static func firstChange(_ owners: [(y: CGFloat, name: String)]) -> (low: CGFloat, high: CGFloat, before: String)? {
        for (before, after) in zip(owners, owners.dropFirst()) where before.name != after.name {
            return (before.y, after.y, before.name)
        }
        return nil
    }

    /// Whether a walk away from the border has gone past the band: its last two steps lie on two touch rows and have the pointer-down
    /// and the click both on `far`, the link at that end of the walk.
    static func pastTheBand(_ steps: [BandStep], far: String) -> Bool {
        let tail = steps.suffix(2)
        guard tail.count == 2, Set(tail.map(\.row)).count == 2 else { return false }
        return tail.allSatisfy { $0.down == far && $0.click == far }
    }

    /// The touch rows at which the pointer-down and the click named different links, in the steps of both walks.
    static func bandRows(_ steps: [BandStep]) -> [Int] {
        Array(Set(steps.filter(differs).map(\.row))).sorted()
    }

    /// The band must be narrower than two touch rows: at most one row of the walk has the pointer-down and the click on different
    /// links, and the rows past it on both sides agree (`pastTheBand`, which the walk checks).
    static func bandDisagreement(_ steps: [BandStep]) -> String? {
        let rows = bandRows(steps)
        if rows.count > 1 { return "the pointer-down and the click named different links on \(rows.count) touch rows \(rows) (a row is a third of a point): not narrower than two rows" }
        return nil
    }
}
// END RULES

final class LinkTapTests: HarnessTestCase {
    private static let largest = "UICTContentSizeCategoryAccessibilityXXXL"

    // MARK: What the page records

    private typealias Seen = LinkTapRules.Seen
    private typealias Look = LinkTapRules.Look
    private typealias Result = LinkTapRules.Tap

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

    /// The page's tap record: its events and the changes of the look, oldest first.
    private func record() -> (events: [Seen], looks: [Look]) {
        LinkTapRules.parse(String(recordText("TAPLOG").dropFirst("TAPLOG".count)))
    }

    /// The links that are lit now.
    private func litNow() -> [String] {
        LinkTapRules.parseLit(String(recordText("TAPLIT").dropFirst("TAPLIT".count)))
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

    /// What every tap's release-to-click time was, on the page's clock, for the summary at the run's end.
    private var clickDelays: [(label: String, delay: Double)] = []

    private func screenPoint(_ point: CGPoint, _ shift: CGVector) -> XCUICoordinate {
        app.coordinate(withNormalizedOffset: .zero).withOffset(CGVector(dx: point.x + shift.dx, dy: point.y + shift.dy))
    }

    /// Taps a point of the page, or holds a finger on it for `hold` seconds, and reports what happened after the last
    /// event the record had before. Every tap is held to the four rules of `LinkTapRules.disagreement`, the whole press and
    /// the click, and begins with no link lit.
    ///
    /// `within` holds the page's own pointer point to the requested point: the tap fails where the page saw the pointer farther
    /// from the point than that on either axis, so a calibration that is wrong fails the tap and does not move the samples.
    /// `clickExpected` is false for a press that the platform may leave without a click (a long press).
    /// `pointerExpected` is false for a step that expects the page to see no press at all.
    private func tap(_ label: String, at point: CGPoint, shift: CGVector, hold: TimeInterval = 0, clickExpected: Bool = true, pointerExpected: Bool = true, within tolerance: CGFloat? = nil) -> Result {
        let first = record()
        let before = first.events.last?.order ?? 0
        let looksBefore = Set(first.looks)
        let openedBefore = opened().count
        let litBefore = litNow()
        if hold > 0 {
            screenPoint(point, shift).press(forDuration: hold)
        } else {
            screenPoint(point, shift).tap()
        }
        Thread.sleep(forTimeInterval: 1.2)
        let last = record()
        let seen = last.events.filter { $0.order > before }
        let now = opened()
        let result = Result(label: label, events: seen, looks: last.looks.filter { !looksBefore.contains($0) }, opened: Array(now.dropFirst(openedBefore)), focus: recordText("TAPFOCUS"), litBefore: litBefore)
        report(result, at: point)
        if let tolerance, let down = seen.first(where: { $0.type == "pointerdown" }) {
            XCTAssertLessThanOrEqual(abs(down.point.x - point.x), tolerance, "\(label): the page saw the pointer at x \(down.point.x), the requested point is x \(point.x)")
            XCTAssertLessThanOrEqual(abs(down.point.y - point.y), tolerance, "\(label): the page saw the pointer at y \(down.point.y), the requested point is y \(point.y)")
        }
        if let disagreement = LinkTapRules.disagreement(result, clickExpected: clickExpected, pointerExpected: pointerExpected) { XCTFail("\(label): the pressed look and the click disagree: \(disagreement)") }
        return result
    }

    /// How far the page's own pointer point may lie from the requested point on either axis, in points, for the taps of a
    /// link's boundary. The inside taps lie 1 point inside an edge and the outside taps 3 points outside it, and a first
    /// tap sets the screen offset, so a tap that lands farther than this from its point is not a sample of that boundary.
    private static let pointerTolerance: CGFloat = 1.5

    /// Drags from a point of the page to another, slowly enough for the page to scroll with the finger.
    private func drag(_ label: String, from point: CGPoint, by distance: CGVector, shift: CGVector) -> Result {
        let first = record()
        let before = first.events.last?.order ?? 0
        let looksBefore = Set(first.looks)
        let openedBefore = opened().count
        let litBefore = litNow()
        let start = screenPoint(point, shift)
        let end = screenPoint(CGPoint(x: point.x + distance.dx, y: point.y + distance.dy), shift)
        // A swipe at the system's own speed, which the page takes for a scroll.
        start.press(forDuration: 0.05, thenDragTo: end, withVelocity: .default, thenHoldForDuration: 0)
        Thread.sleep(forTimeInterval: 1.2)
        let last = record()
        let seen = last.events.filter { $0.order > before }
        let result = Result(label: label, events: seen, looks: last.looks.filter { !looksBefore.contains($0) }, opened: Array(opened().dropFirst(openedBefore)), focus: "\(recordText("TAPFOCUS")) scrolled \(Int(pane().top))", litBefore: litBefore)
        report(result, at: point)
        XCTAssertTrue(litBefore.isEmpty, "\(label): lit before the drag began: \(litBefore)")
        return result
    }

    /// Says what one tap did, one line, where the run's log can be read for it.
    private func report(_ result: Result, at point: CGPoint) {
        if let delay = releaseToClick(result) { clickDelays.append((result.label, delay)) }
        let list = result.events.map {
            "\($0.type)(\($0.target),\($0.trusted ? "trusted" : "synthetic"),detail \($0.detail),\($0.kind) pointer \($0.pointer) \($0.pointerType),at \(String(format: "%.1f %.1f", $0.point.x, $0.point.y)))"
        }.joined(separator: " ")
        say("LINKTAP \(result.label) at (\(Int(point.x)), \(Int(point.y))): \(list.isEmpty ? "no events" : list) | the click named: \(named(result)) | lit before the tap: \(result.litBefore.isEmpty ? "nothing" : result.litBefore.joined(separator: ",")) | lit at the press: \(pressLook(result) ?? "nothing") | lit at the click: \(clickLook(result) ?? "nothing") | press-to-click(\(clickKind(result))): \(away(result).map { String(format: "%.1f", $0) } ?? "no click") | \(timing(result)) | pointer point off by \(pointerOff(result, at: point)) | opened: \(result.opened.isEmpty ? "nothing" : result.opened.joined(separator: " ")) | \(result.focus)")
    }

    /// How long after the pointer's release the system's click came, in milliseconds on the page's clock, or nil where
    /// no click came. A click later than the look's hold (150 ms) after the release finds the look gone and lights it again.
    private func releaseToClick(_ result: Result) -> Double? {
        guard let up = result.events.first(where: { $0.type == "pointerup" })?.at,
            let clicked = result.events.first(where: { $0.type == "click" && $0.trusted }),
            let click = clicked.born ?? clicked.at
        else { return nil }
        return click - up
    }

    /// The page's clock at the release and the click, in milliseconds after the press, and when the look went on and off.
    private func timing(_ result: Result) -> String {
        let down = result.events.first(where: { $0.type == "pointerdown" })?.at
        func since(_ at: Double?) -> String {
            guard let at, let down else { return "-" }
            return String(format: "%.1f", at - down)
        }
        let up = result.events.first(where: { $0.type == "pointerup" })?.at
        let click = result.events.first(where: { $0.type == "click" && $0.trusted })?.at
        let looks = result.looks.map { "\($0.on ? "on" : "off")(\($0.name)) \(since($0.at))" }.joined(separator: ", ")
        let delay = releaseToClick(result).map { String(format: "%.1f", $0) } ?? "no click"
        return "page clock, ms after the press: release \(since(up)), click \(since(click)), release-to-click \(delay) | looks: \(looks.isEmpty ? "none" : looks)"
    }

    /// Says how long every tap of the run took from its release to its click, and how many were later than the hold.
    private func summarizeClickDelays(_ named: String) {
        let late = clickDelays.filter { $0.delay > 150 }
        let detail = late.map { "\($0.label) \(String(format: "%.1f", $0.delay))" }.joined(separator: "; ")
        let largest = clickDelays.map(\.delay).max().map { String(format: "%.1f", $0) } ?? "none"
        say("LINKTAP \(named): release-to-click on the page's clock: \(clickDelays.count) taps got a click, largest \(largest) ms, later than 150 ms: \(late.count) \(detail)")
    }

    /// What the system's click landed on: a link's own element, a control, the composer or plain text, where only the page decides.
    private func clickKind(_ result: Result) -> String { LinkTapRules.clickKind(result) }

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
    private func linkName(of target: String) -> String? { LinkTapRules.linkName(of: target) }

    /// The look the page had lit at the pointer's press, or nil.
    private func pressLook(_ result: Result) -> String? {
        result.events.first(where: { $0.type == "pointerdown" })?.lit
    }

    /// The look the page had lit at the system's trusted click, or nil.
    private func clickLook(_ result: Result) -> String? {
        result.events.first(where: { $0.type == "click" && $0.trusted })?.lit
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

    /// Scrolls the conversation until a link's words lie near the middle of the screen, and reads the link again. It fails where the
    /// words are not near after `attempts` drags: a tap on a link that is off the screen reaches nothing, and no step may go on as if it had.
    private func scroll(to name: String, attempts: Int = 40) -> Link {
        func measure() -> (link: Link, shift: CGVector, room: CGRect, distance: CGFloat) {
            let current = link(name)
            let shift = offset(of: current)
            let room = pane().room
            let screenY = (current.words.first?.midY ?? 0) + shift.dy
            // The middle of the pane as it is now, which the keyboard can have made short.
            return (current, shift, room, screenY - (room.midY + shift.dy))
        }
        for attempt in 0..<attempts {
            let now = measure()
            if abs(now.distance) < 60 { return now.link }
            // A drag from the middle of the pane moves the content with the finger; a drag that starts on a link scrolls too.
            // The frame that the system gives a button far off the screen can be wrong: after eight drags that have not brought the
            // link near, the drag starts at the middle of the screen, where the pane lies at both text sizes.
            if attempt == 8 { say("LINKLOOK scroll to \(name): not near after 8 drags: its first line is \(now.link.words.first ?? .zero), the pane \(now.room), the button's offset \(now.shift)") }
            let start = attempt < 8 ? screenPoint(CGPoint(x: now.room.midX, y: now.room.midY), now.shift) : app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.5))
            let end = start.withOffset(CGVector(dx: 0, dy: -max(min(now.distance, 300), -300)))
            start.press(forDuration: 0.05, thenDragTo: end, withVelocity: .slow, thenHoldForDuration: 0.3)
            Thread.sleep(forTimeInterval: 1.0)
        }
        let last = measure()
        XCTAssertLessThan(abs(last.distance), 60, "scroll to \(name): the link's words are \(last.distance) points from the middle of the pane after \(attempts) drags (first line \(last.link.words.first ?? .zero), the pane \(last.room))")
        return last.link
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

    /// A tap outside the area that lands on the link's own button: the system's click names the button, the page adds no
    /// click, and the link opens once and has the look at the click (the tap's own check holds the look and the opening).
    private func expectOnTheLinksButton(_ result: Result, _ name: String, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertFalse(result.events.contains { $0.type == "click" && !$0.trusted }, "\(result.label): the page added a click on the link's own button", file: file, line: line)
        XCTAssertEqual(result.opened.count, 1, "\(result.label): the links that opened: \(result.opened), expected \(name) once", file: file, line: line)
        XCTAssertTrue(result.opened.allSatisfy { $0.hasSuffix(name) }, "\(result.label): opened \(result.opened), expected only \(name)", file: file, line: line)
    }

    /// A tap outside the area: the page adds no click and lights nothing at the press, and nothing opens unless the platform's own
    /// adjustment moves the click onto the link's button: then the system's click names that link, which opens once and has the
    /// look at the click. A click on plain text opens nothing here.
    private func expectNotOpenedByThePage(_ result: Result, _ name: String, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertFalse(result.events.contains { $0.type == "click" && !$0.trusted }, "\(result.label): the page added a click outside the area", file: file, line: line)
        XCTAssertNil(pressLook(result), "\(result.label): the look lit at the press outside the area", file: file, line: line)
        let click = result.events.first { $0.type == "click" && $0.trusted }
        let named = click.flatMap { linkName(of: $0.target) }
        XCTAssertEqual(clickLook(result), named, "\(result.label): the look at the click outside the area, the click named \(click?.target ?? "none")", file: file, line: line)
        if let named {
            XCTAssertEqual(result.opened.map(LinkTapRules.name(ofAddress:)), [name], "\(result.label): the click named \(named), the links that opened: \(result.opened), expected \(name) once", file: file, line: line)
        } else {
            XCTAssertTrue(result.opened.isEmpty, "\(result.label): opened \(result.opened) with a click that named \(click?.target ?? "none")", file: file, line: line)
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
    /// under it. A tap there gets the system's click on the pane itself, which opens nothing and lights nothing, or the click
    /// of the link's own button where the platform's adjustment reaches it, which opens the link and lights it at the click.
    /// This runs at both sizes.
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
            // The page opens nothing here and lights nothing at the press. Where the platform's own adjustment moves the click onto
            // the link's button (the system's click names it), the link opens by that click and has the look at the click.
            expectNotOpenedByThePage(bare, "short-last")
        }
        let atBottom = tap("\(named): the pane's bottom row", at: CGPoint(x: words.midX, y: room.maxY - 1), shift: shift)
        XCTAssertTrue(atBottom.opened.isEmpty, "\(atBottom.label): opened \(atBottom.opened)")
        summarizeClickDelays(named)
    }

    /// The link on the conversation's last line, at the end of the conversation: the pane's bottom cuts the area under its words.
    private func runLastLine(size: String?, named: String) {
        continueAfterFailure = true
        start(size: size)
        say("LINKTAP size \(named)")
        scrollToEnd()
        tapAround(link("last-line"), named: named)
        summarizeClickDelays(named)
    }


    /// A point of the conversation a line away from every link: 40 points beside a link's box and a line and 40 points above or below
    /// it, on the pane's middle column; nil where there is none.
    private func awayFromLinks() -> CGPoint? {
        let all = links()
        let room = pane().room
        var y = room.minY + 12
        while y < room.maxY - 12 {
            let candidate = CGPoint(x: room.midX, y: y)
            if all.allSatisfy({ !$0.box.insetBy(dx: -40, dy: -(40 + $0.line)).contains(candidate) }) { return candidate }
            y += 6
        }
        return nil
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
        let shiftNow = offset(of: link("docs"))
        if let away = awayFromLinks() {
            let result = tap("\(named): one line away from every link", at: away, shift: shiftNow)
            XCTAssertTrue(result.opened.isEmpty, "\(result.label): opened \(result.opened)")
        } else {
            XCTFail("no point of the conversation lies a line away from every link: \(pane().room)")
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
        // The keyboard rises with an animation that a loaded simulator can slow, so it is waited for (10 seconds at most) and the
        // report says how long it took and what the page's record saw of the tap.
        let tapped = Date()
        _ = app.keyboards.firstMatch.waitForExistence(timeout: 10)
        let raisedAfter = Int(Date().timeIntervalSince(tapped) * 1000)
        Thread.sleep(forTimeInterval: 1.5)
        let keyboardBefore = app.keyboards.count
        let composerEvents = record().events.suffix(4).map { "\($0.type)(\($0.target))" }.joined(separator: " ")
        say("LINKTAP \(named): the composer's tap: keyboard up after \(raisedAfter) ms, keyboards \(keyboardBefore); \(recordText("TAPFOCUS")); the page's last events: \(composerEvents)")
        let reference = scroll(to: "reconnect")
        let withKeyboard = offset(of: reference)
        let words = reference.words[0]
        let focused = tap("\(named): a link while the composer has focus", at: CGPoint(x: words.midX, y: words.midY), shift: withKeyboard)
        say("LINKTAP \(named): composer focus: keyboards before \(keyboardBefore), after \(app.keyboards.count); opened \(focused.opened); \(focused.focus)")
        XCTAssertGreaterThan(keyboardBefore, 0, "\(focused.label): the keyboard was not up before the tap, ten seconds after the tap on the composer")
        expectOpened(focused, "reconnect")
        // WebKit's own press moves the focus to the conversation (its tabindex) before the click, and the keyboard goes
        // with the composer's focus: the focus is on the conversation or on the link, never left in the composer.
        XCTAssertTrue(
            focused.focus.contains("active=div.m-pane") || focused.focus.contains("active=button.md-link(reconnect)"),
            "\(focused.label): the focus is \(focused.focus)"
        )
        summarizeClickDelays(named)
    }

    // MARK: The look

    /// The distance from a point to a rectangle, zero inside it.
    private func distance(from point: CGPoint, to rect: CGRect) -> CGFloat {
        hypot(max(rect.minX - point.x, 0, point.x - rect.maxX), max(rect.minY - point.y, 0, point.y - rect.maxY))
    }

    /// The link whose words lie nearest a point, which is what the page's rule picks on plain text.
    private func nearest(_ point: CGPoint, among all: [Link]) -> String? {
        func gap(_ link: Link) -> CGFloat { link.words.map { distance(from: point, to: $0) }.min() ?? .infinity }
        return all.min { gap($0) < gap($1) }?.name
    }

    /// A tap on plain text that opens a link: no look before the release, and the look stays at least 150 ms from the click's own
    /// time (the page's clock; the look's end is the first change after the click).
    private func expectTheLookAtTheRelease(_ result: Result, _ name: String, file: StaticString = #filePath, line: UInt = #line) {
        if let disagreement = LinkTapRules.releaseDisagreement(result, name) { XCTFail("\(result.label): \(disagreement)", file: file, line: line) }
    }

    /// A press held on plain text: no look at touch-down, none at the end of the hold, none turned on between.
    private func expectNoLookDuringTheHold(_ result: Result, file: StaticString = #filePath, line: UInt = #line) {
        guard let down = result.events.first(where: { $0.type == "pointerdown" }),
            let up = result.events.first(where: { $0.type == "pointerup" })
        else {
            XCTFail("\(result.label): the record has no press or release", file: file, line: line)
            return
        }
        XCTAssertNil(down.lit, "\(result.label): the look at touch-down", file: file, line: line)
        XCTAssertNil(up.lit, "\(result.label): the look at the end of the hold", file: file, line: line)
        let during = result.looks.filter { $0.on && $0.at <= (up.at ?? .infinity) }
        XCTAssertTrue(during.isEmpty, "\(result.label): the look went on during the hold: \(during)", file: file, line: line)
        if let from = down.at, let to = up.at { XCTAssertGreaterThan(to - from, 800, "\(result.label): the press was held \(to - from) ms", file: file, line: line) }
    }

    /// What a tap between links did, for the log: the press's target, the click's, the link the nearest-words rule picks at the
    /// press's point, and whether the click named another link. The light and the opening are held by `tap` (the look at the
    /// click is the link that opens); here at most one link opens, and a click that names a link opens that link.
    private func judge(_ result: Result, among all: [Link], what: String) -> (opens: String?, other: Bool, different: Bool) {
        guard let down = result.events.first(where: { $0.type == "pointerdown" }), let click = result.events.first(where: { $0.type == "click" && $0.trusted }) else {
            say("LINKLOOK \(what): no press or no trusted click: \(result.events.map(\.type))")
            return (nil, false, false)
        }
        let named = click.target.contains("md-link") ? linkName(of: click.target) : nil
        let pick = nearest(down.point, among: all)
        let other = named != nil && named != pick
        XCTAssertLessThanOrEqual(result.opened.count, 1, "\(result.label): the links that opened: \(result.opened)")
        if let named { XCTAssertTrue(result.opened.count == 1 && result.opened[0].hasSuffix("/" + named), "\(result.label): the click named \(named), opened \(result.opened)") }
        let opens = result.opened.last.map { String($0.split(separator: "/").last ?? "") }
        say("LINKLOOK \(what): press target \(down.target) at \(String(format: "%.2f %.2f", down.point.x, down.point.y)), click target \(click.target), nearest words \(pick ?? "none"), the click named the other link: \(other), lit at the press \(down.lit ?? "nothing"), lit at the click \(click.lit ?? "nothing"), opened \(opens ?? "nothing")")
        // The press's own link element against the link the click named: where they differ, the times of the looks say how the look moved.
        let pressed = down.target.contains("md-link") ? linkName(of: down.target) : nil
        let different = pressed != nil && named != nil && pressed != named
        if different {
            say("LINKLOOK \(what): the pointer-down named the element of \(pressed ?? "") and the click named \(named ?? ""); \(timing(result))")
        }
        return (opens, other, different)
    }

    /// The look at every point of one text size that the part (a) rule gives it: touch-down on a link's words, no look under a
    /// held press 15 px past the words, the look at the release, two stacked links where the click names the other link, a
    /// sub-pixel walk across the border of two links, and a touch in the gap below the pane next to a link at the pane's edge.
    private func runLook(size: String?, named: String) {
        continueAfterFailure = true
        start(size: size)
        say("LINKTAP size \(named)")

        // The look at touch-down: a press on a link's own words lights the link at once, and it has the look at the click.
        let table1 = scroll(to: "table-1")
        let onWords = table1.words[0]
        let touched = tap("\(named): look at touch-down: a press on the link's words", at: CGPoint(x: onWords.midX, y: onWords.midY), shift: offset(of: table1))
        expectOpened(touched, "table-1")
        XCTAssertEqual(pressLook(touched), "table-1", "\(touched.label): the look at touch-down")
        XCTAssertEqual(clickLook(touched), "table-1", "\(touched.label): the look at the click")
        say("LINKLOOK \(named): touch-down on the words: press look \(pressLook(touched) ?? "nothing"), click look \(clickLook(touched) ?? "nothing"); \(timing(touched))")

        // The release: plain text 16 to 20 px past a link's words gets no look at touch-down, and the link that opens has it from the click.
        _ = scroll(to: "docs")
        for beside in [16, 18, 20] as [CGFloat] {
            let docs = link("docs")
            let words = docs.words[docs.words.count - 1]
            let released = tap("\(named): look at the release: plain text \(Int(beside)) px past the words", at: CGPoint(x: words.maxX + beside, y: words.midY), shift: offset(of: docs))
            expectOpened(released, "docs")
            expectTheLookAtTheRelease(released, "docs")
            say("LINKLOOK \(named): release after a press \(Int(beside)) px past the words: press look \(pressLook(released) ?? "nothing"), click look \(clickLook(released) ?? "nothing"); \(timing(released))")
        }

        // A press held 15 px past the words: no look while the finger is down.
        let docs = link("docs")
        let past = docs.words[docs.words.count - 1]
        let held = tap("\(named): a held press 15 px past the words", at: CGPoint(x: past.maxX + 15, y: past.midY), shift: offset(of: docs), hold: 1.0, clickExpected: false)
        expectNoLookDuringTheHold(held)
        say("LINKLOOK \(named): held press 15 px past the words: press look \(pressLook(held) ?? "nothing"), look before the release \(held.events.first(where: { $0.type == "pointerup" })?.lit ?? "nothing"), opened \(held.opened.isEmpty ? "nothing" : held.opened.joined(separator: " ")); \(timing(held))")

        walkBetweenStackedLinks(named: named)
        tapBelowThePane(named: named)
        summarizeClickDelays(named)
    }

    /// Two links on lines one above the other: a sweep of points between their lines, a halving search of the place where the click's
    /// link changes, then a walk in quarter points away from it on both sides. At every tap the light and the opening are the same
    /// link (`tap` holds it). The walk goes on until two steps past the band agree, and the band is measured in the simulator's touch
    /// rows (a third of a point), the grid that every touch lands on: a width counted from requested steps would claim more than the
    /// rows show.
    private func walkBetweenStackedLinks(named: String) {
        var upper = scroll(to: "upper", attempts: 40)
        var shift = offset(of: upper)
        let first = upper.words[0]
        guard pane().room.contains(CGPoint(x: first.midX, y: first.midY)) else {
            XCTFail("\(named): the scroll did not bring the upper link into the pane: its first line is at \(first), the pane \(pane().room)")
            return
        }
        let calibration = tap("\(named): stacked links: the upper link's words, to place the taps", at: CGPoint(x: first.minX + min(12, first.width / 2), y: first.midY), shift: shift, within: 4)
        if let down = calibration.events.first(where: { $0.type == "pointerdown" }) {
            shift = CGVector(dx: shift.dx + first.minX + min(12, first.width / 2) - down.point.x, dy: shift.dy + first.midY - down.point.y)
        }
        expectOpened(calibration, "upper")
        upper = link("upper")
        let lower = link("lower")
        let top = upper.words[upper.words.count - 1]
        let bottom = lower.words[0]
        let all = links()
        let left = max(top.minX, bottom.minX)
        let right = min(top.maxX, bottom.maxX)
        let columns: [CGFloat] = right - left > 30 ? [left + 12, (left + right) / 2, right - 12] : [(left + right) / 2]
        let middle = columns[columns.count / 2]
        say("LINKLOOK \(named): stacked links: the upper link's last line \(top), the lower link's first line \(bottom), columns \(columns)")
        var taps = 0
        var other = 0
        var owners: [(y: CGFloat, name: String)] = []
        let rows = 9
        for row in 0..<rows {
            let y = top.midY + (bottom.midY - top.midY) * CGFloat(row) / CGFloat(rows - 1)
            for (index, x) in columns.enumerated() {
                let what = "\(named): stacked links, sweep row \(row) of \(rows - 1), column \(index)"
                let result = tap(what, at: CGPoint(x: x, y: y), shift: shift, within: 4)
                let verdict = judge(result, among: all, what: what)
                taps += 1
                if verdict.other { other += 1 }
                if x == middle, let opens = verdict.opens { owners.append((y, opens)) }
            }
        }
        say("LINKLOOK \(named): stacked links sweep: \(taps) taps, \(other) at which the click named another link than the nearest words")
        // The border: where the middle column's opened link first changes from one link to the next, found to within a fraction
        // of a point by halving the step that holds the change. A sweep that shows no change fails: there is no border to walk across.
        guard let change = LinkTapRules.firstChange(owners) else {
            XCTFail("\(named): the sweep of the middle column shows no change from one opened link to the next: \(owners.map { "\(String(format: "%.2f", Double($0.y))) \($0.name)" })")
            return
        }
        var low = change.low
        var high = change.high
        for halving in 0..<5 {
            let y = (low + high) / 2
            let what = "\(named): stacked links, halving \(halving + 1) of 5 between \(String(format: "%.2f", Double(low))) and \(String(format: "%.2f", Double(high)))"
            let result = tap(what, at: CGPoint(x: middle, y: y), shift: shift, within: 4)
            if judge(result, among: all, what: what).opens == change.before { low = y } else { high = y }
        }
        let border = (low + high) / 2
        // The walk: quarter points away from the border, down toward the lower link and then up toward the upper link, each side until two
        // steps on two touch rows past the band have the pointer-down and the click on the link at that end. A side that does not get there
        // in the most steps fails; so does a band that is not narrower than two touch rows.
        var walk: [String] = []
        var walkOther = 0
        func sample(_ y: CGFloat) -> LinkTapRules.BandStep? {
            let what = "\(named): stacked links, walk across the border, \(String(format: "%+.2f", Double(y - border))) px from \(String(format: "%.2f", Double(border)))"
            let result = tap(what, at: CGPoint(x: middle, y: y), shift: shift, within: 4)
            let verdict = judge(result, among: all, what: what)
            if verdict.other { walkOther += 1 }
            walk.append(verdict.opens ?? "nothing")
            return LinkTapRules.bandStep(of: result)
        }
        let mostSteps = 24
        var towardLower: [LinkTapRules.BandStep] = []
        var pastLower = false
        for index in 0...mostSteps {
            guard let step = sample(border + CGFloat(index) * 0.25) else { break }
            towardLower.append(step)
            if LinkTapRules.pastTheBand(towardLower, far: lower.name) { pastLower = true; break }
        }
        var towardUpper: [LinkTapRules.BandStep] = []
        var pastUpper = false
        for index in 1...mostSteps {
            guard let step = sample(border - CGFloat(index) * 0.25) else { break }
            towardUpper.append(step)
            if LinkTapRules.pastTheBand(towardUpper, far: upper.name) { pastUpper = true; break }
        }
        let walked = towardUpper.reversed() + towardLower
        let differing = LinkTapRules.bandRows(walked)
        say("LINKLOOK \(named): stacked links border: \(walked.count) steps of a quarter point walked (down \(towardLower.count), up \(towardUpper.count)) on \(Set(walked.map(\.row)).count) touch rows (a row is a third of a point); the pointer-down and the click named different links on \(differing.count) rows \(differing); two steps past the band agree: toward \(lower.name) \(pastLower), toward \(upper.name) \(pastUpper); \(differing.count < 2 ? "the band is narrower than two rows" : "the band is not narrower than two rows")")
        XCTAssertTrue(pastLower, "\(named): the walk toward \(lower.name) did not reach two steps on two touch rows past the band in \(mostSteps) steps of a quarter point: \(towardLower)")
        XCTAssertTrue(pastUpper, "\(named): the walk toward \(upper.name) did not reach two steps on two touch rows past the band in \(mostSteps) steps of a quarter point: \(towardUpper)")
        if let disagreement = LinkTapRules.bandDisagreement(walked) { XCTFail("\(named): \(disagreement): a product question") }
        say("LINKLOOK \(named): stacked links walk: the link that opened at each step, from the border downward and then upward: \(walk.joined(separator: " ")); \(walkOther) at which the click named another link than the nearest words")
    }

    /// Where the conversation's last link and the pane's lower edge lie now: the screen offset, the pane and the link's last line.
    private func geometryBelowThePane() -> (shift: CGVector, room: CGRect, words: CGRect) {
        let last = link("last-line")
        return (offset(of: last), pane().room, last.words[last.words.count - 1])
    }

    /// A click that WebKit moves onto the composer focuses it and raises the keyboard, which moves the pane and the gap with it. The
    /// harness's own way of putting the keyboard away (`putTheKeyboardAway`: a tap at the screen's left edge, where no text field and no link
    /// lies, and a wait for the keyboard to go) ends the focus; a tap on the pane cannot, since with the keyboard up the page moves under the
    /// finger and the click can land on the text field again (run 7: a press on `p` got its click on the `textarea`). Then the conversation is
    /// scrolled to its end and the gap's geometry is read again, so that the next tap in the gap is a tap in the gap.
    private func settleBelowThePane() -> (shift: CGVector, room: CGRect, words: CGRect) {
        putTheKeyboardAway()
        Thread.sleep(forTimeInterval: 1.5)
        XCTAssertFalse(app.keyboards.firstMatch.exists, "the keyboard stayed up after the composer's focus was ended")
        scrollToEnd()
        return geometryBelowThePane()
    }

    /// A touch in the gap below the pane, next to the link at the pane's lower edge. The page's rule reads the press's point, so a press
    /// there lights nothing and opens nothing, whether the engine gives no click or moves a click onto plain text or the composer inside
    /// the pane (the iOS path that the lines show); a click that the engine moves onto the link opens it once and lights only it, and the
    /// count says how many taps met one. Every tap must reach the page.
    private func tapBelowThePane(named: String) {
        scrollToEnd()
        var place = geometryBelowThePane()
        let composerTop = composer.frame.minY - place.shift.dy
        let gap = composerTop - place.room.maxY
        say("LINKLOOK \(named): the gap below the pane: the pane ends at \(place.room.maxY), the composer's frame starts at \(composerTop), \(gap) px between them; the last link's words \(place.words)")
        XCTAssertGreaterThan(gap, 3, "\(named): no gap below the pane to tap in")
        var counts: [String: Int] = [:]
        var taps = 0
        var reached = 0
        var settled = 0
        for below in [1, 2, 4, 6, 8, 10, 11] as [CGFloat] where below < gap - 1 {
            for column in 0..<3 {
                if app.keyboards.count > 0 {
                    place = settleBelowThePane()
                    settled += 1
                }
                let x = [place.words.minX + 2, place.words.midX, place.words.maxX - 2][column]
                let what = "\(named): the gap, \(Int(below)) px below the pane, column \(column), next to the last link"
                let result = tap(what, at: CGPoint(x: x, y: place.room.maxY + below), shift: place.shift, clickExpected: false)
                taps += 1
                if result.events.contains(where: { $0.type == "pointerdown" }) { reached += 1 }
                counts[LinkTapRules.clickKind(result), default: 0] += 1
                if let problem = LinkTapRules.gapDisagreement(result, paneBottom: place.room.maxY) { XCTFail("\(what): \(problem)") }
            }
        }
        say("LINKLOOK \(named): the gap below the pane: \(taps) taps, \(reached) reached the page; with no click \(counts["none", default: 0]), with a click on plain text \(counts["plain text", default: 0]), on the composer \(counts["composer", default: 0]), on a control \(counts["control", default: 0]); \(counts["link", default: 0]) at which the engine moved the click onto the last link; the composer's focus was ended \(settled) times")
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

    func testTheLookAtTheDefaultTextSize() {
        runLook(size: nil, named: "default size")
    }

    func testTheLookAtTheLargestTextSize() {
        runLook(size: Self.largest, named: "largest size")
    }
}

//
//  Sharing out of the application, through the platform's own sheet.
//
//  A person sharing a transcript, a path or a change set expects the sheet every other application
//  on the device shows, with their own shortcuts in it. Building a second one would be building
//  something worse that nobody asked for.
//

import UIKit

/// Opens the platform's share sheet over whatever is on screen.
struct ShareSurface {
    /// Shares one or more items from a view controller.
    ///
    /// The popover anchor is set on every platform that has one, because an unanchored popover on
    /// an iPad is a crash rather than a layout problem.
    static func present(
        items: [Any],
        from presenter: UIViewController,
        anchor: UIView?
    ) {
        let sheet = UIActivityViewController(activityItems: items, applicationActivities: nil)
        if let popover = sheet.popoverPresentationController {
            if let anchor {
                popover.sourceView = anchor
                popover.sourceRect = anchor.bounds
            } else {
                popover.sourceView = presenter.view
                popover.sourceRect = CGRect(
                    x: presenter.view.bounds.midX,
                    y: presenter.view.bounds.midY,
                    width: 0,
                    height: 0
                )
                popover.permittedArrowDirections = []
            }
        }
        presenter.present(sheet, animated: true)
    }
}

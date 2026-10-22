package to.kala.reach.companion.mobile

/**
 * Where a tap on a notification goes.
 *
 * The notification's intent carries one extra, the screen to open, and the application reads it
 * once and forgets it. It is never a session, a request or anything the payload said: what needs the
 * person is on the screen it names.
 */
object NotificationRoute {
    /** The extra the notification's intent carries. */
    const val EXTRA = "kr_route"

    /** The screen that holds what needs the person. */
    const val ATTENTION = "attention"
}

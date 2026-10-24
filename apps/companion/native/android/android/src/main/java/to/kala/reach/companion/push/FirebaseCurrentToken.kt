package to.kala.reach.companion.push

import com.google.firebase.messaging.FirebaseMessaging
import to.kala.reach.companion.mobile.CurrentToken

/**
 * Asks Firebase for the registration token it holds now.
 *
 * A build with no Firebase configuration has nothing to ask, and answers with no token.
 */
class FirebaseCurrentToken : CurrentToken {
    override fun fetch(done: (String?) -> Unit) {
        try {
            FirebaseMessaging.getInstance().token.addOnCompleteListener { task ->
                done(if (task.isSuccessful) task.result else null)
            }
        } catch (failure: IllegalStateException) {
            done(null)
        }
    }
}

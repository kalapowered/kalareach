/**
 * What the window does when the account signed in changes.
 *
 * What native code keeps for an account stays with the account, so a change of account leaves the
 * application's own state alone. This window's cache of it goes: the rows of the files it sent, the
 * calls still waiting on them, and the files on the composers that came from them. The text on a
 * composer is the person's own typing and stays, and nothing is discarded in the store of kept drafts.
 * It is done only for a host that answers to an organisation, the one the window was last connected
 * to: the host on this computer is not the account's, and once the window is connected to it, or to any
 * host that answers to no organisation, an account change leaves everything of this window alone.
 */

import type { HostPort } from '../host/port'
import type { AccountMark, ConnectedHost } from '../host/stamped'
import type { DraftBook } from '../model/draft-book'
import type { PairedUploads } from '../model/paired-uploads'
import { FILES_OF_EARLIER_SIGN_IN_REMOVED } from '../model/transfer-words'

/**
 * Follows the account, and clears this window's cache of the files when it changes (a sign-out
 * included) and the host last connected, by its environment, answers to an organisation. "Last
 * connected": a sign-out ends the connection too, in whichever order the two are told, and the clear is
 * still for the host that was in use; a connection to any other host replaces it. Answers a function
 * that stops following.
 */
export function followAccountChange({
  port,
  mark,
  host,
  uploads,
  drafts,
  say
}: {
  readonly port: HostPort
  readonly mark: AccountMark
  readonly host: ConnectedHost
  readonly uploads: PairedUploads
  readonly drafts: DraftBook
  readonly say: (text: string, tone?: 'neutral') => void
}): () => void {
  let stopped = false
  const stopAccount = mark.follow(port, () => {
    if (stopped || host.organisation === null) return
    const cleared = uploads.reset() + drafts.dropUploads()
    if (cleared > 0) say(FILES_OF_EARLIER_SIGN_IN_REMOVED, 'neutral')
  })
  return () => {
    stopped = true
    stopAccount()
  }
}

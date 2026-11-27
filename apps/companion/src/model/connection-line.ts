/**
 * What the line that says why there is no connection says, for the desktop's top bar and the phone's.
 *
 * Both lines show the connection's reason in the words native code gave it. While a try to reach the
 * host has run long, native code marks the state instead, and the line says the application is still
 * trying, which is true of the whole try; the reason it held before describes a try that is over.
 * One function holds both sentences, so the two lines can never say different things.
 */

import type { StillReaching } from '../host/port'

/** What the line says when nothing says why there is no connection. */
const NO_REASON = 'Not in contact'

/** The sentence for a slow try, by the host it is for. */
export function stillReachingWords(host: StillReaching): string {
  switch (host) {
    case 'paired':
      return 'this application is still trying to reach the host you chose'
    case 'local':
      return 'this application is still trying to reach the host on this machine'
    default: {
      // A third kind of host is a compile error here, not a line that says nothing.
      const unknown: never = host
      return unknown
    }
  }
}

/** The part of a connection state that decides what the line says when there is no connection. */
export interface LostConnection {
  readonly reason: string | null
  readonly reaching: StillReaching | null
}

/**
 * The line for a connection that is not live: the words, and whether they are the slow try's. A line
 * that shows the slow try's words has no title, since the title would say them twice; every other line
 * keeps the reason whole there.
 */
export function lostLine(connection: LostConnection): { readonly words: string; readonly marked: boolean } {
  if (connection.reaching !== null) {
    return { words: stillReachingWords(connection.reaching), marked: true }
  }
  return { words: connection.reason ?? NO_REASON, marked: false }
}

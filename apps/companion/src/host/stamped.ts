/**
 * The mark of the account the page acts under, and the port that carries it.
 *
 * Native code keeps what an account sends and drafts under the account, and refuses a command whose
 * mark is not the account signed in now, on a host that answers to an organisation. The page learns
 * the mark from the account's own view: the last signed-in view says which account it acts for, and a
 * sign-out says it acts for none.
 */
import type { AccountView } from '../model/account'
import type { HostPort } from './port'

/**
 * The port's commands that act for an account, each with how many arguments it takes before its
 * mark, which every one of them takes last.
 */
const STAMPED = {
  draftCreate: 2,
  attachmentUpload: 2,
  attachmentUploadBytes: 3,
  draftAddAttachment: 2,
  uploadsOpen: 0,
  uploadCancel: 1,
  draftEnd: 2,
  draftSetText: 3,
  composerSubmit: 3,
  composerQueue: 2
} as const

const ROOT = Symbol('the port a stamped port carries the mark for')

/**
 * The port a stamped port stands for, and the port itself when it is not one. A store kept for each
 * port the page talks to is keyed by this, so the stamped port and the port it wraps are one key.
 */
export function rootOf(port: HostPort): HostPort {
  return (port as unknown as Record<symbol, HostPort | undefined>)[ROOT] ?? port
}

/** The account the page last saw signed in. */
export class AccountMark {
  #mark: string | undefined

  /** The mark of the account in force, none while no account is signed in or none has been read. */
  get current(): string | undefined {
    return this.#mark
  }

  /** The same, as a function that keeps its identity, for what is made once for each port. */
  readonly read = (): string | undefined => this.#mark

  /**
   * Follows the account: the listener is registered before the status is read, and a status that
   * returns after an event that already set the mark is dropped, so an older answer never replaces a
   * newer one. Answers a function that stops following.
   */
  follow(port: HostPort): () => void {
    let stopped = false
    let heard = false
    let unlisten: (() => void) | undefined
    void port
      .onAccount((view) => {
        if (stopped) return
        heard = true
        this.#note(view)
      })
      .then((off) => {
        if (stopped) off()
        else unlisten = off
      })
      .catch(() => undefined)
    port.accountStatus().then(
      (view) => {
        if (!stopped && !heard) this.#note(view)
      },
      () => undefined
    )
    return () => {
      stopped = true
      unlisten?.()
    }
  }

  #note(view: AccountView): void {
    switch (view.state) {
      case 'signed_in':
        this.#mark = view.mark
        return
      case 'signed_out':
      case 'ended':
      case 'unavailable':
        this.#mark = undefined
        return
      case 'browser_open':
      case 'finishing':
      case 'unreadable':
        // Nothing is said of who is signed in: the mark stands.
        return
    }
  }
}

/**
 * The port with the account's mark added, last, to each command that acts for an account. The mark
 * is read as the command is made.
 */
export function stampedPort(port: HostPort, mark: () => string | undefined): HostPort {
  const stamped = Object.create(port) as Record<string | symbol, unknown>
  stamped[ROOT] = rootOf(port)
  for (const [name, arity] of Object.entries(STAMPED)) {
    stamped[name] = (...args: unknown[]) => {
      const given = args.slice(0, arity)
      while (given.length < arity) given.push(undefined)
      const method = (port as unknown as Record<string, (...rest: unknown[]) => unknown>)[name]
      return method.call(port, ...given, mark())
    }
  }
  return stamped as unknown as HostPort
}

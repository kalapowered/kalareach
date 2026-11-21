/**
 * The mark of the account the page acts under, and the port that carries it.
 *
 * Native code keeps what an account sends and drafts under the account, and refuses a command whose
 * mark is not the account signed in now, on a host that answers to an organisation. The page learns
 * the mark from the account's own view: the last signed-in view says which account it acts for, and a
 * sign-out says it acts for none.
 */
import type { AccountView } from '../model/account'
import type { ConnectionState, HostPort } from './port'

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

/**
 * What a change of the account is, as the page sees it: the mark of the account signed in, or none
 * after a sign-out. The mark says nothing of who the account is.
 */
export interface AccountChange {
  readonly from: string | null
  readonly to: string | null
}

/** The mark a view stands for, null for no account, and undefined where the view says nothing of who is signed in. */
function keyOf(view: AccountView): string | null | undefined {
  switch (view.state) {
    case 'signed_in':
      return view.mark
    case 'signed_out':
    case 'ended':
    case 'unavailable':
      return null
    case 'browser_open':
    case 'finishing':
    case 'unreadable':
      return undefined
  }
}

/**
 * The account the page last saw signed in, and when that changes.
 *
 * An account event is a hint, not an answer: it moves the mark that commands carry at once, and it
 * makes the page read the account's status. Only that read says the account changed. A publication
 * that is older than the account's state therefore changes nothing: the read that follows it says
 * the account is as it is, and an answer older than a later event or read is dropped.
 */
export class AccountMark {
  #mark: string | undefined
  /** The account the page has settled on: undefined before the first read, null for none. */
  #settled: string | null | undefined

  /** The mark of the account in force, none while no account is signed in or none has been read. */
  get current(): string | undefined {
    return this.#mark
  }

  /** The same, as a function that keeps its identity, for what is made once for each port. */
  readonly read = (): string | undefined => this.#mark

  /**
   * Follows the account: the listener is registered before the status is read, and each event is
   * followed by a read of the status, of which only the newest counts. The first read is the
   * baseline and says nothing changed. Answers a function that stops following.
   */
  follow(port: HostPort, onChange?: (change: AccountChange) => void): () => void {
    let stopped = false
    let asked = 0
    let unlisten: (() => void) | undefined
    const settle = (): void => {
      const ticket = ++asked
      port.accountStatus().then(
        (view) => {
          if (!stopped && ticket === asked) this.#settle(view, onChange)
        },
        () => undefined
      )
    }
    void port
      .onAccount((view) => {
        if (stopped) return
        this.#note(view)
        if (keyOf(view) !== undefined) settle()
      })
      .then((off) => {
        if (stopped) off()
        else unlisten = off
      })
      .catch(() => undefined)
    settle()
    return () => {
      stopped = true
      unlisten?.()
    }
  }

  /** An event moves the mark commands carry; the read that follows it decides whether the account changed. */
  #note(view: AccountView): void {
    const key = keyOf(view)
    if (key !== undefined) this.#mark = key ?? undefined
  }

  #settle(view: AccountView, onChange: ((change: AccountChange) => void) | undefined): void {
    const key = keyOf(view)
    if (key === undefined) return
    this.#mark = key ?? undefined
    const before = this.#settled
    this.#settled = key
    if (before !== undefined && before !== key) onChange?.({ from: before, to: key })
  }
}

/**
 * The host the window was last connected to, when its grant answers to an organisation, by its
 * environment. It is learned from the connection states the page's own screens read and hear through
 * the stamped port: it asks for none of its own. A connection to any other host replaces it, and a
 * connection that ends leaves it as it was, because a sign-out ends the connection too and the two
 * are told in either order.
 */
export class ConnectedHost {
  #organisation: string | null = null

  /** The environment of the organisation host last connected, none when the last host connected answers to none. */
  get organisation(): string | null {
    return this.#organisation
  }

  readonly note = (state: ConnectionState): void => {
    if (state.connected) this.#organisation = state.organisation === true ? state.environment_id : null
  }
}

/**
 * The port with the account's mark added, last, to each command that acts for an account. The mark
 * is read as the command is made.
 */
export function stampedPort(
  port: HostPort,
  mark: () => string | undefined,
  connection?: (state: ConnectionState) => void
): HostPort {
  const stamped = Object.create(port) as Record<string | symbol, unknown>
  stamped[ROOT] = rootOf(port)
  if (connection !== undefined) {
    // The states the screens read and hear are passed to `connection` as they go by: nothing more is asked.
    stamped.connectionState = () => {
      const read = port.connectionState()
      read.then(connection, () => undefined)
      return read
    }
    stamped.onConnection = (listener: (state: ConnectionState) => void) =>
      port.onConnection((state) => {
        connection(state)
        listener(state)
      })
  }
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

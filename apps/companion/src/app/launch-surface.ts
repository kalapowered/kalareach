/**
 * Reading a session's launch surface while a view of it is shown.
 *
 * The editor's state changes with no event to say so, so the view reads the surface again on a
 * cadence while the page is shown, at once when the page is shown again, on a change of connection,
 * when the person asks, and after a press. It never reads twice at once, and it shows an answer only
 * while it belongs to the newest read and the watch that started it is still running.
 *
 * The window between a change and the next read is one cadence long. The guarantee is the press, not
 * this read: a button lit a moment too long quotes a prompt the session then refuses.
 *
 * Output on the screen wakes the read, at most four times a second, so a prompt that draws itself
 * after the view has read is shown by the next read rather than a cadence later. The person's own
 * input darkens every button in the frame it is sent in, and no read that started before the last
 * input settled lights them again: a read that began while an input was in flight says nothing of
 * where the input left the prompt.
 *
 * The host's saved launch commands are read on a cadence of their own, which nothing wakes: output
 * does not change the list, a full list is large, and a deadline that a wake could push back would
 * leave a button for a command removed elsewhere on the page for as long as output streamed. Each
 * of the two reads is numbered apart from the other, so a wake that starts a read of the surface
 * does not discard the answer to the list read on its way.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'

import type { ActionRight, ShellLaunchCommandsListResult } from '@kalareach/protocol'

import { readOnCadence } from './cadence'
import { ask } from '../mobile/model/call'
import {
  failureCode,
  failureMessage,
  watch,
  type HostPort,
  type LaunchCommandsReading,
  type LaunchSurfaceReading
} from '../host/port'

/** How long the view waits after a read has answered before it reads again. */
export const LAUNCH_SURFACE_CADENCE_MS = 2000

/** The most often output wakes the surface's read: at most four a second. */
export const LAUNCH_SURFACE_WAKE_GAP_MS = 250

/** The inputs the person has made through a view, and how many of them the view has answered. */
export interface InputCounts {
  readonly submitted: number
  readonly settled: number
}

/**
 * Why a read failed, in words, or null where it is nothing to tell: a session the host does not
 * know, as one that has ended on this computer, has no surface to draw and none to apologise for.
 */
function unreadWords(failure: unknown): string | null {
  return failureCode(failure) === 'UNKNOWN_SESSION' ? null : failureMessage(failure)
}

/** What a view has read of one launch surface. */
export interface LaunchSurfaceReads {
  /** The newest answer, or null before the first and after a read that failed. */
  readonly reading: LaunchSurfaceReading | null
  /** Why the newest read failed, in words, or null. */
  readonly unread: string | null
  /**
   * Which read `reading` answers. Reads are numbered in the order they start, and the numbers only
   * grow, across every view the hook has read on.
   */
  readonly number: number
  /** The number of the newest read started so far. */
  readonly newest: () => number
  /** Reads now, or as soon as the read on its way has answered. */
  readonly again: () => void
  /**
   * Whether the person's input says `reading` cannot be trusted to light a button: an input is
   * still held, or one was made after the read started. False where the view takes no input.
   */
  readonly dark: boolean
  /**
   * The newest answer to the read of the host's saved launch commands, or null before the first
   * and where there is nothing to read. A host that does not serve the list, and a connection that
   * may not read it, are remembered until the connection changes and clear the answer.
   */
  readonly list: LaunchCommandsReading | null
  /** Why the newest read of the saved launch commands failed, in words, or null. */
  readonly listUnread: string | null
  /** Reads the saved launch commands now, or as soon as the read on its way has answered. */
  readonly listAgain: () => void
  /**
   * The newest list the host answered, as of this moment and before the page has drawn it: a press
   * is checked against what the host said last, not against what was drawn a frame ago. Null
   * before the first answer on this connection.
   */
  readonly listNow: () => ShellLaunchCommandsListResult | null
}

/** What the hook is given besides the read of the surface. */
export interface LaunchSurfaceOptions {
  /** How long it waits after a read has answered before it reads again. */
  readonly cadenceMs?: number
  /** A number that changes each time the view publishes a state: each change wakes the read. */
  readonly wake?: number
  /**
   * The inputs the view has taken, now and as of any moment: a reader that is current before the
   * page has rendered, so a read started in the frame of an input records it.
   */
  readonly inputs?: { readonly now: () => InputCounts; readonly rendered: InputCounts }
  /** Reads the host's saved launch commands, or null where the page does not offer them. */
  readonly readList?: (() => Promise<LaunchCommandsReading>) | null
}

/**
 * Reads with `read` while the caller is shown. An answer belongs to the `read` that asked, which is
 * a view's own: an answer to an earlier view of the same session is never shown under a new one. A
 * null `read` reads nothing, since the view it would read on is not open yet. `retried` counts the
 * person's "Try again", which starts the watch over.
 */
export function useLaunchSurface(
  port: HostPort,
  read: (() => Promise<LaunchSurfaceReading>) | null,
  retried: number,
  options: LaunchSurfaceOptions = {}
): LaunchSurfaceReads {
  const { cadenceMs = LAUNCH_SURFACE_CADENCE_MS, wake, inputs, readList = null } = options
  const [held, setHeld] = useState<{
    readonly read: () => Promise<LaunchSurfaceReading>
    readonly number: number
    readonly reading: LaunchSurfaceReading | null
    readonly unread: string | null
    /**
     * How many inputs the view had submitted when the read started, where it had answered every
     * one of them by then; null where an input was still held, which the read says nothing after.
     */
    readonly cleanAt: number | null
  } | null>(null)
  const [list, setList] = useState<{
    readonly readList: () => Promise<LaunchCommandsReading>
    readonly reading: LaunchCommandsReading | null
    /** Why the newest read of the list failed, in words, or null. */
    readonly unread: string | null
  } | null>(null)
  const again = useRef<() => void>(() => undefined)
  const soon = useRef<() => void>(() => undefined)
  const listAgain = useRef<() => void>(() => undefined)
  // The newest answer and the reader it answers, so that the answer of another reader (another host,
  // environment or connection) is never taken for this one's.
  const newestList = useRef<{
    readonly readList: () => Promise<LaunchCommandsReading>
    readonly list: ShellLaunchCommandsListResult
  } | null>(null)
  const readListNow = useRef(readList)
  useEffect(() => {
    readListNow.current = readList
  })
  const started = useRef(0)
  const inputsNow = useRef(inputs?.now)
  useEffect(() => {
    inputsNow.current = inputs?.now
  })

  useEffect(() => {
    if (read === null) return
    // The surface and the list are numbered by a reader each: output wakes the surface's read four
    // times a second, and a read of one must not outdate the read of the other.
    let readSurface: (() => (() => boolean) | null) | null = null
    let readSaved: (() => (() => boolean) | null) | null = null
    const cadence = readOnCadence(
      () => {
        const current = readSurface?.() ?? null
        if (current === null) return Promise.resolve()
        started.current += 1
        const number = started.current
        const counts = inputsNow.current?.()
        const cleanAt = counts === undefined || counts.submitted === counts.settled ? (counts?.submitted ?? 0) : null
        return ask(read).then(
          (reading) => {
            if (current()) setHeld({ read, number, reading, unread: null, cleanAt })
          },
          (failure: unknown) => {
            if (current()) setHeld({ read, number, reading: null, unread: unreadWords(failure), cleanAt })
          }
        )
      },
      cadenceMs,
      LAUNCH_SURFACE_WAKE_GAP_MS
    )
    // The saved commands have a cadence of their own, which no wake reaches. A host that does not
    // serve them, or a connection that may not read them, is asked no more until the connection
    // changes. `connection` counts those changes: an answer to a read that began on an earlier
    // connection says nothing of this one, so it neither shows a list nor remembers a refusal.
    let remembered = false
    let connection = 0
    newestList.current = null
    const listCadence =
      readList === null
        ? null
        : readOnCadence(() => {
            const current = readSaved?.() ?? null
            if (current === null || remembered) return Promise.resolve()
            const asked = connection
            return ask(readList).then(
              (reading) => {
                if (!current() || asked !== connection) return
                if (reading.state === 'served') {
                  newestList.current = { readList, list: reading.list }
                  setList({ readList, reading, unread: null })
                } else {
                  // The host holds no list this connection may use: what was shown is cleared, so
                  // no saved command stays pressable.
                  remembered = true
                  newestList.current = null
                  setList(null)
                }
              },
              (failure: unknown) => {
                // The list as it was stays, and the failure is told beside it.
                if (current()) {
                  setList((was) => ({
                    readList,
                    reading: was?.readList === readList ? was.reading : null,
                    unread: failureMessage(failure)
                  }))
                }
              }
            )
          }, cadenceMs)
    const watched = watch(
      [
        port.onConnection((state) => {
          connection += 1
          remembered = false
          if (state.connected) {
            cadence.now()
            listCadence?.now()
          }
        })
      ],
      () => {
        cadence.now()
        listCadence?.now()
      },
      (failure) => {
        setHeld({
          read,
          number: started.current,
          reading: null,
          unread: failureMessage(failure),
          cleanAt: null
        })
      }
    )
    readSurface = watched.reader()
    readSaved = watched.reader()
    again.current = cadence.now
    soon.current = cadence.soon
    listAgain.current = () => {
      listCadence?.now()
    }
    return () => {
      cadence.stop()
      listCadence?.stop()
      watched.stop()
      again.current = () => undefined
      soon.current = () => undefined
      listAgain.current = () => undefined
    }
  }, [port, read, readList, retried, cadenceMs])

  // Each state the view publishes asks for a read of the surface, and no more often than the wake
  // gap allows.
  useEffect(() => {
    soon.current()
  }, [wake])

  const refresh = useCallback(() => {
    again.current()
  }, [])
  const refreshList = useCallback(() => {
    listAgain.current()
  }, [])
  const newest = useCallback(() => started.current, [])
  const listNow = useCallback(
    () =>
      newestList.current !== null && newestList.current.readList === readListNow.current
        ? newestList.current.list
        : null,
    []
  )

  const own = read !== null && held?.read === read ? held : null
  const ownList = readList !== null && list?.readList === readList ? list : null
  // Dark while an input is held, and until a read that started after the last input has answered.
  const dark =
    inputs !== undefined &&
    (inputs.rendered.submitted !== inputs.rendered.settled ||
      own === null ||
      own.cleanAt !== inputs.rendered.submitted)
  return {
    reading: own?.reading ?? null,
    unread: own?.unread ?? null,
    number: own?.number ?? 0,
    newest,
    again: refresh,
    dark,
    list: ownList?.reading ?? null,
    listUnread: ownList?.unread ?? null,
    listAgain: refreshList,
    listNow
  }
}

/**
 * The read of the host's saved launch commands for a connection that holds `rights`, or null where
 * it may not read them: a connection without `host.manage` is refused the list, so it never asks.
 * The read is the same function for as long as the answer to that question is the same, so a watch
 * that depends on it is not started over by a change of the rights' array.
 */
export function useSavedCommandsRead(
  port: HostPort,
  rights: readonly ActionRight[] | null
): (() => Promise<LaunchCommandsReading>) | null {
  const mayRead = rights?.includes('host.manage') === true
  return useMemo(() => (mayRead ? () => port.launchCommands() : null), [port, mayRead])
}

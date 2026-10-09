/**
 * How a screen reaches the drafts: the book the window holds, read the way React reads a store.
 *
 * The book itself is in `model/draft-book.ts`, and one is made for the window by the application's
 * provider, above both layouts, so closing a tab or moving between the conversation and the terminal
 * forgets nothing. This file is what a screen calls.
 */

import { useCallback, useEffect, useSyncExternalStore } from 'react'

import { observeTargets } from '../mobile/model/rebind'
import { rebindAll } from '../mobile/model/lifecycle'
import type { BookSnapshot, DraftBook } from '../model/draft-book'
import type { Draft } from '../model/drafts'
import { useApp } from './state'

/** What the book holds, and the page re-renders when it changes. */
export function useBook(): BookSnapshot {
  const { drafts } = useApp()
  return useSyncExternalStore(drafts.subscribe, drafts.snapshot)
}

/** The window's book, for a screen that changes drafts. */
export function useDraftBook(): DraftBook {
  return useApp().drafts
}

/**
 * One session's draft, and the means to change it.
 *
 * `ready` is false until the store has been read: a composer waits for it, so that what a person
 * types is never typed over what was kept.
 */
export function useSessionDraft(sessionId: string): {
  readonly draft: Draft
  readonly ready: boolean
  readonly change: (change: (draft: Draft) => Draft) => void
} {
  const { drafts } = useApp()
  const draft = useSyncExternalStore(drafts.subscribe, () => drafts.draft(sessionId))
  const status = useSyncExternalStore(drafts.subscribe, () => drafts.snapshot().status)
  const change = useCallback(
    (next: (held: Draft) => Draft) => {
      drafts.update(sessionId, next)
    },
    [drafts, sessionId]
  )
  return { draft, ready: status !== 'opening', change }
}

/**
 * Binds the drafts a break detached to their conversations again, once the host is in contact.
 *
 * A suspension, a network change and a restart each take every draft's association away and leave
 * its text. Nothing about the connection coming back puts the association back, so this does: each
 * time the shell is in contact with detached drafts in hand, whether the contact is new or the
 * application only came back to the front over a connection that never dropped, it asks the host
 * where each draft's conversation stands and offers each draft its rebind. The drafts of sessions
 * that are not on screen are read for as well as the one that is. A read that fails leaves its
 * drafts detached until the next time, and nothing here sends anything.
 *
 * `resumption` counts the times the application came back, and says how many have happened now, for
 * a layout that has such events; the desktop window has none.
 */
export function useRebind(
  connected: boolean,
  resumption: { readonly resumed: number; readonly resumedNow: () => number } = NO_RESUMPTION
): void {
  const { port, drafts: book } = useApp()
  const { drafts: held } = useBook()
  const { resumed, resumedNow } = resumption
  const waiting = held.some((draft) => draft.state === 'detached')

  useEffect(() => {
    if (!connected || !waiting) return
    let current = true
    const asked = resumedNow()
    observeTargets(port, book.snapshot().drafts)
      .then((observed) => {
        // An answer read before the application came back again is about the drafts as they were,
        // and says nothing of what the break since then took away.
        if (!current || resumedNow() !== asked || observed.length === 0) return
        book.setDrafts((now) => rebindAll(now, observed))
      })
      .catch(() => undefined)
    return () => {
      current = false
    }
    // `resumed` is here to run this again when the application comes back over a connection that
    // never dropped, which changes neither `connected` nor, once the drafts detach, `waiting`.
  }, [port, book, connected, waiting, resumed, resumedNow])
}

/** A window that is never told it came back. */
const NO_RESUMPTION = { resumed: 0, resumedNow: () => 0 } as const

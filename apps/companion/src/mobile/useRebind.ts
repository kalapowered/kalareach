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
 */

import { useEffect, useRef } from 'react'

import { useApp } from '../app/state'
import { observeTargets } from './model/rebind'
import { rebindAll } from './model/lifecycle'
import type { Lifecycle } from './useLifecycle'

/** Rebinds `lifecycle`'s detached drafts whenever `connected` and there is something to rebind. */
export function useRebind(lifecycle: Lifecycle, connected: boolean): void {
  const { port } = useApp()
  const { setDrafts, resumed } = lifecycle
  const held = lifecycle.state.drafts
  const drafts = useRef(held)
  useEffect(() => {
    drafts.current = held
  })
  const waiting = held.some((draft) => draft.state === 'detached')

  useEffect(() => {
    if (!connected || !waiting) return
    let current = true
    observeTargets(port, drafts.current)
      .then((observed) => {
        if (!current || observed.length === 0) return
        setDrafts((held) => rebindAll(held, observed))
      })
      .catch(() => undefined)
    return () => {
      current = false
    }
    // `resumed` is here to run this again when the application comes back over a connection that
    // never dropped, which changes neither `connected` nor, once the drafts detach, `waiting`.
  }, [port, connected, waiting, resumed, setDrafts])
}

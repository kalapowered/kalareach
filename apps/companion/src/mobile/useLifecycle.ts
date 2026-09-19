/**
 * The lifecycle the phone actually has, wired to the recovery model.
 *
 * A phone tells a page three things through one event each: the application went to the
 * background or came back (`visibilitychange`), the page is about to be taken away
 * (`pagehide`), and the network changed underneath it (`online`, `offline`). This turns those
 * into the four resumptions the recovery model knows, and writes what must survive before the
 * platform has a chance to take the process away.
 *
 * A cold start is the case with no evidence: nothing in memory, a record on disk. It is told from
 * a resume by a marker written at the first render of a run.
 */

import { useCallback, useEffect, useState } from 'react'

import type { Draft } from '../model/drafts'
import type { Submission } from '../model/receipts'
import {
  EMPTY_DURABLE_STATE,
  onResume,
  persist,
  recoveryBanner,
  restore,
  summarise,
  type DurableState,
  type RecoveryBanner,
  type Resumption
} from './model/lifecycle'
import { deviceStore, memoryStore, type DurableStore } from './model/store'

/**
 * The key a run writes to say it has started.
 *
 * It says a previous run existed, and nothing more. A phone is under no obligation to tell an
 * application it is about to be taken away, so what ended the previous run is not knowable from
 * here and this never claims to know it.
 */
const RUN_MARKER = 'kr.mobile.run'

/** What the hook gives a screen. */
export interface Lifecycle {
  readonly state: DurableState
  /** What the last resumption was, for the banner and for the tests. */
  readonly resumption: Resumption
  /** The banner to show, or null. */
  readonly banner: RecoveryBanner | null
  readonly setDrafts: (change: (drafts: readonly Draft[]) => readonly Draft[]) => void
  readonly setSubmissions: (
    change: (submissions: readonly Submission[]) => readonly Submission[]
  ) => void
  /** Declares a resumption, which is what the platform events call and a test calls directly. */
  readonly resume: (resumption: Resumption) => void
  /** Dismisses the banner without changing anything it described. */
  readonly acknowledge: () => void
  /**
   * True when this device refused to keep what was written.
   *
   * The draft is still here and still editable; what it will not do is survive the application
   * being taken away. A person deserves to know that before they rely on it.
   */
  readonly durable: boolean
}

/** Holds the durable state across a suspension, a termination, a network change and a restart. */
export function useLifecycle(storage?: Storage | null): Lifecycle {
  // One store per run, created once. A store built during render would be a new store on every
  // render, and the records the last one held would go with it.
  const [store] = useState<DurableStore>(() =>
    storage === undefined
      ? deviceStore(typeof localStorage === 'undefined' ? null : localStorage)
      : storage === null
        ? memoryStore()
        : deviceStore(storage)
  )

  const [resumption, setResumption] = useState<Resumption>(() =>
    store.read(RUN_MARKER) === null ? 'cold_start' : 'restarted'
  )
  const [state, setState] = useState<DurableState>(() => {
    const restored = restore(store)
    return restored.drafts.length === 0 && restored.submissions.length === 0
      ? EMPTY_DURABLE_STATE
      : restored
  })
  const [dismissed, setDismissed] = useState(false)
  const [durable, setDurable] = useState(true)

  // The marker says a run has started here. A later run finding it knows there was one before,
  // which is all it can know: nothing on a phone is told that it is about to be terminated.
  useEffect(() => {
    store.write(RUN_MARKER, '1')
  }, [store])

  // Every change is written as it happens, because a phone is not obliged to tell an application
  // it is about to be terminated. These two are a second chance rather than the only one.
  useEffect(() => {
    const write = () => {
      setDurable(persist(store, state))
    }
    const hidden = () => {
      if (document.visibilityState === 'hidden') write()
    }
    window.addEventListener('pagehide', write)
    document.addEventListener('visibilitychange', hidden)
    return () => {
      window.removeEventListener('pagehide', write)
      document.removeEventListener('visibilitychange', hidden)
    }
  }, [store, state])

  const resume = useCallback(
    (next: Resumption) => {
      setResumption(next)
      setDismissed(false)
      setState((current) => onResume(next, current, store))
    },
    [store]
  )

  useEffect(() => {
    const visible = () => {
      if (document.visibilityState === 'visible') resume('suspended')
    }
    const network = () => {
      resume('network_changed')
    }
    document.addEventListener('visibilitychange', visible)
    window.addEventListener('online', network)
    window.addEventListener('offline', network)
    return () => {
      document.removeEventListener('visibilitychange', visible)
      window.removeEventListener('online', network)
      window.removeEventListener('offline', network)
    }
  }, [resume])

  const setDrafts = useCallback(
    (change: (drafts: readonly Draft[]) => readonly Draft[]) => {
      setState((current) => {
        const next = { ...current, drafts: change(current.drafts) }
        // Written straight away rather than on the way out as well: a draft a person typed one
        // keystroke before the system reclaimed the process is a draft that has to be there.
        setDurable(persist(store, next))
        return next
      })
    },
    [store]
  )

  const setSubmissions = useCallback(
    (change: (submissions: readonly Submission[]) => readonly Submission[]) => {
      setState((current) => {
        const next = { ...current, submissions: change(current.submissions) }
        setDurable(persist(store, next))
        return next
      })
    },
    [store]
  )

  const banner = dismissed ? null : recoveryBanner(resumption, summarise(state))

  return {
    state,
    resumption,
    banner,
    setDrafts,
    setSubmissions,
    resume,
    acknowledge: () => {
      setDismissed(true)
    },
    durable
  }
}

/**
 * How much of the screen the software keyboard covers, as a CSS length on the document.
 *
 * The visual viewport shrinks when the keyboard comes up, and the difference between it and the
 * layout viewport is exactly what is hidden. Measuring it is the only way to keep a composer above
 * the keyboard on both platforms; a guessed height is wrong on every device it was not measured on.
 */
export function useKeyboardInset(): void {
  useEffect(() => {
    const viewport = window.visualViewport
    if (!viewport) return
    const measure = () => {
      const covered = Math.max(0, window.innerHeight - viewport.height - viewport.offsetTop)
      document.documentElement.style.setProperty('--keyboard', `${Math.round(covered)}px`)
    }
    measure()
    viewport.addEventListener('resize', measure)
    viewport.addEventListener('scroll', measure)
    return () => {
      viewport.removeEventListener('resize', measure)
      viewport.removeEventListener('scroll', measure)
      document.documentElement.style.removeProperty('--keyboard')
    }
  }, [])
}

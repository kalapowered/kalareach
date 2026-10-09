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

import { useCallback, useEffect, useRef, useState } from 'react'

import { useBook } from '../app/drafts'
import { useApp } from '../app/state'
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
  /**
   * How many resumptions this run has declared. A suspension that follows another is the same kind
   * of resumption, so what it was cannot say that one happened; this can.
   */
  readonly resumed: number
  /**
   * The same count, read at the moment it is asked. The number above is the page's rendering of the
   * count, which trails a resumption by a render; this does not, so an answer to a question asked
   * before a resumption can tell that one has happened since.
   */
  readonly resumedNow: () => number
  /** The banner to show, or null. */
  readonly banner: RecoveryBanner | null
  readonly setSubmissions: (
    change: (submissions: readonly Submission[]) => readonly Submission[]
  ) => void
  /** Declares a resumption, which is what the platform events call and a test calls directly. */
  readonly resume: (resumption: Resumption) => void
  /** Dismisses the banner without changing anything it described. */
  readonly acknowledge: () => void
  /**
   * True when this device refused to keep the unresolved submissions.
   *
   * What it will not do is survive the application being taken away. A person deserves to know that
   * before they rely on it. The drafts say the same of themselves, through the window's book.
   */
  readonly durable: boolean
}

/** Holds the durable state across a suspension, a termination, a network change and a restart. */
export function useLifecycle(storage?: Storage | null): Lifecycle {
  const { drafts: book } = useApp()
  const { drafts } = useBook()
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
    return restored.submissions.length === 0 ? EMPTY_DURABLE_STATE : restored
  })
  const [resumed, setResumed] = useState(0)
  const resumptions = useRef(0)
  const resumedNow = useCallback(() => resumptions.current, [])
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
      resumptions.current += 1
      setResumption(next)
      setResumed((count) => count + 1)
      setDismissed(false)
      setState((current) => onResume(next, current, store))
      // Whatever brought the application back took every draft's association with it.
      book.connectionLost()
    },
    [store, book]
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

  const banner = dismissed ? null : recoveryBanner(resumption, summarise(state, drafts))

  return {
    state,
    resumption,
    resumed,
    resumedNow,
    banner,
    setSubmissions,
    resume,
    acknowledge: () => {
      setDismissed(true)
    },
    durable
  }
}

/**
 * How much of the height a software keyboard takes, and how far the platform has panned the page,
 * both as CSS lengths on the document.
 *
 * The visual viewport shrinks when the keyboard comes up, and the layout viewport keeps its height:
 * the difference is what the keyboard takes, measured, since a guessed height is wrong on every
 * device it was not measured on. Where the platform then pans the page to keep a focused field in
 * sight, the visual viewport is scrolled down inside the layout viewport by its `offsetTop`, and
 * whatever of the shell is above that is above the screen; a platform may also shrink the layout
 * viewport to what is visible while it pans, so the height the page has without a keyboard is the
 * larger of the layout viewport's and the visible height and the pan together. The shell goes with
 * the visual viewport (`--pan`), so what it holds stays where the person sees it, and the keyboard
 * is at its foot whether or not the page was panned. While the page is zoomed in by a pinch, neither
 * is measured.
 */
export function useKeyboardInset(): void {
  useEffect(() => {
    const viewport = window.visualViewport
    if (!viewport) return
    const root = document.documentElement
    const measure = () => {
      // A pinch zoom shrinks the visual viewport and moves it about inside the layout viewport as a
      // keyboard and the platform's pan do, but it is neither: the shell stays where it is, so the
      // whole of it can be reached, and nothing is taken for a keyboard.
      if (Math.abs(viewport.scale - 1) > 0.01) {
        root.style.setProperty('--keyboard', '0px')
        root.style.setProperty('--pan', '0px')
        return
      }
      // The height the page has when no keyboard is up: the layout viewport's, which the platform
      // may shrink to what is visible while it pans to a field, and then the visible height and the
      // pan add up to it.
      const panned = Math.max(0, viewport.offsetTop)
      const whole = Math.max(window.innerHeight, viewport.height + panned)
      const taken = Math.max(0, whole - viewport.height)
      root.style.setProperty('--keyboard', `${Math.round(taken)}px`)
      root.style.setProperty('--pan', `${Math.round(panned)}px`)
    }
    measure()
    viewport.addEventListener('resize', measure)
    viewport.addEventListener('scroll', measure)
    return () => {
      viewport.removeEventListener('resize', measure)
      viewport.removeEventListener('scroll', measure)
      root.style.removeProperty('--keyboard')
      root.style.removeProperty('--pan')
    }
  }, [])
}

/**
 * Session descriptions at setup, as the host reports them.
 *
 * Section 22 offers descriptions during host setup with the asset's size visible, a way to cancel
 * the fetch, a way to turn the feature off, and no account behind any of it. Every figure and every
 * state on the card is the host's own answer: the size is the size of the file the host would
 * fetch, the progress is bytes that have arrived, and a host that offers nothing says why in its
 * own words. The card asks the host to start or stop a fetch and to change the two settings, and
 * names nothing else: it cannot choose a model or an address to fetch from.
 */

import { useCallback, useEffect, useRef, useState } from 'react'

import type { DescriptionSetup } from '@kalareach/protocol'

import { failureMessage, type HostPort } from '../host/port'
import { readableBytes } from './host'

/** How often a fetch that is running is asked about, in milliseconds. */
export const PROGRESS_EVERY_MS = 1000

/** What the card calls the state of descriptions on this host. */
export type DescriptionStatus =
  | 'not_offered'
  | 'downloading'
  | 'failed'
  | 'on'
  | 'ready_off'
  | 'not_downloaded'

/** The state of descriptions as one word, from what the host says. */
export function statusOf(setup: DescriptionSetup): DescriptionStatus {
  if (!setup.offered) return 'not_offered'
  if (setup.download === 'running') return 'downloading'
  if (setup.download === 'failed') return 'failed'
  if (setup.download === 'verified') return setup.enabled ? 'on' : 'ready_off'
  return 'not_downloaded'
}

/** The words for each state. */
export const STATUS_LABEL: Readonly<Record<DescriptionStatus, string>> = {
  not_offered: 'Not offered here',
  downloading: 'Downloading',
  failed: 'Download failed',
  on: 'On',
  ready_off: 'Downloaded, off',
  not_downloaded: 'Not downloaded'
}

/** How much of the file has arrived, as a fraction, or null where the host gave no size. */
export function fetchedFraction(setup: DescriptionSetup): number | null {
  const total = Number(setup.asset_bytes)
  const fetched = Number(setup.fetched_bytes)
  if (!Number.isFinite(total) || !Number.isFinite(fetched) || total <= 0) return null
  return Math.min(1, Math.max(0, fetched / total))
}

/** The size and the sources, in one sentence, before anything is fetched. */
export function costSentence(setup: DescriptionSetup): string {
  const size = `${readableBytes(Number(setup.asset_bytes))} to download`
  const from =
    setup.sources.length > 0 ? `, from ${setup.sources.join(' and ')}` : ''
  return `${size}${from}.`
}

/** What the card holds: the host's last answer, and what is being done about it. */
export interface DescriptionSetupState {
  /** The host's last answer, or null before one has arrived or while the host is not answering. */
  readonly setup: DescriptionSetup | null
  /** Why the last read was refused, in words. */
  readonly failure: string | null
  /** Why the last write was refused, in words, until the next one is made. */
  readonly refusal: string | null
  /** Reads the setup again, as a person asks after the host did not answer. */
  readonly reload: () => void
  /** Turns descriptions on or off. */
  readonly enable: (next: boolean) => void
  /** Allows or forbids inference on battery power. */
  readonly onBattery: (next: boolean) => void
  /** Asks the host to start the fetch, or to stop the one that is running. */
  readonly download: (action: 'start' | 'cancel') => void
}

/**
 * Reads the host's description setup, writes the two settings and the fetch, and follows a fetch
 * that is running until it ends.
 *
 * Every write is followed by a read, because what a person is told is the host's answer and not the
 * request that was made. A read that answers after a newer one began, or after the screen has gone,
 * changes nothing. A write that is made while another is waiting for the host is ignored: the
 * second press would be made from a card that does not yet show the first. No control is disabled
 * while the host answers, so a person on the keyboard or with a screen reader is never moved off
 * the control they pressed or are on.
 */
export function useDescriptionSetup(port: HostPort): DescriptionSetupState {
  const [setup, setSetup] = useState<DescriptionSetup | null>(null)
  const [failure, setFailure] = useState<string | null>(null)
  const [refusal, setRefusal] = useState<string | null>(null)
  const newest = useRef(0)
  const mounted = useRef(true)
  const writing = useRef(false)

  useEffect(() => {
    mounted.current = true
    return () => {
      mounted.current = false
    }
  }, [])

  /** Reads the setup, showing the answer of the newest read only. */
  const read = useCallback((): Promise<void> => {
    newest.current += 1
    const mine = newest.current
    return port
      .descriptionSetup()
      .then((answer) => {
        if (!mounted.current || mine !== newest.current) return
        setSetup(answer)
        setFailure(null)
      })
      .catch((error: unknown) => {
        if (!mounted.current || mine !== newest.current) return
        setSetup(null)
        setFailure(failureMessage(error))
      })
  }, [port])

  // The first read, begun as the card opens.
  useEffect(() => {
    void read()
  }, [read])

  // A read a person asked for shows that it is being made: the words for a failure are the same
  // each time, and are announced again only if they went away first.
  const reload = useCallback(() => {
    setFailure(null)
    void read()
  }, [read])

  const write = useCallback(
    (ask: () => Promise<unknown>) => {
      if (writing.current) return
      writing.current = true
      setRefusal(null)
      void ask()
        .catch((error: unknown) => {
          if (mounted.current) setRefusal(failureMessage(error))
        })
        .then(read)
        .finally(() => {
          writing.current = false
        })
    },
    [read]
  )

  const enable = useCallback(
    (next: boolean) => {
      write(() => port.descriptionConfigure({ enabled: next, on_battery: null }))
    },
    [port, write]
  )
  const onBattery = useCallback(
    (next: boolean) => {
      write(() => port.descriptionConfigure({ enabled: null, on_battery: next }))
    },
    [port, write]
  )
  const download = useCallback(
    (action: 'start' | 'cancel') => {
      write(() => port.descriptionDownload({ action }))
    },
    [port, write]
  )

  // A fetch that is running is asked about until it ends.
  const running = setup?.download === 'running'
  useEffect(() => {
    if (!running) return undefined
    const timer = setTimeout(() => {
      void read()
    }, PROGRESS_EVERY_MS)
    return () => {
      clearTimeout(timer)
    }
  }, [running, setup, read])

  return { setup, failure, refusal, reload, enable, onBattery, download }
}

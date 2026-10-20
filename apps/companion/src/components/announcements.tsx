/**
 * The words of the banners in the page, said to a screen reader.
 *
 * A screen reader says what a live region changes to, and not what one arrives holding, so a banner
 * that comes with its words cannot carry its own region: the region and the words reach the page
 * together, and nothing changes. One region is in the page for as long as the application is, and
 * each banner puts its words into it. The words are for a screen reader alone: what a person reads
 * is the banner.
 */

import { useEffect, useId, useSyncExternalStore, type ReactNode } from 'react'

/** The words each banner in the page has said, by banner, in the order the banners came. */
const said = new Map<string, string>()
const listeners = new Set<() => void>()
let heard: readonly (readonly [string, string])[] = []

function publish(): void {
  heard = Array.from(said)
  for (const listener of listeners) listener()
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener)
  return () => {
    listeners.delete(listener)
  }
}

/**
 * Says `words` to a screen reader for as long as the caller is in the page, and says them again
 * when they change. Nothing is said when no region has been drawn: a page without one is a page
 * with nobody listening.
 */
export function useAnnounced(words: string): void {
  const key = useId()
  useEffect(() => {
    said.set(key, words)
    publish()
  }, [key, words])
  useEffect(
    () => () => {
      said.delete(key)
      publish()
    },
    [key]
  )
}

/**
 * The live region the banners' words go into. It is drawn once, with the application, and holds one
 * paragraph for each banner in the page: a banner that comes adds one, and a banner whose words
 * change changes its own.
 */
export function Announcements(): ReactNode {
  const items = useSyncExternalStore(subscribe, () => heard)
  return (
    <div
      className="visually-hidden"
      aria-live="polite"
      aria-relevant="additions text"
      data-announcements=""
    >
      {items.map(([key, words]) => (
        <p key={key}>{words}</p>
      ))}
    </div>
  )
}

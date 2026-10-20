/**
 * What decides how long a passing message stays, and where it is drawn.
 *
 * A message is drawn over the screen it was said on. While a surface that holds the focus is open
 * (a sheet), the message is drawn inside it, where the keyboard and a screen reader stay: a modal
 * surface is the whole of the screen to both, and a message outside it can be neither reached nor
 * dismissed from them. The surface offers a place for it, and the message takes the newest place on
 * offer. The place comes with the surface's own announcements, since a screen reader inside a modal
 * surface hears only the live region that is in it.
 */

import { useSyncExternalStore } from 'react'

import type { Announcer } from './announcements'

/**
 * The time a message stays once nothing holds it, in milliseconds.
 *
 * A floor, so that a short message is not gone before it is seen, and a longer one where the message
 * offers something to do, which takes a decision as well as a reading. A time for each word, so that
 * a long message is read to its end whatever its box shows of it; a word counts for as much as each
 * six letters of it, since a file name or a path is read in parts. And a ceiling, so that no message
 * stays on until it is put away. A pointer resting on the message or focus inside it holds it, and
 * it goes this long after both have left.
 */
export const TOAST_FLOOR_MS = 4200
export const TOAST_FLOOR_WITH_ACTION_MS = 8000
export const TOAST_WORD_MS = 300
export const TOAST_CEILING_MS = 20_000
/** The letters that count as one word where a word has no break in it. */
export const TOAST_LETTERS_PER_WORD = 6

/** How long `text` stays, with an action of its own or without. */
export function toastDwell(text: string, hasAction: boolean): number {
  const spoken = text.split(/\s+/).filter((word) => word !== '').length
  const read = Math.max(spoken, Math.ceil(text.trim().length / TOAST_LETTERS_PER_WORD))
  const floor = hasAction ? TOAST_FLOOR_WITH_ACTION_MS : TOAST_FLOOR_MS
  return Math.min(TOAST_CEILING_MS, Math.max(floor, read * TOAST_WORD_MS))
}

/** A place for a message, and the announcements of the surface that keeps it. */
export interface ToastDock {
  readonly element: HTMLElement
  readonly announcer: Announcer
}

/** The places on offer, oldest first: one for each open surface that has one. */
let docks: readonly ToastDock[] = []
const watchers = new Set<() => void>()

function publish(): void {
  for (const watcher of watchers) watcher()
}

/** Offers `element` as a place for a message, until the returned function takes it back. */
export function offerToastDock(element: HTMLElement, announcer: Announcer): () => void {
  const dock: ToastDock = { element, announcer }
  docks = [...docks, dock]
  publish()
  return () => {
    docks = docks.filter((each) => each !== dock)
    publish()
  }
}

function subscribe(watcher: () => void): () => void {
  watchers.add(watcher)
  return () => {
    watchers.delete(watcher)
  }
}

/** The place the newest open surface offers, or null where none is open. */
export function useToastDock(): ToastDock | null {
  return useSyncExternalStore(subscribe, () => docks.at(-1) ?? null)
}

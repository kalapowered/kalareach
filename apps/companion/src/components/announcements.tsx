/**
 * The words of the banners on a screen, said to a screen reader.
 *
 * A screen reader says what a live region changes to, and not what one arrives holding, so a banner
 * that comes with its words cannot carry its own region: the region and the words reach the page
 * together, and nothing changes. A scope draws one region, with what it holds, before any banner in
 * it, and each banner puts its words into the nearest one. The application is a scope, and so is
 * each dialog that holds a banner, because a screen reader inside a modal dialog does not reach a
 * region outside it. The words are for a screen reader alone: what a person reads is the banner.
 *
 * A banner that is already on a screen when the screen first appears arrives with its region, and
 * says nothing: a screen reader meets it as the person moves through the screen, as it meets the
 * rest of what is there.
 *
 * A message in passing says its words the same way. Unlike a banner it can be drawn in another
 * place while it is up (inside a dialog that opens over it), and its words are said where the
 * person is when they are new and not again when only the message moves.
 */

import {
  createContext,
  useContext,
  useEffect,
  useId,
  useRef,
  useState,
  useSyncExternalStore,
  type ReactNode
} from 'react'

/** What a scope's region holds for one speaker: its words, and which time they were said. */
type Speech = readonly [words: string, occasion: number]

/** The words each speaker in a scope has said, by speaker, in the order the speakers came. */
export class Announcer {
  readonly #words = new Map<string, Speech>()
  readonly #listeners = new Set<() => void>()
  #heard: readonly (readonly [string, Speech])[] = []

  readonly subscribe = (listener: () => void): (() => void) => {
    this.#listeners.add(listener)
    return () => {
      this.#listeners.delete(listener)
    }
  }

  readonly heard = (): readonly (readonly [string, Speech])[] => this.#heard

  /** Puts `words` into the region as the paragraph of `speaker`; a new `occasion` is a new paragraph. */
  say(speaker: string, words: string, occasion: number): void {
    this.#words.set(speaker, [words, occasion])
    this.#publish()
  }

  withdraw(speaker: string): void {
    this.#words.delete(speaker)
    this.#publish()
  }

  #publish(): void {
    this.#heard = Array.from(this.#words)
    for (const listener of this.#listeners) listener()
  }
}

const Scope = createContext<Announcer | null>(null)

/** The nearest scope, or null outside every one. */
export function useAnnouncer(): Announcer | null {
  return useContext(Scope)
}

/**
 * Says `words` to a screen reader for as long as the caller is on the screen, and says them again
 * when they change. Nothing is said outside every scope: a page without a region is a page with
 * nobody listening.
 */
export function useAnnounced(words: string): void {
  useAnnouncedIn(useContext(Scope), words, 0)
}

/**
 * Says `words` in the region of `place`, for as long as the caller is on the screen.
 *
 * The caller has one paragraph, in the region where its words were last said. A new `occasion` says
 * the words anew even when they read the same. When only `place` changes, as it does for a message
 * that is drawn in a dialog that opens over it, nothing is said: the person has heard the words,
 * and the paragraph stays where it is until the caller goes or has new words. New words are said in
 * the place the caller is in then, and the paragraph left behind is taken away, which a screen
 * reader does not say.
 */
export function useAnnouncedIn(place: Announcer | null, words: string, occasion: number): void {
  const speaker = useId()
  const said = useRef<{ place: Announcer; words: string; occasion: number } | null>(null)
  useEffect(() => {
    if (place === null) return
    const before = said.current
    if (before?.words === words && before.occasion === occasion) return
    if (before !== null && before.place !== place) before.place.withdraw(speaker)
    place.say(speaker, words, occasion)
    said.current = { place, words, occasion }
  }, [place, speaker, words, occasion])
  useEffect(
    () => () => {
      said.current?.place.withdraw(speaker)
      said.current = null
    },
    [speaker]
  )
}

/**
 * A scope for the banners in `children`: the live region their words go into is drawn with it, as
 * its last child, and holds one paragraph for each speaker in the scope. A speaker that comes adds
 * one, and one whose words change changes its own.
 */
export function AnnouncementScope({ children }: { readonly children: ReactNode }): ReactNode {
  const [announcer] = useState(() => new Announcer())
  const items = useSyncExternalStore(announcer.subscribe, announcer.heard)
  return (
    <Scope.Provider value={announcer}>
      {children}
      {/* Set at the corner of its containing block: left where it would fall, an absolutely
          placed region at the end of a scrolling dialog would make the dialog scroll to it. */}
      <div
        className="visually-hidden"
        style={{ insetBlockStart: 0, insetInlineStart: 0 }}
        aria-live="polite"
        aria-relevant="additions text"
        data-announcements=""
      >
        {items.map(([speaker, [words, occasion]]) => (
          <p key={`${speaker}:${String(occasion)}`}>{words}</p>
        ))}
      </div>
    </Scope.Provider>
  )
}

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
 */

import {
  createContext,
  useContext,
  useEffect,
  useId,
  useState,
  useSyncExternalStore,
  type ReactNode
} from 'react'

/** The words each banner in a scope has said, by banner, in the order the banners came. */
class Said {
  readonly #words = new Map<string, string>()
  readonly #listeners = new Set<() => void>()
  #heard: readonly (readonly [string, string])[] = []

  readonly subscribe = (listener: () => void): (() => void) => {
    this.#listeners.add(listener)
    return () => {
      this.#listeners.delete(listener)
    }
  }

  readonly heard = (): readonly (readonly [string, string])[] => this.#heard

  say(banner: string, words: string): void {
    this.#words.set(banner, words)
    this.#publish()
  }

  withdraw(banner: string): void {
    this.#words.delete(banner)
    this.#publish()
  }

  #publish(): void {
    this.#heard = Array.from(this.#words)
    for (const listener of this.#listeners) listener()
  }
}

const Scope = createContext<Said | null>(null)

/**
 * Says `words` to a screen reader for as long as the caller is on the screen, and says them again
 * when they change. Nothing is said outside every scope: a page without a region is a page with
 * nobody listening.
 */
export function useAnnounced(words: string): void {
  const said = useContext(Scope)
  const key = useId()
  useEffect(() => {
    said?.say(key, words)
  }, [said, key, words])
  useEffect(
    () => () => {
      said?.withdraw(key)
    },
    [said, key]
  )
}

/**
 * A scope for the banners in `children`: the live region their words go into is drawn with it, as
 * its last child, and holds one paragraph for each banner in the scope. A banner that comes adds
 * one, and a banner whose words change changes its own.
 */
export function AnnouncementScope({ children }: { readonly children: ReactNode }): ReactNode {
  const [said] = useState(() => new Said())
  const items = useSyncExternalStore(said.subscribe, said.heard)
  return (
    <Scope.Provider value={said}>
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
        {items.map(([key, words]) => (
          <p key={key}>{words}</p>
        ))}
      </div>
    </Scope.Provider>
  )
}

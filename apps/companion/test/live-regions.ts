/**
 * Reading the live regions of a page in a test: which ones are there, what each holds, and what the
 * page did to them. A screen reader says what a region changes to, so the tests that say a message
 * is heard look at the changes.
 */

/** The page's own mutations, kept from the moment `holder` is watched. */
export function watched(holder: HTMLElement): { records: () => MutationRecord[]; stop: () => void } {
  const kept: MutationRecord[] = []
  const watching = new MutationObserver((batch) => {
    kept.push(...batch)
  })
  watching.observe(holder, { childList: true, subtree: true, characterData: true })
  return {
    records: () => {
      kept.push(...watching.takeRecords())
      return kept
    },
    stop: () => {
      watching.disconnect()
    }
  }
}

/** Every live region a scope drew inside `holder`. */
export function regionsOf(holder: ParentNode): HTMLElement[] {
  return Array.from(holder.querySelectorAll<HTMLElement>('[data-announcements]'))
}

/** The words a region holds, a paragraph each. */
export function heardIn(region: HTMLElement): string[] {
  return Array.from(region.querySelectorAll('p')).map((paragraph) => paragraph.textContent ?? '')
}

/** The paragraphs added to `region` in `records`, as the words each holds. */
export function addedTo(region: HTMLElement, records: readonly MutationRecord[]): string[] {
  return records
    .filter((record) => record.target === region)
    .flatMap((record) => Array.from(record.addedNodes))
    .map((node) => node.textContent ?? '')
}

/**
 * A banner is said to a screen reader.
 *
 * A screen reader says what a live region changes to, and not what one arrives holding, and a banner
 * arrives with its words. So the words go into a region its scope drew before it: this reads the
 * page's own mutations to see that the region was never added with them.
 */

import { render, waitFor } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { AnnouncementScope } from '../src/components/announcements'
import { Banner } from '../src/components/ui'

/** The page's own mutations, kept from the moment `holder` is watched. */
function watched(holder: HTMLElement): { records: () => MutationRecord[]; stop: () => void } {
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

function regionsOf(holder: HTMLElement): HTMLElement[] {
  return Array.from(holder.querySelectorAll<HTMLElement>('[data-announcements]'))
}

describe('a banner', () => {
  it('puts its words into a region that was in the page before it', async () => {
    const holder = document.createElement('div')
    document.body.append(holder)
    const { rerender } = render(<AnnouncementScope>{null}</AnnouncementScope>, { container: holder })
    const [region] = regionsOf(holder)
    expect(region).toBeEmptyDOMElement()

    const watching = watched(holder)
    rerender(
      <AnnouncementScope>
        <Banner tone="warning" title="The host is not answering" detail="Sessions cannot be read." />
      </AnnouncementScope>
    )
    await waitFor(() => {
      expect(region).toHaveTextContent('The host is not answering. Sessions cannot be read.')
    })
    const records = watching.records()
    watching.stop()
    expect(regionsOf(holder)[0], 'the region is the one that was there').toBe(region)
    expect(
      records.some((record) => Array.from(record.addedNodes).some((node) => node.contains(region))),
      'the region was not added again'
    ).toBe(false)
  })

  it('says its words again when they change, and leaves the region when it goes', async () => {
    const holder = document.createElement('div')
    document.body.append(holder)
    const { rerender } = render(
      <AnnouncementScope>
        <Banner tone="accent" title="Syncing" detail="Nothing is lost." />
      </AnnouncementScope>,
      { container: holder }
    )
    const [region] = regionsOf(holder)
    await waitFor(() => {
      expect(region).toHaveTextContent('Syncing. Nothing is lost.')
    })

    rerender(
      <AnnouncementScope>
        <Banner tone="accent" title="Synced." detail="All of it." />
      </AnnouncementScope>
    )
    await waitFor(() => {
      expect(region).toHaveTextContent('Synced. All of it.')
    })

    rerender(<AnnouncementScope>{null}</AnnouncementScope>)
    await waitFor(() => {
      expect(region).toBeEmptyDOMElement()
    })
  })

  it('says its words in the dialog that holds it, and not outside it', async () => {
    const holder = document.createElement('div')
    document.body.append(holder)
    render(
      <AnnouncementScope>
        <div role="dialog" aria-modal="true" aria-label="A sheet">
          <AnnouncementScope>
            <Banner tone="warning" title="This host is not answering" detail="Try again." />
          </AnnouncementScope>
        </div>
        <Banner tone="accent" title="Syncing" detail="Nothing is lost." />
      </AnnouncementScope>,
      { container: holder }
    )
    const dialog = holder.querySelector<HTMLElement>('[role="dialog"]')
    const inside = dialog === null ? [] : regionsOf(dialog)
    expect(inside).toHaveLength(1)
    await waitFor(() => {
      expect(inside[0]).toHaveTextContent('This host is not answering. Try again.')
    })
    const outside = regionsOf(holder).filter((region) => !inside.includes(region))
    expect(outside).toHaveLength(1)
    await waitFor(() => {
      expect(outside[0]).toHaveTextContent('Syncing. Nothing is lost.')
    })
    expect(outside[0]).not.toHaveTextContent('This host is not answering')
  })
})

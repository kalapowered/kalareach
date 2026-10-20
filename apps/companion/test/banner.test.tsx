/**
 * A banner is said to a screen reader.
 *
 * A screen reader says what a live region changes to, and not what one arrives holding, and a banner
 * arrives with its words. So the words go into a region the page already holds: this reads the
 * page's own mutations to see that the region was never added with them.
 */

import { render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { Announcements } from '../src/components/announcements'
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

function regionOf(holder: HTMLElement): HTMLElement {
  const region = holder.querySelector<HTMLElement>('[data-announcements]')
  if (region === null) throw new Error('the page holds no region for the banners')
  return region
}

describe('a banner', () => {
  it('puts its words into a region that was in the page before it', async () => {
    const holder = document.createElement('div')
    document.body.append(holder)
    const { rerender } = render(<Announcements />, { container: holder })
    const region = regionOf(holder)
    expect(region).toBeEmptyDOMElement()

    const watching = watched(holder)
    rerender(
      <>
        <Announcements />
        <Banner tone="warning" title="The host is not answering" detail="Sessions cannot be read." />
      </>
    )
    await waitFor(() => {
      expect(region).toHaveTextContent('The host is not answering. Sessions cannot be read.')
    })
    const records = watching.records()
    watching.stop()
    expect(regionOf(holder), 'the region is the one that was there').toBe(region)
    expect(
      records.some((record) => Array.from(record.addedNodes).some((node) => node.contains(region))),
      'the region was not added again'
    ).toBe(false)
    expect(
      records.some(
        (record) => record.target === region && Array.from(record.addedNodes).some((node) => node.nodeName === 'P')
      ),
      'the words were added to the region'
    ).toBe(true)
  })

  it('says its words again when they change, and leaves the region when it goes', async () => {
    const holder = document.createElement('div')
    document.body.append(holder)
    const { rerender } = render(
      <>
        <Announcements />
        <Banner tone="accent" title="Syncing" detail="Nothing is lost." />
      </>,
      { container: holder }
    )
    const region = regionOf(holder)
    await waitFor(() => {
      expect(region).toHaveTextContent('Syncing. Nothing is lost.')
    })

    const watching = watched(holder)
    rerender(
      <>
        <Announcements />
        <Banner tone="accent" title="Synced." detail="All of it." />
      </>
    )
    await waitFor(() => {
      expect(region).toHaveTextContent('Synced. All of it.')
    })
    expect(
      watching.records().some((record) => region.contains(record.target)),
      'the words changed in the region'
    ).toBe(true)
    watching.stop()

    rerender(<Announcements />)
    await waitFor(() => {
      expect(region).toBeEmptyDOMElement()
    })
  })

  it('shows its words to the eye once, and is not a status of its own', async () => {
    render(
      <>
        <Announcements />
        <Banner tone="accent" title="Syncing" detail="Nothing is lost." />
      </>
    )
    expect(screen.getByText('Syncing')).toBeVisible()
    expect(screen.queryByRole('status')).toBeNull()
    await waitFor(() => {
      expect(document.querySelector('[data-announcements]')).toHaveTextContent('Syncing. Nothing is lost.')
    })
  })
})

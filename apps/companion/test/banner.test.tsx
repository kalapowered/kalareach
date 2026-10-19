/**
 * A banner is said to a screen reader.
 *
 * A screen reader says what a live region changes to, and not what one arrives holding, and a banner
 * arrives with its words. So its words reach the region after the region is in the page: this reads
 * the page's own mutations to see that the region was added empty and the words came into it.
 */

import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { Banner } from '../src/components/ui'

/** What the page changes while `show` renders into a holder it watches. */
function changes(show: (holder: HTMLElement) => void): MutationRecord[] {
  const holder = document.createElement('div')
  document.body.append(holder)
  const watching = new MutationObserver(() => undefined)
  watching.observe(holder, { childList: true, subtree: true, characterData: true })
  show(holder)
  const records = watching.takeRecords()
  watching.disconnect()
  return records
}

describe('a banner', () => {
  it('puts its words into a live region that is already in the page', () => {
    const records = changes((container) => {
      render(
        <Banner tone="warning" title="The host is not answering" detail="Sessions cannot be read." />,
        { container }
      )
    })

    const region = screen.getByRole('status')
    expect(region).toHaveTextContent('The host is not answering. Sessions cannot be read.')
    // The region came into the page with nothing in it, and the words came into it afterwards.
    const added = records.findIndex((record) =>
      Array.from(record.addedNodes).some((node) => node.contains(region))
    )
    const worded = records.findIndex(
      (record) =>
        record.target === region &&
        Array.from(record.addedNodes).some((node) => node.nodeType === Node.TEXT_NODE)
    )
    expect(added, 'the region was added to the page').toBeGreaterThanOrEqual(0)
    expect(worded, 'the words were put into the region').toBeGreaterThan(added)
  })

  it('says the words again when they change, and shows them to the eye as they were', () => {
    const { rerender } = render(<Banner tone="accent" title="Syncing" detail="Nothing is lost." />)
    expect(screen.getAllByRole('status')).toHaveLength(1)
    expect(screen.getByText('Syncing')).toBeVisible()

    rerender(<Banner tone="accent" title="Synced." detail="All of it." />)
    expect(screen.getByRole('status')).toHaveTextContent('Synced. All of it.')
  })
})

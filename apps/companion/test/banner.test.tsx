/**
 * A banner is said to a screen reader.
 *
 * A screen reader says what a live region changes to, and not what one arrives holding, and a banner
 * arrives with its words. So its words reach the region after the page has drawn it: this reads the
 * page's own mutations to see that the region was added empty and the words came into it later.
 */

import { render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { Banner } from '../src/components/ui'

describe('a banner', () => {
  it('puts its words into a live region that is already in the page', async () => {
    const holder = document.createElement('div')
    document.body.append(holder)
    const records: MutationRecord[] = []
    const watching = new MutationObserver((batch) => {
      records.push(...batch)
    })
    watching.observe(holder, { childList: true, subtree: true, characterData: true })
    render(
      <Banner tone="warning" title="The host is not answering" detail="Sessions cannot be read." />,
      { container: holder }
    )

    const region = screen.getByRole('status')
    // Nothing is said while the banner is first drawn.
    expect(region).toBeEmptyDOMElement()
    await waitFor(() => {
      expect(region).toHaveTextContent('The host is not answering. Sessions cannot be read.')
    })
    records.push(...watching.takeRecords())
    watching.disconnect()
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

  it('says the words again when they change, and shows them to the eye as they were', async () => {
    const { rerender } = render(<Banner tone="accent" title="Syncing" detail="Nothing is lost." />)
    expect(screen.getAllByRole('status')).toHaveLength(1)
    expect(screen.getByText('Syncing')).toBeVisible()

    rerender(<Banner tone="accent" title="Synced." detail="All of it." />)
    await waitFor(() => {
      expect(screen.getByRole('status')).toHaveTextContent('Synced. All of it.')
    })
  })
})

/**
 * When the shelf of channel messages is read, and what a read that failed leaves (KR-REQ-12.26).
 *
 * The shelf is never read before the book's first read of the drafts has ended, whoever asks, and
 * it is told at the end of every later read of the drafts, a failed one included.
 */

import { describe, expect, it, vi } from 'vitest'

import { FakeChannelMessageStore } from '../src/host/fake-channel-messages'
import { FakeDraftStore } from '../src/host/fake-drafts'
import { fakeHost } from '../src/host/fake'
import { ChannelShelf } from '../src/model/channel-messages'
import { DraftBook } from '../src/model/draft-book'

function world() {
  const drafts = new FakeDraftStore()
  const messages = new FakeChannelMessageStore()
  const { port } = fakeHost({ drafts, channelMessages: messages })
  return { drafts, messages, port }
}

const listings = (messages: FakeChannelMessageStore): number =>
  messages.calls.filter((call) => call.kind === 'list').length

describe('the shelf of channel messages is read after the book’s first read of the drafts', () => {
  it('holds a read from the page and one from the window showing again until the first read has ended, and makes only the newest', async () => {
    const of = world()
    const shelf = new ChannelShelf(of.port)
    let release: () => void = () => undefined
    shelf.after(
      new Promise<void>((resolve) => {
        release = resolve
      })
    )
    void shelf.opened()
    void shelf.refresh()
    await new Promise((resolve) => setTimeout(resolve, 25))
    expect(listings(of.messages)).toBe(0)
    expect(shelf.snapshot().status).toBe('reading')
    release()
    await vi.waitFor(() => {
      expect(shelf.snapshot().status).toBe('ready')
    })
    expect(listings(of.messages)).toBe(1)
    expect(of.messages.calls.filter((call) => call.kind === 'list' && call.withText === true)).toHaveLength(1)
  })

  it('reads once the first read has ended without success too', async () => {
    const of = world()
    const shelf = new ChannelShelf(of.port)
    shelf.after(Promise.reject(new Error('the first read failed')))
    await shelf.opened()
    expect(listings(of.messages)).toBe(1)
    expect(shelf.snapshot().status).toBe('ready')
  })

  it('tells the shelf at the end of a read of the drafts that failed', async () => {
    const of = world()
    let failing = false
    const book = new DraftBook({
      ...of.port,
      deviceDrafts: () => (failing ? Promise.reject(new Error('refused')) : of.port.deviceDrafts())
    })
    await book.hydrate()
    let told = 0
    book.onReloaded(() => {
      told += 1
    })
    await book.reload()
    expect(told).toBe(1)
    failing = true
    await book.reload()
    expect(told).toBe(2)
  })
})

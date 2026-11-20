/**
 * A message sent over a channel that confirms nothing is handed over to the device's store of
 * channel messages, and never returns to a composer (KR-REQ-12.26).
 *
 * These run the book against the scripted host's real store rules: the keep is whole or refused,
 * the draft that held the text goes only after the keep, and a restart is a new book over the
 * same stores. A refused keep ends as an unknown outcome, as it did before this store existed.
 */

import { describe, expect, it } from 'vitest'

import { FakeChannelMessageStore } from '../src/host/fake-channel-messages'
import { FakeDraftStore } from '../src/host/fake-drafts'
import { fakeHost } from '../src/host/fake'
import type { HostPort } from '../src/host/port'
import { DraftBook, type HeldPrompt } from '../src/model/draft-book'
import { edit } from '../src/model/drafts'

const MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'
const ACTION = '6a7b6c50-22bb-4c3d-8e4f-000000000401'
const LOCAL = 's-1-test'

interface World {
  readonly drafts: FakeDraftStore
  readonly messages: FakeChannelMessageStore
  readonly port: HostPort
}

function world(): World {
  const drafts = new FakeDraftStore()
  const messages = new FakeChannelMessageStore()
  const { port } = fakeHost({ drafts, channelMessages: messages })
  return { drafts, messages, port }
}

async function opened(of: World): Promise<DraftBook> {
  const book = new DraftBook(of.port)
  await book.hydrate()
  return book
}

function type(book: DraftBook, sessionId: string, text: string): void {
  book.update(sessionId, (draft) => edit(draft, text, Date.now()))
}

/** The keep the page makes: the port's keep, answering whether it kept. */
function keeping(of: World, seen: HeldPrompt[] = []): (held: HeldPrompt) => Promise<boolean> {
  return async (held) => {
    seen.push(held)
    try {
      await of.port.deviceChannelMessageKeep({
        actionId: ACTION,
        holdId: null,
        localId: LOCAL,
        sessionId: MAIN,
        applicationInstanceId: null,
        agentBindingRevision: null,
        environmentId: null,
        hostName: 'studio',
        text: held.text,
        sentAtMs: '1',
        drafts: held.drafts.map((ref) => ({ id: ref.id, expectedRevision: ref.revision }))
      })
      return true
    } catch {
      return false
    }
  }
}

/** A composer that held `text` and cleared at the press, with the send under way. */
async function pressed(of: World, text = 'the message') {
  const book = await opened(of)
  type(book, MAIN, text)
  await book.settled()
  const token = book.beginSend(MAIN)
  type(book, MAIN, '')
  await book.settled()
  await token.claimed
  return { book, token }
}

describe('a message handed over to the channel store', () => {
  it('never returns to a composer: after the end, a reload, a second send and a restart', async () => {
    const of = world()
    const { book, token } = await pressed(of)
    book.endSend(token, 'handed_over', LOCAL, undefined, keeping(of))
    await book.settled()
    expect(book.draft(MAIN).text).toBe('')
    expect(book.handedOver(LOCAL)).toBe('kept')
    expect(of.messages.all().map((message) => message.actionId)).toEqual([ACTION])
    expect(of.messages.list(true).messages[0]?.text).toBe('the message')
    expect(of.drafts.all()).toEqual([])
    await book.reload()
    expect(book.draft(MAIN).text).toBe('')
    // A second send, and a reload during it, still leave the first message apart.
    type(book, MAIN, 'the next one')
    await book.settled()
    const second = book.beginSend(MAIN)
    type(book, MAIN, '')
    await book.reload()
    book.endSend(second, 'taken')
    await book.settled()
    expect(book.draft(MAIN).text).toBe('')
    const fresh = await opened(of)
    expect(fresh.draft(MAIN).text).toBe('')
    expect(of.messages.all()).toHaveLength(1)
  })

  it('is empty for an older release after a complete end, and for a second window', async () => {
    const of = world()
    const { book, token } = await pressed(of)
    book.endSend(token, 'handed_over', LOCAL, undefined, keeping(of))
    await book.settled()
    of.messages.readWithoutRepair()
    expect((await opened(of)).draft(MAIN).text).toBe('')
    of.messages.readWithoutRepair(false)
    const second = await opened(of)
    await second.reload()
    expect(second.draft(MAIN).text).toBe('')
  })

  it('ends a refused keep as an unknown send: the text is in the composer and a later receipt is ordinary', async () => {
    const of = world()
    of.messages.refuseKeeps({ code: 'QUOTA_EXCEEDED', message: 'full' })
    const { book, token } = await pressed(of)
    const told: (string | null)[] = []
    book.endSend(token, 'handed_over', LOCAL, (id) => told.push(id), keeping(of))
    await book.settled()
    expect(book.handedOver(LOCAL)).toBeNull()
    expect(book.draft(MAIN).text).toBe('the message')
    expect(told).toHaveLength(1)
    expect(told[0]).not.toBeNull()
    // The press record is still stored at its revision, and a fresh book gives the composer the text.
    expect(of.drafts.all().map((draft) => draft.text)).toEqual(['the message'])
    expect((await opened(of)).draft(MAIN).text).toBe('the message')
    // The host then says it was taken: an ordinary late receipt, which removes the draft.
    book.sendSettled(LOCAL, 'applied')
    await book.settled()
    expect(of.drafts.all()).toEqual([])
  })

  it('owes the removal of the draft when the discard fails after the keep, and makes it at the next start', async () => {
    const of = world()
    const { book, token } = await pressed(of)
    of.drafts.refuseDiscards({ code: 'STORAGE_UNAVAILABLE', message: 'refused' })
    book.endSend(token, 'handed_over', LOCAL, undefined, keeping(of))
    await book.settled()
    expect(of.drafts.pendingRemovals()).toHaveLength(1)
    expect(book.draft(MAIN).text).toBe('')
    of.drafts.refuseDiscards(null)
    const next = await opened(of)
    await next.settled()
    expect(next.draft(MAIN).text).toBe('')
    expect(of.drafts.all()).toEqual([])
  })

  it('is finished by the read after a stop between the entry and the ledger, and pins the older release', async () => {
    const of = world()
    const { token } = await pressed(of)
    of.messages.stopAfterEntry()
    const seen: HeldPrompt[] = []
    const kept = await keeping(of, seen)({ text: 'the message', drafts: token.pressed() })
    expect(kept).toBe(false)
    expect(of.messages.all()).toHaveLength(1)
    // A release with the repair keeps the composer empty; an older one finds the record a draft.
    of.messages.readWithoutRepair()
    expect((await opened(of)).draft(MAIN).text).toBe('the message')
    of.messages.readWithoutRepair(false)
    const repaired = await opened(of)
    await repaired.settled()
    expect(repaired.draft(MAIN).text).toBe('')
  })

  it.each(['applied', 'refused'] as const)(
    'changes nothing when a %s receipt arrives during the keep, even with the same text typed again',
    async (state) => {
      const of = world()
      const { book, token } = await pressed(of)
      let release: () => void = () => undefined
      const gate = new Promise<void>((resolve) => {
        release = resolve
      })
      const inner = keeping(of)
      book.endSend(token, 'handed_over', LOCAL, undefined, async (held) => {
        await gate
        return inner(held)
      })
      expect(book.handedOver(LOCAL)).toBe('pending')
      type(book, MAIN, 'the message')
      book.sendSettled(LOCAL, state)
      release()
      await book.settled()
      expect(book.draft(MAIN).text).toBe('the message')
      expect(of.messages.all()).toHaveLength(1)
      expect(book.handedOver(LOCAL)).toBe('kept')
    }
  )

  it('names the one reference the press left when the press write failed', async () => {
    const of = world()
    const book = await opened(of)
    type(book, MAIN, 'the message')
    await book.settled()
    const before = of.drafts.all()
    of.drafts.refuseSaves({ code: 'STORAGE_UNAVAILABLE', message: 'refused' })
    const token = book.beginSend(MAIN)
    type(book, MAIN, '')
    await book.settled()
    await token.claimed
    expect(token.exact()).toBe(false)
    of.drafts.refuseSaves(null)
    const seen: HeldPrompt[] = []
    book.endSend(token, 'handed_over', LOCAL, undefined, keeping(of, seen))
    await book.settled()
    expect(seen[0]?.drafts.map((ref) => ref.id)).toEqual(before.map((draft) => draft.id))
    expect(of.drafts.all()).toEqual([])
  })

  it('applies a final receipt once when the keep then fails', async () => {
    for (const state of ['applied', 'refused'] as const) {
      const of = world()
      of.messages.refuseKeeps({ code: 'RESOURCE_UNAVAILABLE', message: 'refused' })
      const { book, token } = await pressed(of)
      let release: () => void = () => undefined
      const gate = new Promise<void>((resolve) => {
        release = resolve
      })
      const inner = keeping(of)
      book.endSend(token, 'handed_over', LOCAL, undefined, async (held) => {
        await gate
        return inner(held)
      })
      book.sendSettled(LOCAL, state)
      release()
      await book.settled()
      // Taken: the unknown path ran and the late receipt removed the draft; refused: the text is back, once.
      if (state === 'applied') {
        expect(of.drafts.all()).toEqual([])
        expect(book.draft(MAIN).text).toBe('')
      } else {
        expect(book.draft(MAIN).text).toBe('the message')
        expect(of.drafts.all().map((draft) => draft.text)).toEqual(['the message'])
      }
    }
  })

  it('applies a receipt that came during a failed keep to the sends of that moment, and to none made after it', async () => {
    const of = world()
    of.messages.refuseKeeps({ code: 'RESOURCE_UNAVAILABLE', message: 'refused' })
    const { book, token } = await pressed(of)
    let release: () => void = () => undefined
    const gate = new Promise<void>((resolve) => {
      release = resolve
    })
    const inner = keeping(of)
    const told: (string | null)[] = []
    book.endSend(token, 'handed_over', LOCAL, (id) => told.push(id), async (held) => {
      await gate
      return inner(held)
    })
    // The host says it took the first message, and the person sends the same words again before the keep answers.
    book.sendSettled(LOCAL, 'applied')
    type(book, MAIN, 'the message')
    const later = book.beginSend(MAIN)
    type(book, MAIN, '')
    release()
    await book.settled()
    await later.claimed
    // The first prompt's end is told once, after its receipt was applied; the later send is not done by it.
    expect(told).toEqual([null])
    book.endSend(later, 'refused', 'local-later')
    await book.settled()
    expect(book.draft(MAIN).text).toBe('the message')
    expect(of.drafts.all().map((draft) => draft.text)).toEqual(['the message'])
  })

  it('still keeps a message whose words another prompt of the composer was applied for', async () => {
    const of = world()
    const book = await opened(of)
    type(book, MAIN, 'the message')
    await book.settled()
    const first = book.beginSend(MAIN)
    type(book, MAIN, '')
    await book.settled()
    await first.claimed
    // The same words again, sent by a person who checked, and still on their way.
    type(book, MAIN, 'the message')
    await book.settled()
    const second = book.beginSend(MAIN)
    type(book, MAIN, '')
    await book.settled()
    await second.claimed
    // The first prompt is said to have been applied after nobody knew: it marks the second consumed.
    book.endSend(first, 'unknown', 'local-first')
    await book.settled()
    book.sendSettled('local-first', 'applied')
    await book.settled()
    const seen: HeldPrompt[] = []
    book.endSend(second, 'handed_over', LOCAL, undefined, keeping(of, seen))
    await book.settled()
    // Consumed or not, the keep ran: the message is in the store and nothing of it is left to send again.
    expect(seen).toHaveLength(1)
    expect(book.handedOver(LOCAL)).toBe('kept')
    expect(of.messages.all().map((message) => message.actionId)).toEqual([ACTION])
    expect(of.drafts.all()).toEqual([])
    expect(book.draft(MAIN).text).toBe('')
  })

  it('exact() is true only when the press stored the sent text', async () => {
    const of = world()
    const { token } = await pressed(of)
    expect(token.exact()).toBe(true)
    expect(token.pressed()).toHaveLength(1)
  })
})

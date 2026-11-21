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

  it('ends as an unknown send for a refusal that is a local failure and leaves the press record stored', async () => {
    const of = world()
    of.messages.refuseKeeps({ code: 'RESOURCE_UNAVAILABLE', message: 'refused' })
    const { book, token } = await pressed(of)
    const record = token.pressed()[0]
    const told: (string | null)[] = []
    const seen: HeldPrompt[] = []
    const attempt = keeping(of)
    book.endSend(token, 'handed_over', LOCAL, (id) => told.push(id), async (held) => {
      seen.push(held)
      return attempt(held)
    })
    await book.settled()
    expect(book.handedOver(LOCAL)).toBeNull()
    expect(book.draft(MAIN).text).toBe('the message')
    expect(told).toHaveLength(1)
    // The press record is the one that stays, with the text: the composer takes it back under the same identity.
    expect(of.drafts.all().map((draft) => [draft.id, draft.text])).toEqual([[record?.id, 'the message']])
    // The keep was asked with the press record's exact version, and the record took the text back after it.
    expect(seen.map((held) => held.drafts.map((ref) => [ref.id, ref.revision]))).toEqual([
      [[record?.id, record?.revision]]
    ])
  })

  it('ends as an unknown send for a keep that rejects and leaves the press record stored', async () => {
    const of = world()
    const { book, token } = await pressed(of)
    const record = token.pressed()[0]
    const told: (string | null)[] = []
    const seen: HeldPrompt[] = []
    const attempt = (held: HeldPrompt): Promise<boolean> =>
      Promise.reject(new Error(`the keep of ${held.text.length} characters rejected`))
    book.endSend(token, 'handed_over', LOCAL, (id) => told.push(id), async (held) => {
      seen.push(held)
      return attempt(held)
    })
    await book.settled()
    expect(book.handedOver(LOCAL)).toBeNull()
    expect(book.draft(MAIN).text).toBe('the message')
    expect(told).toHaveLength(1)
    // The press record is the one that stays, with the text: the composer takes it back under the same identity.
    expect(of.drafts.all().map((draft) => [draft.id, draft.text])).toEqual([[record?.id, 'the message']])
    // The keep was asked with the press record's exact version, and the record took the text back after it.
    expect(seen.map((held) => held.drafts.map((ref) => [ref.id, ref.revision]))).toEqual([
      [[record?.id, record?.revision]]
    ])
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

  it('changes nothing when a applied receipt arrives during the keep, even with the same text typed again', async () => {
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
    book.sendSettled(LOCAL, 'applied')
    const before = of.drafts.calls.length
    release()
    await book.settled()
    // The store saw the keep's own removal of the press record and the typed words, and nothing
    // else: no receipt cleared a composer and none returned text to it.
    expect(of.drafts.calls.slice(before)).toEqual([{ kind: 'discard' }, { kind: 'save', text: 'the message' }])
    expect(book.draft(MAIN).text).toBe('the message')
    expect(of.messages.all()).toHaveLength(1)
    expect(book.handedOver(LOCAL)).toBe('kept')
  })

  it('changes nothing when a refused receipt arrives during the keep, even with the same text typed again', async () => {
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
    book.sendSettled(LOCAL, 'refused')
    const before = of.drafts.calls.length
    release()
    await book.settled()
    // The store saw the keep's own removal of the press record and the typed words, and nothing
    // else: no receipt cleared a composer and none returned text to it.
    expect(of.drafts.calls.slice(before)).toEqual([{ kind: 'discard' }, { kind: 'save', text: 'the message' }])
    expect(book.draft(MAIN).text).toBe('the message')
    expect(of.messages.all()).toHaveLength(1)
    expect(book.handedOver(LOCAL)).toBe('kept')
  })

  it('names the one reference the press left when the press write failed, and leaves an unrelated draft as it is', async () => {
    const of = world()
    // A draft of another session that nothing here touches: its stored revision is compared at the end.
    const unrelated = of.drafts.save({
      id: null,
      expectedRevision: null,
      sessionId: '8a7b6c50-22bb-4c3d-8e4f-000000000102',
      applicationInstanceId: null,
      agentBindingRevision: null,
      state: 'open',
      text: 'an unrelated draft',
      attachments: []
    }).draft
    const book = await opened(of)
    type(book, MAIN, 'the message')
    await book.settled()
    const before = of.drafts.all().filter((draft) => draft.id !== unrelated.id)
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
    expect(seen[0]?.drafts.map((ref) => ref.revision)).toEqual(before.map((draft) => draft.revision))
    expect(seen[0]?.drafts.map((ref) => ref.id)).not.toContain(unrelated.id)
    // The press's draft is gone; the unrelated one stands at the revision it had.
    expect(of.drafts.all().map((draft) => [draft.id, draft.revision])).toEqual([[unrelated.id, unrelated.revision]])
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
      const seen: HeldPrompt[] = []
      const told: (string | null)[] = []
      book.endSend(token, 'handed_over', LOCAL, (id) => told.push(id), async (held) => {
        seen.push(held)
        await gate
        return inner(held)
      })
      book.sendSettled(LOCAL, state)
      const before = of.drafts.calls.length
      release()
      await book.settled()
      // One keep, one end told once, and one application of the receipt: the press record's removal
      // when it was taken, the text stored back when it was refused.
      expect(seen).toHaveLength(1)
      expect(told).toHaveLength(1)
      expect(of.drafts.calls.slice(before)).toEqual(
        state === 'applied' ? [{ kind: 'discard' }] : [{ kind: 'save', text: 'the message' }]
      )
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

  it('leaves a newer revision of a draft listed when its retirement conflicts, and shows the store’s', async () => {
    const of = world()
    const book = await opened(of)
    type(book, MAIN, 'what the composer holds')
    await book.settled()
    const save = (id: string | null, expectedRevision: string | null, text: string) =>
      of.drafts.save({
        id,
        expectedRevision,
        sessionId: MAIN,
        applicationInstanceId: null,
        agentBindingRevision: null,
        state: 'open',
        text,
        attachments: []
      }).draft
    const apart = save(null, null, 'the draft that was held')
    await book.reload()
    expect(book.snapshot().kept.map((each) => each.text)).toEqual(['the draft that was held'])
    // The person edits it in another window; the retirement names the version that was held.
    const newer = save(apart.id, apart.revision, 'edited since')
    // The newer revision is already listed when the retirement of the older one is asked for.
    await book.reload()
    expect(book.snapshot().kept.map((each) => each.text)).toEqual(['edited since'])
    await book.retireHeld([{ id: apart.id, revision: apart.revision }])
    await book.settled()
    expect(of.drafts.all().map((each) => each.text)).toContain('edited since')
    expect(book.snapshot().kept.map((each) => each.text)).toEqual(['edited since'])
    expect(book.snapshot().kept[0]?.revision).toBe(newer.revision)
    // The exact version that was held goes, and nothing else.
    await book.retireHeld([{ id: newer.id, revision: newer.revision }])
    await book.settled()
    expect(book.snapshot().kept).toEqual([])
  })

  it('lists a newer revision that only the store holds when a retirement conflicts, by reading the store again', async () => {
    const of = world()
    const book = await opened(of)
    type(book, MAIN, 'what the composer holds')
    await book.settled()
    const save = (id: string | null, expectedRevision: string | null, text: string) =>
      of.drafts.save({
        id,
        expectedRevision,
        sessionId: MAIN,
        applicationInstanceId: null,
        agentBindingRevision: null,
        state: 'open',
        text,
        attachments: []
      }).draft
    const apart = save(null, null, 'the draft that was held')
    await book.reload()
    expect(book.snapshot().kept.map((each) => each.text)).toEqual(['the draft that was held'])
    // Another window saves a newer revision. This window has not read it: only the store holds it.
    const newer = save(apart.id, apart.revision, 'edited since')
    expect(book.snapshot().kept.map((each) => each.revision)).toEqual([apart.revision])
    await book.retireHeld([{ id: apart.id, revision: apart.revision }])
    await book.settled()
    // The conflict says the draft changed; the list is read again, and shows the revision it did not know.
    expect(book.snapshot().kept.map((each) => [each.text, each.revision])).toEqual([['edited since', newer.revision]])
  })

  it('leaves a newer revision listed when the retirement conflicts and the read after it fails too', async () => {
    const of = world()
    let failing = false
    const book = new DraftBook({
      ...of.port,
      deviceDrafts: () => (failing ? Promise.reject(new Error('refused')) : of.port.deviceDrafts())
    })
    await book.hydrate()
    const save = (id: string | null, expectedRevision: string | null, text: string) =>
      of.drafts.save({
        id,
        expectedRevision,
        sessionId: MAIN,
        applicationInstanceId: null,
        agentBindingRevision: null,
        state: 'open',
        text,
        attachments: []
      }).draft
    const held = save(null, null, 'the composer’s text')
    await book.reload()
    const apart = save(null, null, 'the draft that was held')
    await book.reload()
    expect(book.snapshot().kept.map((each) => each.text)).toEqual(['the draft that was held'])
    const newer = save(apart.id, apart.revision, 'edited since')
    await book.reload()
    expect(book.snapshot().kept.map((each) => each.text)).toEqual(['edited since'])
    failing = true
    await book.retireHeld([{ id: apart.id, revision: apart.revision }])
    await book.settled()
    // Only the version that was held is dropped: the newer one is listed with no read to bring it back.
    expect(book.snapshot().kept.map((each) => [each.text, each.revision])).toEqual([['edited since', newer.revision]])
    expect(held.id).not.toBe(apart.id)
  })

  it('names the keep and the submission in the type of a handed-over end', () => {
    const wrong = (book: DraftBook, token: Parameters<DraftBook['endSend']>[0]) => {
      // @ts-expect-error a handed_over end names its submission and its keep
      book.endSend(token, 'handed_over')
      // @ts-expect-error the keep is required
      book.endSend(token, 'handed_over', LOCAL, undefined)
    }
    expect(typeof wrong).toBe('function')
  })

  it('exact() is true only when the press stored the sent text', async () => {
    const of = world()
    const { token } = await pressed(of)
    expect(token.exact()).toBe(true)
    expect(token.pressed()).toHaveLength(1)
  })
})

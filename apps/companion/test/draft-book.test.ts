/**
 * The drafts a window holds, kept in the store native code keeps them in (KR-REQ-13.13, 24.13).
 *
 * These run the book against the scripted host's real store rules: a save names the version it
 * replaces, another window can write in between, and a restart is a new book over the same store.
 * Nothing here sends a prompt, and the book has no means to.
 */

import { describe, expect, it } from 'vitest'

import { FakeDraftStore } from '../src/host/fake-drafts'
import type {
  DraftDiscardRequest,
  DraftRetargetRequest,
  DraftSaveRequest,
  HostPort
} from '../src/host/port'
import { DraftBook, keptEntry } from '../src/model/draft-book'
import { edit, startDraft } from '../src/model/drafts'

const MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'
const BUILD = '8a7b6c50-22bb-4c3d-8e4f-000000000102'

/** The four members of the port a book calls, over one store. */
function portOver(store: FakeDraftStore): HostPort {
  return {
    deviceDrafts: async () => store.list(),
    deviceDraftSave: async (request: DraftSaveRequest) => store.save(request),
    deviceDraftRetarget: async (request: DraftRetargetRequest) => store.retarget(request),
    deviceDraftDiscard: async (request: DraftDiscardRequest) => store.discard(request),
    deviceDraftMarkRemoval: async (request: DraftDiscardRequest) => {
      store.markRemoval(request)
    }
  } as unknown as HostPort
}

/** A book that has read its store. */
async function opened(store: FakeDraftStore): Promise<DraftBook> {
  const book = new DraftBook(portOver(store))
  await book.hydrate()
  return book
}

/** The person types into a session's composer. */
function type(book: DraftBook, sessionId: string, text: string): void {
  book.update(sessionId, (draft) => edit(draft, text, Date.now()))
}

describe('a draft is written to the store as it is typed', () => {
  it('stores what was typed, and a window that opens the store later finds it', async () => {
    const store = new FakeDraftStore()
    const book = await opened(store)
    type(book, MAIN, 'half a thought')
    await book.settled()

    expect(store.all().map((draft) => draft.text)).toEqual(['half a thought'])

    const restarted = await opened(store)
    const draft = restarted.draft(MAIN)
    expect(draft.text).toBe('half a thought')
    // A fresh process holds no association: the draft is kept and detached until the host is asked.
    expect(draft.state).toBe('detached')
    expect(draft.stored).not.toBeNull()
  })

  it('does not store a composer nobody has written in', async () => {
    const store = new FakeDraftStore()
    const book = await opened(store)
    book.draft(MAIN)
    type(book, BUILD, '')
    await book.settled()
    expect(store.all()).toEqual([])
    expect(store.calls).toEqual([])
  })

  it('writes the newest text after a burst of keystrokes, not every one of them', async () => {
    const store = new FakeDraftStore()
    const book = await opened(store)
    for (const text of ['h', 'he', 'hel', 'hell', 'hello']) type(book, MAIN, text)
    await book.settled()
    expect(store.all().map((draft) => draft.text)).toEqual(['hello'])
    expect(store.calls.length).toBeLessThan(5)
    expect(store.calls.at(-1)).toEqual({ kind: 'save', text: 'hello' })
  })

  it('keeps what was typed while a write was on its way, and writes it next', async () => {
    const store = new FakeDraftStore()
    const real = portOver(store)
    let release: () => void = () => undefined
    const held = new Promise<void>((resolve) => {
      release = resolve
    })
    let first = true
    const book = new DraftBook({
      ...real,
      deviceDraftSave: async (request) => {
        const answer = await real.deviceDraftSave(request)
        if (first) {
          first = false
          await held
        }
        return answer
      }
    })
    await book.hydrate()
    type(book, MAIN, 'one')
    await Promise.resolve()
    // The first write has been made and its answer has not come back.
    type(book, MAIN, 'one two')
    release()
    await book.settled()

    expect(book.draft(MAIN).text).toBe('one two')
    expect(store.all().map((draft) => draft.text)).toEqual(['one two'])
    expect(store.all()).toHaveLength(1)
  })

  it('removes the stored draft when the person clears it', async () => {
    const store = new FakeDraftStore()
    const book = await opened(store)
    type(book, MAIN, 'something to clear')
    await book.settled()
    type(book, MAIN, '')
    await book.settled()
    expect(store.all()).toEqual([])
    expect(book.draft(MAIN).stored).toBeNull()
  })
})

describe('a lost connection', () => {
  it('takes every draft’s association away and writes nothing, keeping text and edits as they were', async () => {
    const store = new FakeDraftStore()
    const book = await opened(store)
    type(book, MAIN, 'half a thought')
    type(book, BUILD, 'another')
    await book.settled()
    const before = book.snapshot().drafts.map((draft) => [draft.text, draft.revision])
    const writes = store.calls.length

    book.connectionLost()
    await book.settled()

    const after = book.snapshot().drafts
    expect(after.map((draft) => draft.state)).toEqual(['detached', 'detached'])
    expect(after.map((draft) => [draft.text, draft.revision])).toEqual(before)
    expect(store.calls.length).toBe(writes)
  })
})

describe('a store that cannot be opened', () => {
  it('leaves the drafts in this window and says nothing is kept', async () => {
    const store = new FakeDraftStore()
    store.breakOpening()
    const book = await opened(store)
    expect(book.snapshot().status).toBe('memory-only')
    expect(book.snapshot().problem).toMatch(/could not be opened/)

    type(book, MAIN, 'typed anyway')
    await book.settled()
    expect(book.draft(MAIN).text).toBe('typed anyway')
    expect(store.calls).toEqual([])
  })

  it('says so when a write is refused, and writes again at the next change', async () => {
    const store = new FakeDraftStore()
    const book = await opened(store)
    store.refuseSaves({ code: 'STORAGE_UNAVAILABLE', message: 'the disk is full' })
    type(book, MAIN, 'first')
    await book.settled()
    expect(book.snapshot().problem).toMatch(/disk is full/)
    expect(store.all()).toEqual([])

    store.refuseSaves(null)
    type(book, MAIN, 'first, and more')
    await book.settled()
    expect(book.snapshot().problem).toBeNull()
    expect(store.all().map((draft) => draft.text)).toEqual(['first, and more'])
  })
})

describe('a window that is about to be hidden', () => {
  it('writes again what the store refused, so that it is not lost with the window', async () => {
    const store = new FakeDraftStore()
    const book = await opened(store)
    store.refuseSaves({ code: 'STORAGE_UNAVAILABLE', message: 'the disk is full' })
    type(book, MAIN, 'written while the disk was full')
    await book.settled()
    expect(store.all()).toEqual([])

    store.refuseSaves(null)
    // The window is hidden or closed: whatever is not written yet is written then.
    book.writeAll()
    await book.settled()
    expect(store.all().map((draft) => draft.text)).toEqual(['written while the disk was full'])
    expect(book.snapshot().problem).toBeNull()
  })
})

describe('two windows that change the same draft', () => {
  it('keeps this window’s text beside the other’s, and loses neither', async () => {
    const store = new FakeDraftStore()
    const one = await opened(store)
    type(one, MAIN, 'begun in the first window')
    await one.settled()
    const two = await opened(store)
    const notices: string[] = []
    one.onNotice((words) => notices.push(words))

    // The second window writes first.
    type(two, MAIN, 'the second window’s version')
    await two.settled()
    // The first window still holds the first version.
    type(one, MAIN, 'the first window’s version')
    await one.settled()

    const texts = store.all().map((draft) => draft.text).sort()
    expect(texts).toEqual(['the first window’s version', 'the second window’s version'])
    expect(notices).toHaveLength(1)
    // The first window carries on with what it wrote; the other's is listed beside, apart.
    expect(one.draft(MAIN).text).toBe('the first window’s version')
    await one.settled()
    expect(one.snapshot().kept.map((kept) => kept.text)).toEqual(['the second window’s version'])

    // However long it carries on, it is one copy, not one more each time.
    type(one, MAIN, 'the first window’s version, further on')
    await one.settled()
    expect(store.all()).toHaveLength(2)
  })

  it('never puts a copy in a composer on its own after a restart', async () => {
    const store = new FakeDraftStore()
    const one = await opened(store)
    type(one, MAIN, 'begun')
    await one.settled()
    const two = await opened(store)
    type(two, MAIN, 'theirs')
    await two.settled()
    type(one, MAIN, 'mine')
    await one.settled()

    const restarted = await opened(store)
    // The stored draft, the other window's, is the session's. Mine is kept apart, as a copy.
    expect(restarted.draft(MAIN).text).toBe('theirs')
    const kept = restarted.snapshot().kept
    expect(kept.map((each) => [each.text, each.why])).toEqual([['mine', 'copy']])
  })

  it('picks the newest draft of a session that has several, and lists the rest', async () => {
    const store = new FakeDraftStore()
    const made = store.save({
      id: null,
      expectedRevision: null,
      sessionId: MAIN,
      applicationInstanceId: null,
      agentBindingRevision: null,
      state: 'open',
      text: 'older',
      attachments: []
    })
    store.save({
      id: null,
      expectedRevision: null,
      sessionId: MAIN,
      applicationInstanceId: null,
      agentBindingRevision: null,
      state: 'open',
      text: 'newer',
      attachments: []
    })
    const book = await opened(store)
    expect(book.draft(MAIN).text).toBe('newer')
    expect(book.snapshot().kept).toEqual([
      expect.objectContaining({ id: made.draft.id, text: 'older', why: 'other' })
    ])
  })
})

describe('a prompt sent from a draft (the draft goes only once the host took it)', () => {
  /**
   * Sends 'send this' from a composer that held it and cleared, as the desktop does, and ends the
   * send as `outcome` says. `giveBack` is the screen putting a refused prompt's text back into an
   * empty composer, which it does while its conversation is open.
   */
  async function sending(
    outcome: 'taken' | 'refused' | 'unknown',
    options: { during?: (book: DraftBook) => void; giveBack?: boolean } = {}
  ): Promise<{ store: FakeDraftStore; book: DraftBook }> {
    const store = new FakeDraftStore()
    const book = await opened(store)
    type(book, MAIN, 'send this')
    await book.settled()
    const token = book.beginSend(MAIN)
    // The composer clears when the person presses Send.
    type(book, MAIN, '')
    options.during?.(book)
    await book.settled()
    // While the prompt is on its way the stored draft is exactly what was sent.
    expect(store.all().map((draft) => draft.text)).toContain('send this')
    if (outcome === 'refused' && options.giveBack !== false && book.draft(MAIN).text === '') {
      type(book, MAIN, 'send this')
    }
    book.endSend(token, outcome)
    await book.settled()
    return { store, book }
  }

  it('removes the stored draft once the host took the prompt', async () => {
    const { store } = await sending('taken')
    expect(store.all()).toEqual([])
  })

  it('keeps it when the host refused the prompt, once', async () => {
    const { store, book } = await sending('refused')
    expect(store.all().map((draft) => draft.text)).toEqual(['send this'])
    expect(book.draft(MAIN).text).toBe('send this')
  })

  it('keeps it when nobody knows what became of the prompt, and puts it back in the composer', async () => {
    const { store, book } = await sending('unknown')
    expect(store.all().map((draft) => draft.text)).toEqual(['send this'])
    expect(book.draft(MAIN).text).toBe('send this')
    expect(book.draft(MAIN).stored).not.toBeNull()
  })

  it('gives the text back itself when the screen it was sent from is gone', async () => {
    // The tab was closed before the answer: nothing puts the text back, so the book does.
    const { store, book } = await sending('refused', { giveBack: false })
    expect(book.draft(MAIN).text).toBe('send this')
    expect(store.all().map((draft) => draft.text)).toEqual(['send this'])
    const restarted = await opened(store)
    expect(restarted.draft(MAIN).text).toBe('send this')
  })

  it('stores what was typed after the press, in place of what was sent, once the host took it', async () => {
    const { store, book } = await sending('taken', {
      during: (during) => type(during, MAIN, 'the next thing')
    })
    expect(store.all().map((draft) => draft.text)).toEqual(['the next thing'])
    expect(book.draft(MAIN).text).toBe('the next thing')
  })

  for (const outcome of ['refused', 'unknown'] as const) {
    it(`keeps what was sent and what was written meanwhile when the outcome is ${outcome}`, async () => {
      const notices: string[] = []
      const store = new FakeDraftStore()
      const book = await opened(store)
      book.onNotice((words) => notices.push(words))
      type(book, MAIN, 'send this')
      await book.settled()
      const token = book.beginSend(MAIN)
      type(book, MAIN, '')
      type(book, MAIN, 'the next thing')
      await book.settled()
      book.endSend(token, outcome)
      await book.settled()

      // Neither text is replaced by the other: the composer holds the new one, and the prompt's
      // text is a draft of its own that a person finds in the kept drafts.
      expect(store.all().map((draft) => draft.text).sort()).toEqual(['send this', 'the next thing'])
      expect(book.draft(MAIN).text).toBe('the next thing')
      expect(book.snapshot().kept.map((kept) => [kept.text, kept.why])).toEqual([['send this', 'sent']])
      expect(notices.join(' ')).toMatch(/kept/i)

      // After a restart the composer holds the newer text and the older one is still listed.
      const restarted = await opened(store)
      expect(restarted.draft(MAIN).text).toBe('the next thing')
      expect(restarted.snapshot().kept.map((kept) => kept.text)).toEqual(['send this'])
    })
  }

  it('writes what is typed while a prompt is on its way, however long it takes to end', async () => {
    const store = new FakeDraftStore()
    const book = await opened(store)
    type(book, MAIN, 'send this')
    await book.settled()
    book.beginSend(MAIN)
    type(book, MAIN, '')
    type(book, MAIN, 'the next thing')
    await book.settled()

    // The prompt has not ended, and what was typed since is kept.
    expect(store.all().map((draft) => draft.text).sort()).toEqual(['send this', 'the next thing'])
  })

  it('does not lose the text of a prompt whose first write failed', async () => {
    const store = new FakeDraftStore()
    const book = await opened(store)
    type(book, MAIN, 'send this')
    // The store refuses what is typed, so nothing of the draft is stored when it is sent.
    store.refuseSaves({ code: 'STORAGE_UNAVAILABLE', message: 'the disk is full' })
    await book.settled()
    const token = book.beginSend(MAIN)
    type(book, MAIN, '')
    await book.settled()
    store.refuseSaves(null)
    book.endSend(token, 'refused')
    await book.settled()

    expect(book.draft(MAIN).text).toBe('send this')
    expect(store.all().map((draft) => draft.text)).toEqual(['send this'])
  })

  it('leaves no older version of a prompt behind once its text is kept', async () => {
    const store = new FakeDraftStore()
    const book = await opened(store)
    type(book, MAIN, 'send')
    await book.settled()
    // The rest of the text is written while the store refuses, and sent from there.
    store.refuseSaves({ code: 'STORAGE_UNAVAILABLE', message: 'the disk is full' })
    type(book, MAIN, 'send this')
    await book.settled()
    const token = book.beginSend(MAIN)
    type(book, MAIN, '')
    await book.settled()
    store.refuseSaves(null)
    book.endSend(token, 'refused')
    await book.settled()

    expect(store.all().map((draft) => draft.text)).toEqual(['send this'])
    expect(book.draft(MAIN).text).toBe('send this')
  })
})

describe('a conflict is a person’s to settle', () => {
  it('sends a draft to a conversation only when the person says so, and the store agrees', async () => {
    const store = new FakeDraftStore()
    const book = await opened(store)
    book.update(MAIN, (draft) => ({
      ...edit(draft, 'for the old conversation', 1),
      target: { sessionId: MAIN, applicationInstanceId: 'a-1', agentBindingRevision: '3' }
    }))
    await book.settled()
    book.update(MAIN, (draft) => ({ ...draft, state: 'conflicted' }))
    await book.settled()
    expect(store.all()[0]?.state).toBe('conflicted')

    // A window that thinks the draft is open does not reopen it.
    book.update(MAIN, (draft) => edit({ ...draft, state: 'bound' }, 'for the old conversation, edited', 2))
    await book.settled()
    expect(store.all()[0]?.state).toBe('conflicted')
    expect(book.draft(MAIN).state).toBe('conflicted')

    book.retarget(MAIN, { sessionId: MAIN, applicationInstanceId: 'a-2', agentBindingRevision: '1' })
    await book.settled()
    expect(store.all()[0]).toMatchObject({ state: 'open', applicationInstanceId: 'a-2' })
    expect(book.draft(MAIN).state).toBe('bound')
  })

  it('puts the draft back when the store refuses a retarget, and says so', async () => {
    const store = new FakeDraftStore()
    const book = await opened(store)
    book.update(MAIN, (draft) => ({
      ...edit(draft, 'text', 1),
      target: { sessionId: MAIN, applicationInstanceId: 'a-1', agentBindingRevision: '3' },
      state: 'conflicted'
    }))
    await book.settled()
    const notices: string[] = []
    book.onNotice((words) => notices.push(words))
    // Another window moved the draft on, so the version this window holds is stale.
    store.writeAsAnotherWindow(store.all()[0]?.id ?? '', { text: 'theirs' })

    book.retarget(MAIN, { sessionId: MAIN, applicationInstanceId: 'a-2', agentBindingRevision: '1' })
    await book.settled()
    expect(book.draft(MAIN).state).toBe('conflicted')
    expect(notices.join(' ')).toMatch(/not moved/)
  })
})

describe('the drafts nobody has open', () => {
  it('lists an orphan and a conflict from the store, and moves or discards each', async () => {
    const store = new FakeDraftStore()
    store.save({
      id: null,
      expectedRevision: null,
      sessionId: BUILD,
      applicationInstanceId: null,
      agentBindingRevision: null,
      state: 'orphaned',
      text: 'for a session that went',
      attachments: []
    })
    const book = await opened(store)
    expect(book.draft(BUILD).state).toBe('orphaned')
    expect(book.snapshot().kept.map((kept) => [kept.text, kept.why])).toEqual([
      ['for a session that went', 'orphaned']
    ])

    const row = book.snapshot().kept[0]
    await book.moveTo(row?.id ?? '', MAIN, row?.revision ?? '')
    expect(store.all()[0]).toMatchObject({ sessionId: MAIN, state: 'open' })
    expect(book.snapshot().kept).toEqual([])
    expect(book.draft(MAIN).text).toBe('for a session that went')

    // The composer of the new session holds it now, and discarding it empties that composer.
    const held = book.draft(MAIN).stored
    await book.discard(held?.id ?? '', held?.revision ?? '')
    expect(store.all()).toEqual([])
    expect(book.draft(MAIN).text).toBe('')
  })
})

describe('a draft another window removed', () => {
  it('is kept again when this window writes on, under the identity the store gives it', async () => {
    const store = new FakeDraftStore()
    const one = await opened(store)
    type(one, MAIN, 'begun in the first window')
    await one.settled()
    const [begun] = store.all()
    // The second window sent it, or discarded it.
    store.discard({ id: begun?.id ?? '', expectedRevision: begun?.revision ?? '' })
    expect(store.all()).toEqual([])

    type(one, MAIN, 'begun in the first window, and more')
    await one.settled()
    expect(one.snapshot().problem).toBeNull()
    expect(store.all().map((draft) => draft.text)).toEqual(['begun in the first window, and more'])
    expect(one.draft(MAIN).stored?.id).toBe(store.all()[0]?.id)

    // And it goes on being kept: the next change is written against the new identity.
    type(one, MAIN, 'begun in the first window, and a good deal more')
    await one.settled()
    expect(store.all().map((draft) => draft.text)).toEqual(['begun in the first window, and a good deal more'])
  })
})

describe('moving a draft to another session', () => {
  it('does not move what the store could not be given the newest of', async () => {
    const store = new FakeDraftStore()
    const book = await opened(store)
    book.update(MAIN, (draft) => ({ ...edit(draft, 'older', 1), state: 'conflicted' }))
    await book.settled()
    const id = store.all()[0]?.id ?? ''
    // The newest text cannot be stored.
    store.refuseSaves({ code: 'QUOTA_EXCEEDED', message: 'too large to keep' })
    type(book, MAIN, 'newer, and too large to keep')
    await book.settled()

    await expect(book.moveTo(id, BUILD, '1')).rejects.toMatchObject({ code: 'QUOTA_EXCEEDED' })
    // Nothing moved, and the newer text is still in the composer.
    expect(store.all().map((draft) => [draft.sessionId, draft.text])).toEqual([[MAIN, 'older']])
    expect(book.draft(MAIN).text).toBe('newer, and too large to keep')
  })

  it('can be tried again after another window changed the draft', async () => {
    const store = new FakeDraftStore()
    store.save({
      id: null,
      expectedRevision: null,
      sessionId: BUILD,
      applicationInstanceId: null,
      agentBindingRevision: null,
      state: 'orphaned',
      text: 'for a session that went',
      attachments: []
    })
    const book = await opened(store)
    const shown = book.snapshot().kept[0]
    const id = shown?.id ?? ''
    store.writeAsAnotherWindow(id, { text: 'changed in the other window' })

    await expect(book.moveTo(id, MAIN, shown?.revision ?? '')).rejects.toMatchObject({
      code: 'DRAFT_CONFLICT'
    })
    // The list shows what is stored now, so the person decides on what they see. What this window
    // held is kept too: the other window's version did not replace it.
    await book.settled()
    const listed = book.snapshot().kept
    expect(listed.map((kept) => kept.text).sort()).toEqual([
      'changed in the other window',
      'for a session that went'
    ])
    const theirs = listed.find((kept) => kept.text === 'changed in the other window')
    await book.moveTo(theirs?.id ?? '', MAIN, theirs?.revision ?? '')
    expect(store.all().find((draft) => draft.sessionId === MAIN)).toMatchObject({
      text: 'changed in the other window'
    })
  })
})

describe('a draft another window changed, when this window settles it', () => {
  async function conflicted(): Promise<{
    store: FakeDraftStore
    book: DraftBook
    id: string
    revision: string
  }> {
    const store = new FakeDraftStore()
    const book = await opened(store)
    book.update(MAIN, (draft) => ({
      ...edit(draft, 'for the old conversation', 1),
      target: { sessionId: MAIN, applicationInstanceId: 'a-1', agentBindingRevision: '3' },
      state: 'conflicted'
    }))
    await book.settled()
    const id = store.all()[0]?.id ?? ''
    const revision = store.all()[0]?.revision ?? ''
    store.writeAsAnotherWindow(id, { text: 'theirs' })
    return { store, book, id, revision }
  }

  it('lets a retarget go through on the second try, with the text of this window kept apart from theirs', async () => {
    const { store, book } = await conflicted()
    const notices: string[] = []
    book.onNotice((words) => notices.push(words))

    book.retarget(MAIN, { sessionId: MAIN, applicationInstanceId: 'a-2', agentBindingRevision: '1' })
    await book.settled()
    expect(notices.join(' ')).toMatch(/not moved/)
    expect(book.draft(MAIN).state).toBe('conflicted')

    book.retarget(MAIN, { sessionId: MAIN, applicationInstanceId: 'a-2', agentBindingRevision: '1' })
    await book.settled()
    expect(book.draft(MAIN).state).toBe('bound')
    expect(book.draft(MAIN).text).toBe('for the old conversation')
    // Their version is theirs, and it is listed.
    expect(store.all().map((draft) => draft.text).sort()).toEqual(['for the old conversation', 'theirs'])
    expect(book.snapshot().kept.map((kept) => kept.text)).toContain('theirs')
  })

  it('lets a discard go through on the second try, once the list shows what is stored', async () => {
    const { store, book, id, revision } = await conflicted()
    await expect(book.discard(id, revision)).rejects.toMatchObject({ code: 'DRAFT_CONFLICT' })
    // Nothing was removed, and the text this window holds was not lost to the refusal.
    expect(store.all().map((draft) => draft.text)).toContain('theirs')
    expect(book.draft(MAIN).text).toBe('for the old conversation')
    await book.settled()

    const theirs = book.snapshot().kept.find((kept) => kept.text === 'theirs')
    expect(theirs).toBeDefined()
    await book.discard(theirs?.id ?? '', theirs?.revision ?? '')
    expect(store.all().map((draft) => draft.text)).toEqual(['for the old conversation'])
  })
})

describe('a kept draft of a session that is listed', () => {
  it('is put in that session’s composer, and what the composer held is kept whole beside it', async () => {
    const store = new FakeDraftStore()
    const one = await opened(store)
    type(one, MAIN, 'begun')
    await one.settled()
    const two = await opened(store)
    type(two, MAIN, 'theirs')
    await two.settled()
    type(one, MAIN, 'mine')
    await one.settled()

    const restarted = await opened(store)
    expect(restarted.draft(MAIN).text).toBe('theirs')
    const mine = restarted.snapshot().kept.find((kept) => kept.text === 'mine')
    expect(mine?.why).toBe('copy')

    await restarted.useHere(mine?.id ?? '', mine?.revision ?? '')
    await restarted.settled()
    expect(restarted.draft(MAIN).text).toBe('mine')
    // Their text is not lost to putting mine in the composer.
    expect(restarted.snapshot().kept.map((kept) => [kept.text, kept.why])).toEqual([['theirs', 'other']])
    expect(store.all().map((draft) => draft.text).sort()).toEqual(['mine', 'theirs'])

    // And the choice holds after another restart: mine is the session's, no longer a copy.
    const again = await opened(store)
    expect(again.draft(MAIN).text).toBe('mine')
  })
})

describe('a store that could not be opened', () => {
  it('is opened again when the person asks, and keeps what was typed meanwhile', async () => {
    const store = new FakeDraftStore()
    store.breakOpening()
    const book = await opened(store)
    type(book, MAIN, 'typed while nothing was kept')
    await book.settled()
    expect(book.snapshot().status).toBe('memory-only')

    store.mendOpening()
    await book.hydrate()
    await book.settled()
    expect(book.snapshot().status).toBe('ready')
    expect(book.snapshot().problem).toBeNull()
    expect(store.all().map((draft) => draft.text)).toEqual(['typed while nothing was kept'])
  })
})

describe('what a draft sends the store', () => {
  it('holds no preview of a file, which a stored record cannot afford', async () => {
    const store = new FakeDraftStore()
    const seen: unknown[] = []
    const book = new DraftBook({
      ...portOver(store),
      deviceDraftSave: async (request: DraftSaveRequest) => {
        seen.push(request.attachments)
        return store.save(request)
      }
    })
    await book.hydrate()
    book.update(MAIN, (draft) => ({
      ...edit(draft, 'look at this', 1),
      attachments: [
        {
          localId: 'file-1',
          transferId: '2',
          name: 'diagram.png',
          byteLen: 4096,
          mediaType: 'image/png',
          presentedAsImage: true,
          upload: 'uploaded',
          acceptedUpstream: false,
          handle: {
            transfer_id: '2',
            original_file_name: 'diagram.png',
            byte_len: '4096',
            declared_media_type: 'image/png',
            presented_as_image: true,
            preview: { source_format: 'png', source_width: '64', source_height: '64', width: '32', height: '32', thumbnail: 'AAAA' }
          } as unknown as import('@kalareach/protocol').AttachmentHandle
        }
      ]
    }))
    await book.settled()
    expect(seen).toHaveLength(1)
    expect((seen[0] as { preview: unknown }[])[0]?.preview).toBeNull()
  })
})

describe('a store read while a prompt is on its way', () => {
  for (const outcome of ['taken', 'refused', 'unknown'] as const) {
    it(`does not hand the prompt's stored text back to the composer before it ends (${outcome})`, async () => {
      const store = new FakeDraftStore()
      const book = await opened(store)
      type(book, MAIN, 'send this')
      await book.settled()
      const token = book.beginSend(MAIN)
      type(book, MAIN, '')
      await book.settled()

      // Something reads the store again: a discard in the kept drafts, a copy another window made.
      await book.reload()
      expect(book.draft(MAIN).text).toBe('')
      expect(book.snapshot().kept).toEqual([])

      book.endSend(token, outcome)
      await book.settled()
      const restarted = await opened(store)
      if (outcome === 'taken') {
        expect(store.all()).toEqual([])
        expect(book.draft(MAIN).text).toBe('')
        expect(restarted.draft(MAIN).text).toBe('')
      } else {
        expect(store.all().map((draft) => draft.text)).toEqual(['send this'])
        expect(book.draft(MAIN).text).toBe('send this')
        expect(restarted.draft(MAIN).text).toBe('send this')
      }
    })
  }

  it('keeps the text that was sent when the returned text is edited before the refusal', async () => {
    const store = new FakeDraftStore()
    const book = await opened(store)
    type(book, MAIN, 'send this')
    await book.settled()
    const token = book.beginSend(MAIN)
    type(book, MAIN, '')
    await book.settled()
    await book.reload()
    type(book, MAIN, 'written meanwhile')
    await book.settled()

    book.endSend(token, 'refused')
    await book.settled()
    expect(store.all().map((draft) => draft.text).sort()).toEqual(['send this', 'written meanwhile'])
    expect(book.draft(MAIN).text).toBe('written meanwhile')
  })

  it('keeps both texts when another window changed the stored prompt meanwhile', async () => {
    const store = new FakeDraftStore()
    const book = await opened(store)
    type(book, MAIN, 'send this')
    await book.settled()
    const token = book.beginSend(MAIN)
    type(book, MAIN, '')
    await book.settled()
    store.writeAsAnotherWindow(store.all()[0]?.id ?? '', { text: 'the other window’s' })

    book.endSend(token, 'refused')
    await book.settled()
    expect(book.draft(MAIN).text).toBe('send this')
    expect(store.all().map((draft) => draft.text).sort()).toEqual(['send this', 'the other window’s'])
  })
})

describe('a prompt whose text could not be stored when it ended', () => {
  it('keeps the older stored version, and stores the prompt’s text apart once the store takes it', async () => {
    const store = new FakeDraftStore()
    const book = await opened(store)
    type(book, MAIN, 'send')
    await book.settled()
    store.refuseSaves({ code: 'STORAGE_UNAVAILABLE', message: 'the disk is full' })
    type(book, MAIN, 'send this')
    await book.settled()
    const token = book.beginSend(MAIN)
    type(book, MAIN, '')
    type(book, MAIN, 'the next thing')
    await book.settled()
    // The store still refuses when the prompt ends: nothing may be removed that it holds.
    book.endSend(token, 'refused')
    await book.settled()
    expect(store.all().map((draft) => draft.text)).toEqual(['send'])

    store.refuseSaves(null)
    book.writeAll()
    await book.settled()
    expect(store.all().map((draft) => draft.text).sort()).toEqual(['send this', 'the next thing'])
    expect(book.draft(MAIN).text).toBe('the next thing')
  })
})

describe('a kept draft acted on after the list moved under the person', () => {
  it('moves what the composer holds now, when a save made a copy between the press and the move', async () => {
    const store = new FakeDraftStore()
    const book = await opened(store)
    book.update(MAIN, (draft) => ({ ...edit(draft, 'older', 1), state: 'conflicted' }))
    await book.settled()
    const row = book.snapshot().kept[0]
    store.writeAsAnotherWindow(row?.id ?? '', { text: 'theirs' })
    // The person types, and presses Move before the write that follows has ended: it makes a copy.
    type(book, MAIN, 'newer')
    const moving = book.moveTo(row?.id ?? '', BUILD, row?.revision ?? '')
    await moving
    await book.settled()

    expect(store.all().map((draft) => [draft.sessionId, draft.text]).sort()).toEqual([
      [MAIN, 'theirs'],
      [BUILD, 'newer']
    ])
  })

  it('refuses to discard another window’s version that the row did not show', async () => {
    const store = new FakeDraftStore()
    for (const text of ['older', 'newer']) {
      store.save({
        id: null,
        expectedRevision: null,
        sessionId: MAIN,
        applicationInstanceId: null,
        agentBindingRevision: null,
        state: 'open',
        text,
        attachments: []
      })
    }
    const book = await opened(store)
    const row = book.snapshot().kept[0]
    expect(row?.text).toBe('older')
    // Another window changed it, and this window read the store again before the press.
    store.writeAsAnotherWindow(row?.id ?? '', { text: 'changed since it was shown' })
    await book.reload()

    await expect(book.discard(row?.id ?? '', row?.revision ?? '')).rejects.toMatchObject({
      code: 'DRAFT_CONFLICT'
    })
    expect(store.all().map((draft) => draft.text).sort()).toEqual(['changed since it was shown', 'newer'])
  })

  it('does not reuse an edit number: a composer put in place of another starts above it', async () => {
    const store = new FakeDraftStore()
    const one = await opened(store)
    type(one, MAIN, 'begun')
    await one.settled()
    const two = await opened(store)
    type(two, MAIN, 'theirs')
    await two.settled()
    type(one, MAIN, 'mine')
    await one.settled()
    type(one, MAIN, 'mine, and more')
    await one.settled()

    const restarted = await opened(store)
    const before = restarted.draft(MAIN).revision
    const copy = restarted.snapshot().kept.find((kept) => kept.why === 'copy')
    await restarted.useHere(copy?.id ?? '', copy?.revision ?? '')
    expect(restarted.draft(MAIN).revision).toBeGreaterThan(before)

    // And a composer made new after its draft was moved away starts above where that one ended.
    const row = restarted.snapshot().kept[0]
    const ended = restarted.draft(MAIN).revision
    await restarted.moveTo(restarted.draft(MAIN).stored?.id ?? '', BUILD, restarted.draft(MAIN).stored?.revision ?? '')
    expect(restarted.draft(MAIN).revision).toBeGreaterThan(ended)
    expect(row).toBeDefined()
  })

  it('keeps the text written while a kept draft was being put in the composer', async () => {
    const store = new FakeDraftStore()
    const one = await opened(store)
    type(one, MAIN, 'begun')
    await one.settled()
    const two = await opened(store)
    type(two, MAIN, 'theirs')
    await two.settled()
    type(one, MAIN, 'mine')
    await one.settled()

    const real = portOver(store)
    let release: () => void = () => undefined
    const held = new Promise<void>((resolve) => {
      release = resolve
    })
    let reached: () => void = () => undefined
    const asked = new Promise<void>((resolve) => {
      reached = resolve
    })
    const book = new DraftBook({
      ...real,
      deviceDraftRetarget: async (request: DraftRetargetRequest) => {
        const answer = await real.deviceDraftRetarget(request)
        reached()
        await held
        return answer
      }
    })
    await book.hydrate()
    const copy = book.snapshot().kept.find((kept) => kept.why === 'copy')
    const using = book.useHere(copy?.id ?? '', copy?.revision ?? '')
    await asked
    // The person comes back to the composer and writes while the store is answering.
    type(book, MAIN, 'written while it was being put there')
    release()
    await using
    await book.settled()

    expect(book.draft(MAIN).text).toBe('written while it was being put there')
    // What was written replaced the text it was written over, as writing does, and the kept draft
    // is stored and listed, not lost and not put over it.
    expect(store.all().map((draft) => draft.text).sort()).toEqual([
      'mine',
      'written while it was being put there'
    ])
    expect(book.snapshot().kept.map((kept) => kept.text)).toEqual(['mine'])
  })
})

describe('a retarget of a draft another window removed', () => {
  it('goes through on the second try, with the text kept as a draft again', async () => {
    const store = new FakeDraftStore()
    const book = await opened(store)
    book.update(MAIN, (draft) => ({
      ...edit(draft, 'for the old conversation', 1),
      target: { sessionId: MAIN, applicationInstanceId: 'a-1', agentBindingRevision: '3' },
      state: 'conflicted'
    }))
    await book.settled()
    const [stored] = store.all()
    store.discard({ id: stored?.id ?? '', expectedRevision: stored?.revision ?? '' })

    book.retarget(MAIN, { sessionId: MAIN, applicationInstanceId: 'a-2', agentBindingRevision: '1' })
    await book.settled()
    expect(book.draft(MAIN).state).toBe('conflicted')
    expect(book.draft(MAIN).text).toBe('for the old conversation')

    book.retarget(MAIN, { sessionId: MAIN, applicationInstanceId: 'a-2', agentBindingRevision: '1' })
    await book.settled()
    expect(book.draft(MAIN).state).toBe('bound')
    expect(store.all().map((draft) => [draft.text, draft.state])).toEqual([
      ['for the old conversation', 'open']
    ])
  })
})

/** A port whose answer to one call is held until the test lets it go. */
function holding<K extends 'deviceDraftRetarget' | 'deviceDraftSave' | 'deviceDrafts' | 'deviceDraftDiscard'>(
  store: FakeDraftStore,
  call: K,
  when: 'before' | 'after' = 'after'
): { port: HostPort; reached: Promise<void>; release: () => void } {
  const real = portOver(store) as unknown as Record<K, (...args: never[]) => Promise<unknown>>
  let release: () => void = () => undefined
  const held = new Promise<void>((resolve) => {
    release = resolve
  })
  let reach: () => void = () => undefined
  const reached = new Promise<void>((resolve) => {
    reach = resolve
  })
  let first = true
  const port = {
    ...real,
    [call]: async (...args: never[]) => {
      // Held before the store acts, the call has not changed anything yet when a read comes in;
      // held after, the store has acted and the answer is on its way.
      if (first && when === 'before') {
        first = false
        reach()
        await held
      }
      const answer = await real[call](...args)
      if (first) {
        first = false
        reach()
        await held
      }
      return answer
    }
  } as unknown as HostPort
  return { port, reached, release }
}

describe('a kept draft acted on while the composer is being given another', () => {
  it('does not discard the draft that was put in the composer after the press', async () => {
    const store = new FakeDraftStore()
    const one = await opened(store)
    type(one, MAIN, 'begun')
    await one.settled()
    const two = await opened(store)
    type(two, MAIN, 'theirs')
    await two.settled()
    type(one, MAIN, 'mine')
    await one.settled()

    // A window whose composer holds the other window's text, a conflicted one; "mine" is a copy.
    const gate = holding(store, 'deviceDraftRetarget')
    const book = new DraftBook(gate.port)
    await book.hydrate()
    book.update(MAIN, (draft) => ({ ...draft, state: 'conflicted' }))
    await book.settled()
    const composerRow = book.snapshot().kept.find((kept) => kept.inComposer)
    const copy = book.snapshot().kept.find((kept) => kept.why === 'copy')
    expect(composerRow?.text).toBe('theirs')

    // Put the copy in the composer; before the store answers, discard the composer's row.
    const using = book.useHere(copy?.id ?? '', copy?.revision ?? '')
    await gate.reached
    const discarding = book.discard(composerRow?.id ?? '', composerRow?.revision ?? '')
    gate.release()
    await using
    await expect(discarding).rejects.toMatchObject({ code: 'DRAFT_CONFLICT' })
    await book.settled()

    // The copy the person chose is in the composer and stored; nothing they chose was discarded.
    expect(book.draft(MAIN).text).toBe('mine')
    expect(store.all().map((draft) => draft.text).sort()).toEqual(['mine', 'theirs'])
  })

  it('keeps the text typed while the composer’s own text is being stored before a kept draft is put there', async () => {
    const store = new FakeDraftStore()
    const one = await opened(store)
    type(one, MAIN, 'begun')
    await one.settled()
    const two = await opened(store)
    type(two, MAIN, 'theirs')
    await two.settled()
    type(one, MAIN, 'mine')
    await one.settled()

    const gate = holding(store, 'deviceDraftSave')
    const book = new DraftBook(gate.port)
    await book.hydrate()
    // The composer holds something the store refused, so putting a kept draft there stores it first.
    store.refuseSaves({ code: 'STORAGE_UNAVAILABLE', message: 'the disk is full' })
    type(book, MAIN, 'an edit not stored yet')
    await book.settled()
    store.refuseSaves(null)
    const copy = book.snapshot().kept.find((kept) => kept.why === 'copy')
    const using = book.useHere(copy?.id ?? '', copy?.revision ?? '')
    await gate.reached
    type(book, MAIN, 'typed while it was stored')
    gate.release()
    await using
    await book.settled()

    expect(book.draft(MAIN).text).toBe('typed while it was stored')
    expect(store.all().map((draft) => draft.text).sort()).toEqual(['mine', 'typed while it was stored'])
  })
})

describe('a prompt kept apart from the composer', () => {
  async function refusedWithNewText(): Promise<{
    store: FakeDraftStore
    book: DraftBook
    token: ReturnType<DraftBook['beginSend']>
  }> {
    const store = new FakeDraftStore()
    const book = await opened(store)
    type(book, MAIN, 'send this')
    await book.settled()
    const token = book.beginSend(MAIN)
    type(book, MAIN, '')
    type(book, MAIN, 'the next thing')
    await book.settled()
    return { store, book, token }
  }

  it('is stored again, as a draft of its own, when another window removed it meanwhile', async () => {
    const { store, book, token } = await refusedWithNewText()
    const sent = store.all().find((draft) => draft.text === 'send this')
    store.discard({ id: sent?.id ?? '', expectedRevision: sent?.revision ?? '' })

    book.endSend(token, 'refused')
    await book.settled()
    expect(store.all().map((draft) => draft.text).sort()).toEqual(['send this', 'the next thing'])
    expect(book.snapshot().kept.map((kept) => [kept.text, kept.why])).toEqual([['send this', 'sent']])
  })

  it('is kept beside what another window made of it meanwhile, and neither is lost', async () => {
    const { store, book, token } = await refusedWithNewText()
    const sent = store.all().find((draft) => draft.text === 'send this')
    store.writeAsAnotherWindow(sent?.id ?? '', { text: 'changed by the other window' })

    book.endSend(token, 'refused')
    await book.settled()
    expect(store.all().map((draft) => draft.text).sort()).toEqual([
      'changed by the other window',
      'send this',
      'the next thing'
    ])
  })

  it('is stored when a later write succeeds, with no hide and no reopening to prompt it', async () => {
    const { store, book, token } = await refusedWithNewText()
    store.refuseSaves({ code: 'STORAGE_UNAVAILABLE', message: 'the disk is full' })
    // The record of the prompt is gone from the store, as if it were never stored.
    const sent = store.all().find((draft) => draft.text === 'send this')
    store.discard({ id: sent?.id ?? '', expectedRevision: sent?.revision ?? '' })
    book.endSend(token, 'refused')
    await book.settled()
    expect(store.all().map((draft) => draft.text)).toEqual(['the next thing'])
    expect(book.snapshot().problem).not.toBeNull()

    store.refuseSaves(null)
    // The person goes on writing; that write succeeds, and with it the prompt's text is stored.
    type(book, MAIN, 'the next thing, and more')
    await book.settled()
    await book.settled()
    expect(store.all().map((draft) => draft.text).sort()).toEqual([
      'send this',
      'the next thing, and more'
    ])
    expect(book.snapshot().problem).toBeNull()
  })

  it('is stored when the store is opened again', async () => {
    const { store, book, token } = await refusedWithNewText()
    store.refuseSaves({ code: 'STORAGE_UNAVAILABLE', message: 'the disk is full' })
    const sent = store.all().find((draft) => draft.text === 'send this')
    store.discard({ id: sent?.id ?? '', expectedRevision: sent?.revision ?? '' })
    book.endSend(token, 'refused')
    await book.settled()

    store.refuseSaves(null)
    await book.hydrate()
    await book.settled()
    expect(store.all().map((draft) => draft.text).sort()).toEqual(['send this', 'the next thing'])
    // The failure that was reported is cleared by the success that settled it.
    expect(book.snapshot().problem).toBeNull()
  })

  it('is not retried when the text is too long for the store to keep, and the person can still reach it', async () => {
    const { store, book, token } = await refusedWithNewText()
    store.refuseSaves({ code: 'QUOTA_EXCEEDED', message: 'too large to keep' })
    const sent = store.all().find((draft) => draft.text === 'send this')
    store.discard({ id: sent?.id ?? '', expectedRevision: sent?.revision ?? '' })
    const notices: string[] = []
    book.onNotice((words) => notices.push(words))
    book.endSend(token, 'refused')
    await book.settled()

    expect(notices.join(' ')).toMatch(/too long/i)
    // The text is held for the person to copy, with the kept drafts, after the tab is gone as well.
    expect(book.snapshot().unstored.map((each) => each.text)).toEqual(['send this'])
    expect(keptEntry(book.snapshot())?.title).toBe('One prompt held in this window only')
    store.refuseSaves(null)
    book.writeAll()
    await book.settled()
    // Retrying would never help, so it is not retried.
    expect(store.all().map((draft) => draft.text)).toEqual(['the next thing'])
    expect(book.snapshot().unstored.map((each) => each.text)).toEqual(['send this'])
    expect(book.snapshot().problem).toBeNull()

    book.forgetUnstored(book.snapshot().unstored[0]?.id ?? '')
    expect(book.snapshot().unstored).toEqual([])
  })

  it('holds the whole text of a prompt that was never stored and is too long for the store, with new text in the composer', async () => {
    const store = new FakeDraftStore()
    const book = await opened(store)
    type(book, MAIN, 'send')
    await book.settled()
    // From here the store refuses what it is given for its size: the prompt's text never reached it.
    store.refuseSaves({ code: 'QUOTA_EXCEEDED', message: 'too large to keep' })
    type(book, MAIN, 'send this')
    await book.settled()
    const token = book.beginSend(MAIN)
    type(book, MAIN, '')
    type(book, MAIN, 'the next thing')
    await book.settled()
    book.endSend(token, 'refused')
    await book.settled()

    // The older version it grew from is still stored, and the whole text is held for the person.
    expect(book.snapshot().unstored.map((each) => each.text)).toEqual(['send this'])
    expect(store.all().map((draft) => draft.text)).toEqual(['send'])
    expect(book.draft(MAIN).text).toBe('the next thing')
  })

  it('removes a record it could not remove at the first try once the store takes it', async () => {
    const store = new FakeDraftStore()
    const book = await opened(store)
    type(book, MAIN, 'send this')
    await book.settled()
    const token = book.beginSend(MAIN)
    type(book, MAIN, '')
    await book.settled()
    store.refuseDiscards({ code: 'STORAGE_UNAVAILABLE', message: 'the disk is full' })
    book.endSend(token, 'taken')
    await book.settled()
    // The record stays, out of every composer and list while it is waiting to go.
    expect(store.all().map((draft) => draft.text)).toEqual(['send this'])
    expect(book.draft(MAIN).text).toBe('')
    expect(book.snapshot().kept).toEqual([])
    expect(book.snapshot().problem).not.toBeNull()
    // A read while the record waits to go neither lists it nor gives it to the composer.
    await book.reload()
    expect(book.snapshot().kept).toEqual([])
    expect(book.draft(MAIN).text).toBe('')

    store.refuseDiscards(null)
    book.writeAll()
    await book.settled()
    expect(store.all()).toEqual([])
    expect(book.snapshot().problem).toBeNull()
  })
})

describe('a read of the store that a removal overtook', () => {
  it('does not give a composer a record that was removed after the read began', async () => {
    const store = new FakeDraftStore()
    const real = portOver(store)
    let hold = false
    let release: () => void = () => undefined
    const held = new Promise<void>((resolve) => {
      release = resolve
    })
    let reach: () => void = () => undefined
    const reached = new Promise<void>((resolve) => {
      reach = resolve
    })
    const book = new DraftBook({
      ...real,
      deviceDrafts: async () => {
        const answer = await real.deviceDrafts()
        if (hold) {
          hold = false
          reach()
          await held
        }
        return answer
      }
    })
    await book.hydrate()
    type(book, MAIN, 'send this')
    await book.settled()
    const token = book.beginSend(MAIN)
    type(book, MAIN, '')
    await book.settled()

    // A read starts, and the store answers it with the prompt's record still in it.
    hold = true
    const reading = book.reload()
    await reached
    // The prompt is taken before the read is merged: its record is removed, and the prompt ends.
    book.endSend(token, 'taken')
    await book.settled()
    expect(store.all()).toEqual([])
    release()
    await reading

    // The read that was overtaken is not merged, so the composer does not show a ghost of the prompt.
    expect(book.draft(MAIN).text).toBe('')
    expect(book.snapshot().kept).toEqual([])
  })
})

describe('a composer a window makes for itself', () => {
  it('starts above every number the composer it replaces showed', async () => {
    const store = new FakeDraftStore()
    const book = await opened(store)
    for (const text of ['a', 'ab', 'abc']) type(book, MAIN, text)
    await book.settled()
    const ended = book.draft(MAIN).revision
    const row = book.snapshot().kept
    expect(row).toEqual([])
    book.update(MAIN, (draft) => ({ ...draft, state: 'conflicted' }))
    await book.settled()
    const shown = book.snapshot().kept[0]
    await book.moveTo(shown?.id ?? '', BUILD, shown?.revision ?? '')

    // The phone makes its own empty draft and offers it to the book at the number it starts from.
    book.setDrafts((drafts) => [
      ...drafts,
      startDraft(
        `draft-${MAIN}`,
        { sessionId: MAIN, applicationInstanceId: null, agentBindingRevision: null },
        0
      )
    ])
    expect(book.draft(MAIN).revision).toBeGreaterThan(ended)
  })
})

describe('a draft written in while the store answered a move or a discard', () => {
  it('keeps the text written during a move, and the move keeps what was pressed on', async () => {
    const store = new FakeDraftStore()
    const one = await opened(store)
    type(one, MAIN, 'begun')
    await one.settled()
    const gate = holding(store, 'deviceDraftRetarget')
    const book = new DraftBook(gate.port)
    await book.hydrate()
    book.update(MAIN, (draft) => ({ ...draft, state: 'conflicted' }))
    await book.settled()
    const row = book.snapshot().kept[0]
    const moving = book.moveTo(row?.id ?? '', BUILD, row?.revision ?? '')
    await gate.reached
    type(book, MAIN, 'written while it was moving')
    gate.release()
    await moving
    await book.settled()

    expect(book.draft(MAIN).text).toBe('written while it was moving')
    expect(store.all().map((draft) => [draft.sessionId, draft.text]).sort()).toEqual([
      [MAIN, 'written while it was moving'],
      [BUILD, 'begun']
    ])
    // The next number the composer shows is not one it has shown.
    const before = book.draft(MAIN).revision
    type(book, MAIN, 'and more')
    expect(book.draft(MAIN).revision).toBeGreaterThan(before)
  })

  it('keeps the text written during a discard', async () => {
    const store = new FakeDraftStore()
    const one = await opened(store)
    type(one, MAIN, 'begun')
    await one.settled()
    const gate = holding(store, 'deviceDraftDiscard')
    const book = new DraftBook(gate.port)
    await book.hydrate()
    book.update(MAIN, (draft) => ({ ...draft, state: 'conflicted' }))
    await book.settled()
    const row = book.snapshot().kept[0]
    const discarding = book.discard(row?.id ?? '', row?.revision ?? '')
    await gate.reached
    type(book, MAIN, 'written while it was discarded')
    gate.release()
    await discarding
    await book.settled()

    expect(book.draft(MAIN).text).toBe('written while it was discarded')
    expect(store.all().map((draft) => draft.text)).toEqual(['written while it was discarded'])
  })
})

describe('a failure that belonged to a prompt', () => {
  async function refusedTwice(): Promise<{ store: FakeDraftStore; book: DraftBook }> {
    const store = new FakeDraftStore()
    const book = await opened(store)
    type(book, MAIN, 'send this')
    // The store refuses what it is given when the prompt is sent, and again when it is refused.
    store.refuseSaves({ code: 'STORAGE_UNAVAILABLE', message: 'the disk is full' })
    const token = book.beginSend(MAIN)
    type(book, MAIN, '')
    await book.settled()
    book.endSend(token, 'refused')
    await book.settled()
    return { store, book }
  }

  it('is over, with no hide to say so, once the composer that took the text is stored', async () => {
    const { store, book } = await refusedTwice()
    // The composer shows the text, held in this window only, and the person is told.
    expect(book.draft(MAIN).text).toBe('send this')
    expect(book.snapshot().problem).not.toBeNull()

    store.refuseSaves(null)
    type(book, MAIN, 'send this, shorter')
    await book.settled()
    expect(store.all().map((draft) => draft.text)).toEqual(['send this, shorter'])
    expect(book.snapshot().problem).toBeNull()
  })

  it('is the composer’s own when the text is too long to keep, and goes when the text is short enough', async () => {
    const store = new FakeDraftStore()
    const book = await opened(store)
    type(book, MAIN, 'send this')
    store.refuseSaves({ code: 'QUOTA_EXCEEDED', message: 'too large to keep' })
    const token = book.beginSend(MAIN)
    type(book, MAIN, '')
    await book.settled()
    book.endSend(token, 'refused')
    await book.settled()
    expect(book.snapshot().problem).not.toBeNull()

    store.refuseSaves(null)
    type(book, MAIN, 'short enough')
    await book.settled()
    expect(book.snapshot().problem).toBeNull()
    expect(store.all().map((draft) => draft.text)).toEqual(['short enough'])
  })
})

describe('an older version of a prompt that is being removed', () => {
  it('is not given to a composer by a read that merges before the removal ends', async () => {
    const store = new FakeDraftStore()
    const gate = holding(store, 'deviceDraftDiscard', 'before')
    const book = new DraftBook(gate.port)
    await book.hydrate()
    type(book, MAIN, 'send')
    await book.settled()
    // The write of what is sent fails, so the older version stays the only stored record.
    store.refuseSaves({ code: 'STORAGE_UNAVAILABLE', message: 'the disk is full' })
    type(book, MAIN, 'send this')
    await book.settled()
    const token = book.beginSend(MAIN)
    type(book, MAIN, '')
    await book.settled()
    store.refuseSaves(null)
    book.endSend(token, 'taken')
    await gate.reached
    // A read merges while the removal of the older version is on its way.
    await book.reload()
    expect(book.draft(MAIN).text).toBe('')
    gate.release()
    await book.settled()
    expect(store.all()).toEqual([])
    expect(book.draft(MAIN).text).toBe('')
  })
})

describe('a kept draft an act is working on', () => {
  it('is not given to a composer by a read that merges before the act ends', async () => {
    const store = new FakeDraftStore()
    for (const text of ['older', 'newer']) {
      store.save({
        id: null,
        expectedRevision: null,
        sessionId: MAIN,
        applicationInstanceId: null,
        agentBindingRevision: null,
        state: 'open',
        text,
        attachments: []
      })
    }
    const gate = holding(store, 'deviceDraftDiscard', 'before')
    const book = new DraftBook(gate.port)
    await book.hydrate()
    const row = book.snapshot().kept[0]
    expect(row?.text).toBe('older')
    const discarding = book.discard(row?.id ?? '', row?.revision ?? '')
    await gate.reached
    // The composer is cleared and a read merges: it must not take the draft being discarded.
    book.update(MAIN, (draft) => edit(draft, '', Date.now()))
    await book.settled()
    await book.reload()
    expect(book.draft(MAIN).text).not.toBe('older')
    gate.release()
    await discarding
    await book.settled()
    // The composer was cleared by the person, and the draft discarded is gone: nothing is left.
    expect(store.all()).toEqual([])
    expect(book.draft(MAIN).text).toBe('')
  })
})

/**
 * A book holding a prompt the host did not take and the store will not keep for its size, with
 * another thing typed in the composer meanwhile. The store takes saves again from here on only
 * when a test says so.
 */
async function withAnUnstoredPrompt(
  store: FakeDraftStore,
  port: HostPort = portOver(store)
): Promise<{ readonly book: DraftBook; readonly id: string }> {
  const book = new DraftBook(port)
  await book.hydrate()
  type(book, MAIN, 'send')
  await book.settled()
  store.refuseSaves({ code: 'QUOTA_EXCEEDED', message: 'too large to keep' })
  type(book, MAIN, 'send this')
  await book.settled()
  const token = book.beginSend(MAIN)
  type(book, MAIN, '')
  type(book, MAIN, 'the next thing')
  await book.settled()
  book.endSend(token, 'refused')
  await book.settled()
  const held = book.snapshot().unstored[0]
  expect(held?.text).toBe('send this')
  return { book, id: held?.id ?? '' }
}

describe('an unstored prompt put in its composer', () => {
  it('is copied there, stays listed until the person lets go of it, and the warning is on', async () => {
    const store = new FakeDraftStore()
    const { book, id } = await withAnUnstoredPrompt(store)

    // The composer holds something else: the prompt is not put over it.
    expect(await book.useUnstored(id)).toBe(false)
    expect(book.snapshot().unstored).toHaveLength(1)
    expect(book.draft(MAIN).text).toBe('the next thing')

    type(book, MAIN, '')
    await book.settled()
    // A composer with nothing in it has nothing to keep: no failure is left from what it held.
    expect(book.snapshot().problem).toBeNull()
    expect(await book.useUnstored(id)).toBe(true)
    await book.settled()
    expect(book.draft(MAIN).text).toBe('send this')
    // The store was asked for it and refused: it is in the composer only, and the person is told.
    expect(store.calls.at(-1)).toEqual({ kind: 'save', text: 'send this' })
    expect(store.all().map((draft) => draft.text)).not.toContain('send this')
    expect(book.snapshot().problem).not.toBeNull()
    // The composer is a place the text can be lost from (its session can close with nothing stored
    // for it), so the prompt stays listed, and says a copy is there.
    expect(book.snapshot().unstored).toMatchObject([{ id, text: 'send this', inComposer: true }])

    // Pressing again puts nothing anywhere and changes nothing.
    expect(await book.useUnstored(id)).toBe(false)
    expect(book.draft(MAIN).text).toBe('send this')

    // The person clears the composer: the text is only in the list again, and can be put back.
    type(book, MAIN, '')
    await book.settled()
    expect(book.snapshot().unstored).toMatchObject([{ id, inComposer: false }])
    expect(book.snapshot().problem).toBeNull()

    book.forgetUnstored(id)
    expect(book.snapshot().unstored).toEqual([])
  })

  it('is not put over a file that is still uploading', async () => {
    const store = new FakeDraftStore()
    const { book, id } = await withAnUnstoredPrompt(store)
    type(book, MAIN, '')
    store.refuseSaves(null)
    await book.settled()

    // The composer holds only a file that is still uploading: that is not nothing.
    book.update(MAIN, (draft) => ({
      ...draft,
      attachments: [
        {
          localId: 'file-1',
          transferId: null,
          name: 'diagram.png',
          byteLen: 4096,
          mediaType: 'image/png',
          presentedAsImage: true,
          upload: 'uploading',
          acceptedUpstream: false,
          handle: null
        }
      ]
    }))
    expect(await book.useUnstored(id)).toBe(false)
    expect(book.draft(MAIN).attachments).toHaveLength(1)
    expect(book.snapshot().unstored).toHaveLength(1)
  })

  it('waits for the removal of the stored version the person cleared, and then puts the text there', async () => {
    const store = new FakeDraftStore()
    const real = portOver(store)
    let armed = false
    let release: () => void = () => undefined
    const gate = new Promise<void>((resolve) => {
      release = resolve
    })
    let reach: () => void = () => undefined
    const reached = new Promise<void>((resolve) => {
      reach = resolve
    })
    const port: HostPort = {
      ...real,
      deviceDraftDiscard: async (request: DraftDiscardRequest) => {
        if (armed) {
          armed = false
          reach()
          await gate
        }
        return await real.deviceDraftDiscard(request)
      }
    }
    const { book, id } = await withAnUnstoredPrompt(store, port)
    // The composer's text is stored under a record, and the person clears it: the record is on its
    // way out when the person asks for the prompt to be put there.
    store.refuseSaves(null)
    type(book, MAIN, 'stored for a moment')
    await book.settled()
    expect(store.all().map((draft) => draft.text)).toContain('stored for a moment')
    armed = true
    type(book, MAIN, '')
    await reached

    let answered = false
    const using = book.useUnstored(id).then((put) => {
      answered = true
      return put
    })
    await Promise.resolve()
    expect(answered).toBe(false)
    release()
    expect(await using).toBe(true)
    await book.settled()
    expect(book.draft(MAIN).text).toBe('send this')
    // The version the person cleared is gone, and the text put there is what the store holds now.
    const stored = store.all().map((draft) => draft.text)
    expect(stored).not.toContain('stored for a moment')
    expect(stored).toContain('send this')
  })

  it('is not put in a composer whose stored version could not be removed', async () => {
    const store = new FakeDraftStore()
    const { book, id } = await withAnUnstoredPrompt(store)
    store.refuseSaves(null)
    type(book, MAIN, 'stored for a moment')
    await book.settled()
    store.refuseDiscards({ code: 'STORAGE_UNAVAILABLE', message: 'the disk is full' })
    type(book, MAIN, '')
    await book.settled()

    expect(await book.useUnstored(id)).toBe(false)
    expect(book.draft(MAIN).text).toBe('')
    expect(book.snapshot().unstored).toHaveLength(1)
  })
})

describe('a listed draft whose act failed', () => {
  it('is back in the list when a read hid it while the act ran', async () => {
    const store = new FakeDraftStore()
    for (const text of ['for a session that went', 'newer']) {
      store.save({
        id: null,
        expectedRevision: null,
        sessionId: BUILD,
        applicationInstanceId: null,
        agentBindingRevision: null,
        state: 'orphaned',
        text,
        attachments: []
      })
    }
    const gate = holding(store, 'deviceDraftDiscard', 'before')
    const book = new DraftBook(gate.port)
    await book.hydrate()
    const row = book.snapshot().kept.find((kept) => !kept.inComposer)
    expect(row?.text).toBe('for a session that went')
    const discarding = book.discard(row?.id ?? '', row?.revision ?? '')
    await gate.reached
    // A read while the act runs leaves its row out of the list, as it should.
    await book.reload()
    expect(book.snapshot().kept.some((kept) => kept.text === 'for a session that went')).toBe(false)
    // The store then refuses the discard.
    store.refuseDiscards({ code: 'STORAGE_UNAVAILABLE', message: 'the disk is full' })
    gate.release()
    await expect(discarding).rejects.toMatchObject({ code: 'STORAGE_UNAVAILABLE' })
    await book.settled()
    expect(store.all().map((draft) => draft.text).sort()).toEqual(['for a session that went', 'newer'])
    expect(book.snapshot().kept.some((kept) => kept.text === 'for a session that went')).toBe(true)
  })
})

describe('a listed draft whose act ended while the store would not be read', () => {
  /** A store with two orphaned drafts and a book that has read them. */
  async function twoDrafts(gate: ReturnType<typeof holding>, store: FakeDraftStore) {
    for (const text of ['for a session that went', 'newer']) {
      store.save({
        id: null,
        expectedRevision: null,
        sessionId: BUILD,
        applicationInstanceId: null,
        agentBindingRevision: null,
        state: 'orphaned',
        text,
        attachments: []
      })
    }
    const book = new DraftBook(gate.port)
    await book.hydrate()
    const row = book.snapshot().kept.find((kept) => !kept.inComposer)
    expect(row?.text).toBe('for a session that went')
    return { book, row }
  }

  it('is back in the list when the act failed, though the list cannot be read again', async () => {
    const store = new FakeDraftStore()
    const gate = holding(store, 'deviceDraftDiscard', 'before')
    const { book, row } = await twoDrafts(gate, store)
    const discarding = book.discard(row?.id ?? '', row?.revision ?? '')
    await gate.reached
    await book.reload()
    expect(book.snapshot().kept.some((kept) => kept.text === 'for a session that went')).toBe(false)
    store.refuseDiscards({ code: 'STORAGE_UNAVAILABLE', message: 'the disk is full' })
    store.breakOpening()
    gate.release()
    await expect(discarding).rejects.toMatchObject({ code: 'STORAGE_UNAVAILABLE' })
    await book.settled()
    expect(book.snapshot().kept.some((kept) => kept.text === 'for a session that went')).toBe(true)
  })

  it('stays out of the list when the act worked, though the list cannot be read again', async () => {
    const store = new FakeDraftStore()
    const gate = holding(store, 'deviceDraftDiscard', 'before')
    const { book, row } = await twoDrafts(gate, store)
    const discarding = book.discard(row?.id ?? '', row?.revision ?? '')
    await gate.reached
    await book.reload()
    store.breakOpening()
    gate.release()
    await discarding
    await book.settled()
    expect(store.all().map((draft) => draft.text)).toEqual(['newer'])
    expect(book.snapshot().kept.some((kept) => kept.text === 'for a session that went')).toBe(false)
  })
})

describe('what the entry to the kept drafts says', () => {
  const none = { kept: [], unreadable: 0, unstored: [] } as const
  const one = { id: 'a', sessionId: MAIN, text: 'x', files: 0, inComposer: false }
  const kept = {
    id: 'k',
    revision: '1',
    sessionId: MAIN,
    text: 'y',
    files: 0,
    why: 'other',
    updatedAtMs: 1,
    inComposer: false
  } as const

  it('says text is held in this window only, and does not call it a kept draft', () => {
    expect(keptEntry(none)).toBeNull()
    expect(keptEntry({ ...none, unstored: [one] })).toMatchObject({
      title: 'One prompt held in this window only'
    })
    expect(keptEntry({ ...none, unstored: [one, { ...one, id: 'b' }] })?.title).toBe(
      '2 prompts held in this window only'
    )
  })

  it('says it in the line a phone shows, when there are kept drafts as well', () => {
    expect(keptEntry({ ...none, kept: [kept], unstored: [one] })?.title).toBe(
      'One kept draft, and text held in this window only'
    )
    expect(keptEntry({ ...none, kept: [kept] })?.title).toBe('One kept draft')
  })
})

describe('a composer that holds a file still uploading', () => {
  /** A file the person added whose upload has not ended: nothing a store can keep, but theirs. */
  const UPLOADING = {
    localId: 'file-uploading',
    transferId: null,
    name: 'picture.png',
    byteLen: 12,
    mediaType: 'image/png',
    presentedAsImage: false,
    upload: 'uploading' as const,
    acceptedUpstream: false,
    handle: null
  }

  /** Puts the uploading file in a session's composer, as an attach does. */
  function attach(book: DraftBook, sessionId: string): void {
    book.update(sessionId, (draft) => ({ ...draft, attachments: [...draft.attachments, UPLOADING] }))
  }

  /** The file names a composer shows. */
  const filesOf = (book: DraftBook, sessionId: string): string[] =>
    book.draft(sessionId).attachments.map((file) => file.localId)

  it('is not replaced by the text of a prompt the host refused, which is kept apart instead', async () => {
    const store = new FakeDraftStore()
    const book = await opened(store)
    type(book, MAIN, 'send this')
    await book.settled()
    const token = book.beginSend(MAIN)
    // The composer clears when the person presses Send, and they add a file while it is on its way.
    type(book, MAIN, '')
    attach(book, MAIN)
    await book.settled()

    book.endSend(token, 'refused')
    await book.settled()

    expect(filesOf(book, MAIN)).toEqual(['file-uploading'])
    expect(book.draft(MAIN).text).toBe('')
    expect(book.snapshot().kept.map((kept) => [kept.text, kept.why])).toEqual([['send this', 'sent']])
    expect(store.all().map((draft) => draft.text)).toEqual(['send this'])
  })

  it('is not replaced by a stored draft when the store is read again', async () => {
    const store = new FakeDraftStore()
    const book = await opened(store)
    attach(book, MAIN)
    await book.settled()
    // Another window writes a draft for the same session meanwhile.
    const other = await opened(store)
    type(other, MAIN, 'written in another window')
    await other.settled()

    await book.reload()
    await book.settled()

    expect(filesOf(book, MAIN)).toEqual(['file-uploading'])
    expect(book.draft(MAIN).text).toBe('')
    expect(book.snapshot().kept.map((kept) => kept.text)).toEqual(['written in another window'])
  })

  it('is not replaced by a kept draft the person puts in the composer; the draft stays listed', async () => {
    const store = new FakeDraftStore()
    const one = await opened(store)
    type(one, MAIN, 'begun')
    await one.settled()
    const two = await opened(store)
    type(two, MAIN, 'theirs')
    await two.settled()
    type(one, MAIN, 'mine')
    await one.settled()

    const restarted = await opened(store)
    const mine = restarted.snapshot().kept.find((kept) => kept.text === 'mine')
    // Their text is the composer's, and the person clears it and adds a file before choosing.
    type(restarted, MAIN, '')
    attach(restarted, MAIN)
    await restarted.settled()

    await restarted.useHere(mine?.id ?? '', mine?.revision ?? '')
    await restarted.settled()

    expect(filesOf(restarted, MAIN)).toEqual(['file-uploading'])
    expect(restarted.draft(MAIN).text).toBe('')
    expect(restarted.snapshot().kept.map((kept) => kept.text)).toContain('mine')
    expect(store.all().map((draft) => draft.text)).toContain('mine')
  })

  it('stops a move of the composer’s draft to another session, and keeps the file', async () => {
    const store = new FakeDraftStore()
    const book = await opened(store)
    book.update(MAIN, (draft) => ({ ...edit(draft, 'older', 1), state: 'conflicted' }))
    await book.settled()
    attach(book, MAIN)
    await book.settled()
    const id = store.all()[0]?.id ?? ''
    const notices: string[] = []
    book.onNotice((words) => notices.push(words))

    await book.moveTo(id, BUILD, store.all()[0]?.revision ?? '')
    expect(notices.join(' ')).toMatch(/has not finished uploading/)
    expect(filesOf(book, MAIN)).toEqual(['file-uploading'])
    expect(store.all().map((draft) => [draft.sessionId, draft.text])).toEqual([[MAIN, 'older']])
  })

  it('keeps a file added while a prompt was on its way when the host refuses it and the composer still shows its text', async () => {
    // The phone keeps the sent text in its composer until the answer, and lets a file be picked.
    const store = new FakeDraftStore()
    const book = await opened(store)
    type(book, MAIN, 'send this')
    await book.settled()
    const token = book.beginSend(MAIN)
    await book.settled()
    attach(book, MAIN)
    await book.settled()

    book.endSend(token, 'refused')
    await book.settled()

    expect(book.draft(MAIN).text).toBe('send this')
    expect(filesOf(book, MAIN)).toEqual(['file-uploading'])
  })
})

describe('two windows that hold the same draft', () => {
  /** Two books over one store, as two windows of the application are, both holding one draft. */
  async function twoHolding(): Promise<{ store: FakeDraftStore; one: DraftBook; two: DraftBook }> {
    const store = new FakeDraftStore()
    const one = await opened(store)
    type(one, MAIN, 'send this once')
    await one.settled()
    const two = await opened(store)
    expect(two.draft(MAIN).text).toBe('send this once')
    return { store, one, two }
  }

  it('let only the first claim it to send: the second is refused while the first is on its way', async () => {
    const { one, two } = await twoHolding()
    const first = one.beginSend(MAIN)
    await expect(first.claimed).resolves.toBeUndefined()

    const second = two.beginSend(MAIN)
    await expect(second.claimed).rejects.toMatchObject({ code: 'DRAFT_CONFLICT' })
  })

  it('let only the first send it even when the first has finished, and the second keeps its text', async () => {
    const { store, one, two } = await twoHolding()
    const notices: string[] = []
    two.onNotice((words) => notices.push(words))
    const first = one.beginSend(MAIN)
    await first.claimed
    // The host took the prompt: the stored draft is gone.
    one.endSend(first, 'taken')
    await one.settled()
    expect(store.all()).toEqual([])

    const second = two.beginSend(MAIN)
    await expect(second.claimed).rejects.toMatchObject({ code: 'DRAFT_CONFLICT' })
    two.endSend(second, 'refused')
    await two.settled()
    expect(notices.join(' ')).toMatch(/Another window/)
    // What this window held is not lost to the refusal.
    expect(two.draft(MAIN).text).toBe('send this once')
    expect(store.all().map((draft) => draft.text)).toEqual(['send this once'])
  })

  it('claim nothing twice in one window: a second press after the first ended is a new draft’s', async () => {
    const store = new FakeDraftStore()
    const book = await opened(store)
    type(book, MAIN, 'one')
    await book.settled()
    const first = book.beginSend(MAIN)
    await first.claimed
    book.endSend(first, 'taken')
    await book.settled()
    type(book, MAIN, 'two')
    await book.settled()
    const second = book.beginSend(MAIN)
    await expect(second.claimed).resolves.toBeUndefined()
  })
})

describe('a removal the store would not make', () => {
  it('is made by the next start, and the text of a prompt the host took does not come back', async () => {
    const store = new FakeDraftStore()
    const book = await opened(store)
    type(book, MAIN, 'send this')
    await book.settled()
    const sending = book.beginSend(MAIN)
    await sending.claimed
    type(book, MAIN, '')
    store.refuseDiscards({ code: 'STORAGE_UNAVAILABLE', message: 'the disk refused it' })
    book.endSend(sending, 'taken')
    await book.settled()
    // The prompt was taken and its record could not be removed: it is owed, in the store's ledger.
    expect(store.all().map((draft) => draft.text)).toEqual(['send this'])
    expect(store.pendingRemovals()).toHaveLength(1)

    // The application starts again, with the disk working: the new book finishes the removal.
    store.refuseDiscards(null)
    const restarted = await opened(store)
    await restarted.settled()
    expect(store.all()).toEqual([])
    expect(store.pendingRemovals()).toEqual([])
    expect(restarted.draft(MAIN).text).toBe('')
    expect(restarted.snapshot().kept).toEqual([])
  })

  it('has every removal it owes made at the next start, whichever version of a draft they name', async () => {
    const store = new FakeDraftStore()
    const book = await opened(store)
    type(book, MAIN, 'one')
    await book.settled()
    type(book, MAIN, 'one two')
    await book.settled()
    const held = store.all()[0]
    expect(held?.revision).toBe('2')
    // An older removal is owed besides the newer one, as two failed removals leave them.
    store.markRemoval({ id: held?.id ?? '', expectedRevision: '1' })
    store.markRemoval({ id: held?.id ?? '', expectedRevision: '2' })

    const restarted = await opened(store)
    await restarted.settled()

    expect(store.all()).toEqual([])
    expect(store.pendingRemovals()).toEqual([])
  })
})

describe('a prompt the host is said to have applied after nobody knew what became of it', () => {
  /** A file the person added whose upload has not ended: nothing a store can keep, but theirs. */
  const UPLOADING = {
    localId: 'file-uploading',
    transferId: null,
    name: 'picture.png',
    byteLen: 12,
    mediaType: 'image/png',
    presentedAsImage: false,
    upload: 'uploading' as const,
    acceptedUpstream: false,
    handle: null
  }

  /**
   * Sends 'send this' from a composer and ends the send as of unknown outcome, under the
   * submission `local-1`: the text is back in the composer, under its stored record.
   */
  async function unknownOn(book: DraftBook, after?: () => void): Promise<void> {
    type(book, MAIN, 'send this')
    await book.settled()
    const token = book.beginSend(MAIN)
    await token.claimed
    type(book, MAIN, '')
    after?.()
    book.endSend(token, 'unknown', 'local-1')
    await book.settled()
  }

  it('keeps what is typed while its removal is made, and the text sent goes', async () => {
    const store = new FakeDraftStore()
    const gate = holding(store, 'deviceDraftDiscard')
    const book = new DraftBook(gate.port)
    await book.hydrate()
    await unknownOn(book)
    expect(book.draft(MAIN).text).toBe('send this')

    book.sendSettled('local-1', 'applied')
    await gate.reached
    type(book, MAIN, 'send this, and then more')
    gate.release()
    await book.settled()

    expect(book.draft(MAIN).text).toBe('send this, and then more')
    expect(store.all().map((draft) => draft.text)).toEqual(['send this, and then more'])
  })

  it('keeps a file that is still uploading, and removes only the text that was sent', async () => {
    const store = new FakeDraftStore()
    const book = await opened(store)
    await unknownOn(book)
    book.update(MAIN, (draft) => ({ ...draft, attachments: [...draft.attachments, UPLOADING] }))
    await book.settled()

    book.sendSettled('local-1', 'applied')
    await book.settled()

    expect(book.draft(MAIN).text).toBe('')
    expect(book.draft(MAIN).attachments.map((file) => file.localId)).toEqual(['file-uploading'])
    expect(store.all()).toEqual([])
  })

  it('clears a composer that holds the text in this window only, because the store would not take it', async () => {
    const store = new FakeDraftStore()
    const book = await opened(store)
    store.refuseSaves({ code: 'STORAGE_UNAVAILABLE', message: 'the disk refused it' })
    await unknownOn(book)
    expect(book.draft(MAIN).text).toBe('send this')
    expect(book.draft(MAIN).stored).toBeNull()

    book.sendSettled('local-1', 'applied')
    await book.settled()
    store.refuseSaves(null)
    book.writeAll()
    await book.settled()

    expect(book.draft(MAIN).text).toBe('')
    expect(store.all()).toEqual([])
  })

  describe('whose text was kept apart because the composer held something else', () => {
    /** The prompt is listed with the kept drafts, and the composer holds 'newer'. */
    async function keptApart(book: DraftBook): Promise<void> {
      await unknownOn(book, () => type(book, MAIN, 'newer'))
      expect(book.snapshot().kept.map((kept) => kept.text)).toEqual(['send this'])
    }

    it('is removed from the store and from the list', async () => {
      const store = new FakeDraftStore()
      const book = await opened(store)
      await keptApart(book)

      book.sendSettled('local-1', 'applied')
      await book.settled()

      expect(book.snapshot().kept).toEqual([])
      expect(store.all().map((draft) => draft.text)).toEqual(['newer'])
    })

    it('is left alone when another window changed it and this window has read it again', async () => {
      const store = new FakeDraftStore()
      const book = await opened(store)
      await keptApart(book)
      const kept = book.snapshot().kept[0]
      store.writeAsAnotherWindow(kept?.id ?? '', { text: 'theirs' })
      await book.reload()

      book.sendSettled('local-1', 'applied')
      await book.settled()

      expect(store.all().map((draft) => draft.text).sort()).toEqual(['newer', 'theirs'])
    })

    it('is removed though the report came while the book was listing it', async () => {
      const store = new FakeDraftStore()
      const real = portOver(store)
      let listing = false
      let reach: () => void = () => undefined
      const reached = new Promise<void>((resolve) => {
        reach = resolve
      })
      let release: () => void = () => undefined
      const held = new Promise<void>((resolve) => {
        release = resolve
      })
      const book = new DraftBook({
        ...real,
        deviceDrafts: async () => {
          const answer = await real.deviceDrafts()
          if (listing) {
            listing = false
            reach()
            await held
          }
          return answer
        }
      })
      await book.hydrate()
      // The book tells the person the prompt is kept just before it reads the store to list it.
      book.onNotice(() => {
        listing = true
      })
      type(book, MAIN, 'send this')
      await book.settled()
      const token = book.beginSend(MAIN)
      await token.claimed
      type(book, MAIN, 'newer')
      book.endSend(token, 'unknown', 'local-1')
      await reached

      book.sendSettled('local-1', 'applied')
      release()
      await book.settled()

      expect(book.snapshot().kept).toEqual([])
      expect(store.all().map((draft) => draft.text)).toEqual(['newer'])
    })

    it('is dropped from this window’s memory when the store could not keep it, and is not stored later', async () => {
      const store = new FakeDraftStore()
      const book = await opened(store)
      type(book, MAIN, 'send this')
      await book.settled()
      const token = book.beginSend(MAIN)
      await token.claimed
      type(book, MAIN, 'newer')
      store.breakOpening()
      book.endSend(token, 'unknown', 'local-1')
      await book.settled()
      expect(book.snapshot().problem).not.toBeNull()

      book.sendSettled('local-1', 'applied')
      await book.settled()
      store.mendOpening()
      book.writeAll()
      await book.reload()
      await book.settled()

      expect(book.snapshot().kept).toEqual([])
      expect(book.snapshot().problem).toBeNull()
      expect(store.all().map((draft) => draft.text)).toEqual(['newer'])
    })
  })

  it('is no longer held for a person to copy when the store would never have taken it', async () => {
    const store = new FakeDraftStore()
    const book = await opened(store)
    type(book, MAIN, 'send')
    await book.settled()
    // From here the store refuses what it is given for its size: the prompt's text never reached it.
    store.refuseSaves({ code: 'QUOTA_EXCEEDED', message: 'too large to keep' })
    type(book, MAIN, 'send this')
    await book.settled()
    const token = book.beginSend(MAIN)
    type(book, MAIN, '')
    type(book, MAIN, 'the next thing')
    await book.settled()
    book.endSend(token, 'unknown', 'local-1')
    await book.settled()
    expect(book.snapshot().unstored.map((each) => each.text)).toEqual(['send this'])

    book.sendSettled('local-1', 'applied')
    await book.settled()

    expect(book.snapshot().unstored).toEqual([])
    expect(book.draft(MAIN).text).toBe('the next thing')
  })

  it('leaves nothing stored when the text was sent again by a person who checked, and the first send is the one applied', async () => {
    const store = new FakeDraftStore()
    const book = await opened(store)
    await unknownOn(book)
    // The person checked, and sends the text again: a new prompt, ended as of unknown outcome too.
    const again = book.beginSend(MAIN)
    await again.claimed
    type(book, MAIN, '')
    book.endSend(again, 'unknown', 'local-2')
    await book.settled()
    expect(book.draft(MAIN).text).toBe('send this')

    book.sendSettled('local-1', 'applied')
    await book.settled()

    // The words were done once: they are not in the composer or the store to be sent a third time.
    expect(book.draft(MAIN).text).toBe('')
    expect(store.all()).toEqual([])
    // The second prompt has not been heard of, and what the host says of it later changes nothing.
    book.sendSettled('local-2', 'refused')
    await book.settled()
    expect(book.draft(MAIN).text).toBe('')
    expect(store.all()).toEqual([])
  })

  it('is owed at the version it tried to remove, so the next start removes it', async () => {
    const store = new FakeDraftStore()
    const book = await opened(store)
    await unknownOn(book)
    store.refuseDiscards({ code: 'STORAGE_UNAVAILABLE', message: 'the disk refused it' })

    book.sendSettled('local-1', 'applied')
    await book.settled()
    expect(store.pendingRemovals()).toHaveLength(1)

    store.refuseDiscards(null)
    const restarted = await opened(store)
    await restarted.settled()
    expect(store.all()).toEqual([])
    expect(restarted.draft(MAIN).text).toBe('')
  })
})

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
import { DraftBook } from '../src/model/draft-book'
import { edit } from '../src/model/drafts'

const MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'
const BUILD = '8a7b6c50-22bb-4c3d-8e4f-000000000102'

/** The four members of the port a book calls, over one store. */
function portOver(store: FakeDraftStore): HostPort {
  return {
    deviceDrafts: async () => store.list(),
    deviceDraftSave: async (request: DraftSaveRequest) => store.save(request),
    deviceDraftRetarget: async (request: DraftRetargetRequest) => store.retarget(request),
    deviceDraftDiscard: async (request: DraftDiscardRequest) => store.discard(request)
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
      expect(book.snapshot().kept.map((kept) => [kept.text, kept.why])).toEqual([['send this', 'other']])
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

    const id = book.snapshot().kept[0]?.id ?? ''
    await book.moveTo(id, MAIN)
    expect(store.all()[0]).toMatchObject({ sessionId: MAIN, state: 'open' })
    expect(book.snapshot().kept).toEqual([])
    expect(book.draft(MAIN).text).toBe('for a session that went')

    // The composer of the new session holds it now, and discarding it empties that composer.
    await book.discard(book.draft(MAIN).stored?.id ?? '')
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

    await expect(book.moveTo(id, BUILD)).rejects.toMatchObject({ code: 'QUOTA_EXCEEDED' })
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
    const id = book.snapshot().kept[0]?.id ?? ''
    store.writeAsAnotherWindow(id, { text: 'changed in the other window' })

    await expect(book.moveTo(id, MAIN)).rejects.toMatchObject({ code: 'DRAFT_CONFLICT' })
    // The list shows what is stored now, so the person decides on what they see. What this window
    // held is kept too: the other window's version did not replace it.
    await book.settled()
    const listed = book.snapshot().kept
    expect(listed.map((kept) => kept.text).sort()).toEqual([
      'changed in the other window',
      'for a session that went'
    ])
    const theirs = listed.find((kept) => kept.text === 'changed in the other window')
    await book.moveTo(theirs?.id ?? '', MAIN)
    expect(store.all().find((draft) => draft.sessionId === MAIN)).toMatchObject({
      text: 'changed in the other window'
    })
  })
})

describe('a draft another window changed, when this window settles it', () => {
  async function conflicted(): Promise<{ store: FakeDraftStore; book: DraftBook; id: string }> {
    const store = new FakeDraftStore()
    const book = await opened(store)
    book.update(MAIN, (draft) => ({
      ...edit(draft, 'for the old conversation', 1),
      target: { sessionId: MAIN, applicationInstanceId: 'a-1', agentBindingRevision: '3' },
      state: 'conflicted'
    }))
    await book.settled()
    const id = store.all()[0]?.id ?? ''
    store.writeAsAnotherWindow(id, { text: 'theirs' })
    return { store, book, id }
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
    const { store, book, id } = await conflicted()
    await expect(book.discard(id)).rejects.toMatchObject({ code: 'DRAFT_CONFLICT' })
    // Nothing was removed, and the text this window holds was not lost to the refusal.
    expect(store.all().map((draft) => draft.text)).toContain('theirs')
    expect(book.draft(MAIN).text).toBe('for the old conversation')
    await book.settled()

    const theirs = book.snapshot().kept.find((kept) => kept.text === 'theirs')
    expect(theirs).toBeDefined()
    await book.discard(theirs?.id ?? '')
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

    await restarted.useHere(mine?.id ?? '')
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

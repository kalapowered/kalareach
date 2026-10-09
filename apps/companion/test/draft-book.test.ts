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
  async function sending(
    outcome: 'taken' | 'refused' | 'unknown',
    during?: (book: DraftBook) => void
  ): Promise<{ store: FakeDraftStore; book: DraftBook }> {
    const store = new FakeDraftStore()
    const book = await opened(store)
    type(book, MAIN, 'send this')
    await book.settled()
    const token = book.beginSend(MAIN)
    // The composer clears when the person presses Send.
    type(book, MAIN, '')
    during?.(book)
    await book.settled()
    // While the prompt is on its way the stored draft is exactly what was sent.
    expect(store.all().map((draft) => draft.text)).toEqual(['send this'])
    if (outcome === 'refused') type(book, MAIN, 'send this')
    book.endSend(token, outcome)
    await book.settled()
    return { store, book }
  }

  it('removes the stored draft once the host took the prompt', async () => {
    const { store } = await sending('taken')
    expect(store.all()).toEqual([])
  })

  it('keeps it when the host refused the prompt', async () => {
    const { store, book } = await sending('refused')
    expect(store.all().map((draft) => draft.text)).toEqual(['send this'])
    expect(book.draft(MAIN).text).toBe('send this')
  })

  it('keeps it when nobody knows what became of the prompt', async () => {
    const { store } = await sending('unknown')
    expect(store.all().map((draft) => draft.text)).toEqual(['send this'])
  })

  it('stores what was typed after the press, in place of what was sent, once the host took it', async () => {
    const { store, book } = await sending('taken', (during) => type(during, MAIN, 'the next thing'))
    expect(store.all().map((draft) => draft.text)).toEqual(['the next thing'])
    expect(book.draft(MAIN).text).toBe('the next thing')
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

/**
 * The messages sent over a channel that confirms nothing, as the Kept drafts page shows them
 * (KR-REQ-12.26).
 *
 * These render the real application over the scripted host, whose store of channel messages applies
 * the rules native code applies. The group lists each message whole and never puts one in a
 * composer; a restart is a new render over the same stores. Every case that could send checks that
 * nothing was sent.
 */

import { useEffect } from 'react'
import { act, cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it } from 'vitest'

import { App } from '../src/App'
import { AppProvider, useApp, type Place } from '../src/app/state'
import { FakeChannelMessageStore } from '../src/host/fake-channel-messages'
import { FakeDraftStore } from '../src/host/fake-drafts'
import { fakeHost } from '../src/host/fake'
import type { ChannelMessageKeep, HostPort } from '../src/host/port'
import { ChannelShelf, EMPTY_SHELF, MANY_HOLDS, type ShelfSnapshot } from '../src/model/channel-messages'
import { keptEntry } from '../src/model/draft-book'
import type { InputState, Submission } from '../src/model/receipts'
import type { SessionStates } from '../src/model/sessions'

const MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'
const BUILD = '8a7b6c50-22bb-4c3d-8e4f-000000000102'
const GONE = '8a7b6c50-22bb-4c3d-8e4f-0000000009ff'
const KEPT_PAGE: Place = { view: 'drafts' }
const SENT_AT = '1700000000000'

afterEach(cleanup)

interface World {
  readonly drafts: FakeDraftStore
  readonly messages: FakeChannelMessageStore
}

function world(): World {
  return { drafts: new FakeDraftStore(), messages: new FakeChannelMessageStore() }
}

/** The calls that would send a prompt or write a draft, counted. */
interface Counts {
  submit: number
  queue: number
  draftSave: number
}

/** Hands the test the window's rows of sends, which a part of the page reads and writes. */
function Probe({ give }: { readonly give: (states: SessionStates) => void }): null {
  const { sessions } = useApp()
  useEffect(() => {
    give(sessions)
  }, [give, sessions])
  return null
}

/** A row of this window's, for the record `holdId`, in `state`. */
function rowFor(holdId: string, state: InputState): Submission {
  return { localId: `s-${holdId}`, actionId: null, label: 'a message', text: 'a message', state, createdAtMs: 0, error: null, holdId }
}

function startOver(of: World, place: Place = KEPT_PAGE, wrap?: (port: HostPort) => HostPort) {
  const counts: Counts = { submit: 0, queue: 0, draftSave: 0 }
  const grabbed: { states: SessionStates | null } = { states: null }
  const host = fakeHost({ drafts: of.drafts, channelMessages: of.messages })
  const counted: HostPort = {
    ...host.port,
    composerSubmit: (params) => {
      counts.submit += 1
      return host.port.composerSubmit(params)
    },
    composerQueue: (params) => {
      counts.queue += 1
      return host.port.composerQueue(params)
    },
    deviceDraftSave: (request) => {
      counts.draftSave += 1
      return host.port.deviceDraftSave(request)
    }
  }
  const view = render(
    <AppProvider port={wrap ? wrap(counted) : counted} initialPlace={place}>
      <App />
      <Probe
        give={(held) => {
          grabbed.states = held
        }}
      />
    </AppProvider>
  )
  const states = (): SessionStates => {
    if (grabbed.states === null) throw new Error('the application did not render')
    return grabbed.states
  }
  return { ...host, view, counts, states }
}

/** What the host's store was asked, of one kind. */
const asked = (of: World, kind: string): number => of.messages.calls.filter((call) => call.kind === kind).length

let sequence = 0

/** Keeps a message, as the host's store does after a send that nothing confirmed. */
function keepMessage(of: World, over: Partial<ChannelMessageKeep> = {}): ChannelMessageKeep {
  sequence += 1
  const request: ChannelMessageKeep = {
    actionId: `6a7b6c50-22bb-4c3d-8e4f-${String(sequence).padStart(12, '0')}`,
    holdId: null,
    localId: `s-${String(sequence)}-test`,
    sessionId: MAIN,
    applicationInstanceId: null,
    agentBindingRevision: null,
    environmentId: null,
    hostName: 'studio',
    text: `message ${String(sequence)}`,
    sentAtMs: String(1_700_000_000_000 + sequence),
    drafts: [],
    ...over
  }
  of.messages.keep(request, of.drafts)
  return request
}

function keepHold(of: World, sessionId = MAIN, holdId = `hold-${String((sequence += 1))}`): string {
  of.messages.createHold({
    holdId,
    localId: `s-${holdId}`,
    sessionId,
    applicationInstanceId: null,
    agentBindingRevision: null,
    environmentId: null,
    hostName: 'studio',
    sentAtMs: SENT_AT,
    drafts: []
  })
  return holdId
}

function leaveDraft(of: World, sessionId: string, text: string) {
  return of.drafts.save({
    id: null,
    expectedRevision: null,
    sessionId,
    applicationInstanceId: null,
    agentBindingRevision: null,
    state: 'open',
    text,
    attachments: []
  }).draft
}

const NO_BOOK = { kept: [], unreadable: 0, unstored: [], ledger: 'ok' } as const
const kept = {
  id: 'k',
  revision: '1',
  sessionId: MAIN,
  text: 'y',
  files: 0,
  why: 'other',
  updatedAtMs: 1,
  inComposer: false,
  unread: false
} as const
const message = {
  actionId: 'a',
  holdId: null,
  localId: 'l',
  sessionId: MAIN,
  applicationInstanceId: null,
  agentBindingRevision: null,
  environmentId: null,
  hostName: 'studio',
  sentAtMs: SENT_AT
} as const
const hold = { ...message, holdId: 'h', actionId: null, drafts: [] } as const

function shelf(over: Partial<ShelfSnapshot>): ShelfSnapshot {
  return { ...EMPTY_SHELF, status: 'ready', ...over }
}

describe('the messages kept apart, listed whole on the Kept drafts page', () => {
  it('K1 shows each message with its session line, its host, its time and its whole text', async () => {
    const of = world()
    keepMessage(of, { text: 'first line\nsecond line', hostName: 'studio' })
    keepMessage(of, { sessionId: GONE, text: 'to a session that went', hostName: 'old laptop' })
    startOver(of)
    const entries = await screen.findAllByTestId('channel-message')
    expect(entries).toHaveLength(2)
    const texts = screen.getAllByTestId('channel-message-text').map((each) => each.textContent)
    expect(texts).toEqual(['first line\nsecond line', 'to a session that went'])
    expect(within(entries[0]).getByText(/Session \d+/)).toBeVisible()
    expect(entries[0]).toHaveTextContent('studio')
    expect(entries[0]).toHaveTextContent(`Sent at ${new Date(1_700_000_000_001).toLocaleString()}.`)
    expect(entries[0]).toHaveTextContent(
      'When this was sent, the host could not tell whether Claude Code took it. Check the session before you send it again.'
    )
    // A session the host does not list is said so, with the host the message was sent to.
    expect(entries[1]).toHaveTextContent('A session that is not listed · old laptop')
    expect(screen.getByRole('heading', { name: 'Channel messages' })).toBeVisible()
    expect(screen.getByTestId('channel-messages')).toHaveTextContent(
      'When these were sent, Claude Code did not confirm the messages it takes, so the host could not tell whether they arrived. They stay on this device until you remove them, and nothing here sends them.'
    )
  })

  it('K1b says so when the host cannot be asked which sessions there are', async () => {
    const of = world()
    keepMessage(of)
    startOver(of, KEPT_PAGE, (port) => ({ ...port, sessionList: () => Promise.reject(new Error('out of reach')) }))
    const entry = await screen.findByTestId('channel-message')
    await waitFor(() => {
      expect(entry).toHaveTextContent('Its session cannot be listed now · studio')
    })
  })

  it('K2 puts no message in a composer: not after a reload, not in a fresh window', async () => {
    const of = world()
    const draft = leaveDraft(of, MAIN, 'the text that was sent')
    keepMessage(of, {
      text: 'the text that was sent',
      drafts: [{ id: draft.id, expectedRevision: draft.revision }]
    })
    const first = startOver(of, { view: 'session', sessionId: MAIN, pane: 'semantic' })
    expect(await screen.findByTestId('composer-input')).toHaveValue('')
    first.view.unmount()
    const second = startOver(of, { view: 'session', sessionId: MAIN, pane: 'semantic' })
    expect(await screen.findByTestId('composer-input')).toHaveValue('')
    await act(async () => {
      await Promise.resolve()
    })
    expect(screen.getByTestId('composer-input')).toHaveValue('')
    expect(second.counts).toEqual({ submit: 0, queue: 0, draftSave: 0 })
    expect(of.drafts.all()).toEqual([])
    expect(of.messages.all()).toHaveLength(1)
  })

  it('K3 offers no composer control, no draft write and no send while the group is used', async () => {
    const of = world()
    keepMessage(of)
    keepMessage(of, { sessionId: BUILD })
    const started = startOver(of)
    const group = await screen.findByTestId('channel-messages')
    await waitFor(() => {
      expect(within(group).getAllByTestId('channel-message')).toHaveLength(2)
    })
    expect(within(group).queryByRole('textbox')).toBeNull()
    expect(within(group).queryByTestId('composer-input')).toBeNull()
    const labels = within(group)
      .getAllByRole('button')
      .map((button) => button.textContent)
    expect(labels).toEqual(['Remove', 'Remove'])
    expect(started.counts).toEqual({ submit: 0, queue: 0, draftSave: 0 })
    expect(of.messages.calls.filter((call) => call.kind === 'keep')).toHaveLength(2)
  })

  it('K4 removes a message at its press, and every message of a session with "Remove all"', async () => {
    const of = world()
    const person = userEvent.setup()
    keepMessage(of, { text: 'one' })
    keepMessage(of, { text: 'two' })
    keepMessage(of, { sessionId: BUILD, text: 'other session' })
    startOver(of)
    await screen.findAllByTestId('channel-message')
    // One "Remove all" for the session that has more than one message, and none for a lone message.
    expect(screen.getAllByTestId('channel-session-remove-all')).toHaveLength(1)
    const first = screen.getAllByTestId('channel-message')[0]
    // The first press arms the control and asks the store for nothing; the second removes.
    await person.click(within(first).getByTestId('channel-message-remove'))
    expect(asked(of, 'remove')).toBe(0)
    expect(of.messages.all()).toHaveLength(3)
    expect(within(first).getByTestId('channel-message-remove')).toHaveTextContent('Press again to remove')
    await person.click(within(first).getByTestId('channel-message-remove'))
    await waitFor(() => {
      expect(of.messages.all().map((each) => each.text)).toEqual(['two', 'other session'])
    })
    await waitFor(() => {
      expect(screen.getAllByTestId('channel-message')).toHaveLength(2)
    })
    // The session now has one message left: no "Remove all" for it. Add another and remove the pair.
    expect(screen.queryByTestId('channel-session-remove-all')).toBeNull()
    keepMessage(of, { text: 'three' })
    await act(async () => {
      document.dispatchEvent(new Event('visibilitychange'))
      await Promise.resolve()
    })
    const all = await screen.findByTestId('channel-session-remove-all')
    await person.click(all)
    expect(asked(of, 'remove')).toBe(1)
    expect(of.messages.all()).toHaveLength(3)
    expect(all).toHaveTextContent('Press again to remove all')
    await person.click(all)
    await waitFor(() => {
      expect(of.messages.all().map((each) => each.text)).toEqual(['other session'])
    })
    expect(asked(of, 'remove')).toBe(2)
  })

  it('K4b removes the messages "Remove all" showed and a message kept after the read stays', async () => {
    const of = world()
    const person = userEvent.setup()
    keepMessage(of, { text: 'one' })
    keepMessage(of, { text: 'two' })
    startOver(of)
    const all = await screen.findByTestId('channel-session-remove-all')
    expect(screen.getAllByTestId('channel-message')).toHaveLength(2)
    // Another window keeps a third message of the session. This window has not read it.
    keepMessage(of, { text: 'third, never shown' })
    await person.click(all)
    expect(asked(of, 'remove')).toBe(0)
    await person.click(all)
    await waitFor(() => {
      expect(of.messages.all().map((each) => each.text)).toEqual(['third, never shown'])
    })
    expect(await screen.findByTestId('channel-message-text')).toHaveTextContent('third, never shown')
    expect(asked(of, 'remove')).toBe(1)
  })

  it('K4c ends the armed state of "Remove all" when the list of the session changes', async () => {
    const of = world()
    const person = userEvent.setup()
    keepMessage(of, { text: 'one' })
    keepMessage(of, { text: 'two' })
    startOver(of)
    const all = await screen.findByTestId('channel-session-remove-all')
    await person.click(all)
    expect(all).toHaveTextContent('Press again to remove all')
    keepMessage(of, { text: 'three' })
    await act(async () => {
      document.dispatchEvent(new Event('visibilitychange'))
      await Promise.resolve()
    })
    await waitFor(() => {
      expect(screen.getAllByTestId('channel-message')).toHaveLength(3)
    })
    const again = screen.getByTestId('channel-session-remove-all')
    expect(again).not.toHaveTextContent('Press again')
    await person.click(again)
    expect(asked(of, 'remove')).toBe(0)
    expect(of.messages.all()).toHaveLength(3)
    expect(again).toHaveTextContent('Press again to remove all')
  })

  it('K5 says what could not be read, shows no empty group, and reads again on a failed read', async () => {
    const of = world()
    of.messages.leaveUnreadable('messages', { layout: 2 })
    startOver(of)
    expect(await screen.findByText('Some channel messages could not be read')).toBeVisible()
    expect(
      screen.getByText(
        '2 stored messages could not be read by this version of the application. They were left as they are, and nothing was removed.'
      )
    ).toBeVisible()
    expect(screen.queryByTestId('channel-messages')).toBeNull()
    cleanup()
    const failing = world()
    keepMessage(failing)
    failing.messages.refuseListings({ code: 'STORAGE_UNAVAILABLE', message: 'refused' })
    startOver(failing)
    expect(await screen.findByText('The messages kept on this device could not be read now.')).toBeVisible()
    expect(screen.queryByTestId('channel-message')).toBeNull()
  })

  it('K5b lists a draft with N28 and puts none in a composer while a place that can say it was sent is unread', async () => {
    const of = world()
    leaveDraft(of, MAIN, 'a draft that can be a sent message')
    of.messages.leaveUnreadable('messages', { now: 1 })
    const started = startOver(of)
    const draft = await screen.findByTestId('kept-draft')
    expect(draft).toHaveAttribute('data-why', 'unread')
    expect(within(draft).getByTestId('kept-draft-why')).toHaveTextContent(
      'This device could not read its channel messages, so this draft is not put in a composer by itself. It can be a message that was sent.'
    )
    expect(started.counts).toEqual({ submit: 0, queue: 0, draftSave: 0 })
    cleanup()
    const ledger = world()
    leaveDraft(ledger, MAIN, 'another')
    ledger.messages.damageLedger('unreadable')
    startOver(ledger)
    expect(await screen.findByTestId('kept-draft-why')).toHaveTextContent(
      'This device could not read its list of removals, so this draft is not put in a composer by itself.'
    )
    cleanup()
    const both = world()
    leaveDraft(both, MAIN, 'and another')
    both.messages.leaveUnreadable('messages', { now: 1 })
    both.messages.damageLedger('unreadable')
    startOver(both)
    expect(await screen.findByTestId('kept-draft-why')).toHaveTextContent(
      'This device could not read its channel messages or its list of removals, so this draft is not put in a composer by itself.'
    )
  })

  it('K5b ends the warning for records that could not be read with the ruled words, in both forms', async () => {
    const of = world()
    of.messages.leaveUnreadable('holds', { layout: 1, now: 2 })
    startOver(of)
    expect(await screen.findByText('Some records of messages being sent could not be read')).toBeVisible()
    expect(
      await screen.findByText(
        'A record of a message that was being sent could not be read by this version of the application. It was left as it is. Check your sessions before you send again. 2 records of messages that were being sent could not be read now. Check your sessions before you send again.'
      )
    ).toBeVisible()
  })

  it('K14 treats a newest read that failed as a failed read after one that worked, and keeps what was listed', async () => {
    const of = world()
    const person = userEvent.setup()
    startOver(of, { view: 'sessions' })
    await waitFor(() => {
      expect(of.messages.calls.some((call) => call.kind === 'list')).toBe(true)
    })
    expect(screen.queryByTestId('kept-drafts-entry')).toBeNull()
    of.messages.refuseListings({ code: 'STORAGE_UNAVAILABLE', message: 'refused' })
    await act(async () => {
      document.dispatchEvent(new Event('visibilitychange'))
      await Promise.resolve()
    })
    const line = await screen.findByTestId('kept-drafts-entry')
    expect(line).toHaveTextContent('Channel messages could not be read now.')
    await person.click(within(line).getByRole('button'))
    expect(await screen.findByText('The messages kept on this device could not be read now.')).toBeVisible()
    cleanup()
    const stale = world()
    keepMessage(stale, { text: 'listed before the failure' })
    startOver(stale)
    expect(await screen.findByTestId('channel-message-text')).toHaveTextContent('listed before the failure')
    stale.messages.refuseListings({ code: 'STORAGE_UNAVAILABLE', message: 'refused' })
    await act(async () => {
      document.dispatchEvent(new Event('visibilitychange'))
      await Promise.resolve()
    })
    expect(await screen.findByText('The messages kept on this device could not be read now.')).toBeVisible()
    expect(screen.getByTestId('channel-message-text')).toHaveTextContent('listed before the failure')
  })

  it('K15 says the text could not be read when the read for the page failed after a read without text worked', async () => {
    const of = world()
    const person = userEvent.setup()
    keepMessage(of, { text: 'its text' })
    startOver(of, { view: 'sessions' }, (port) => ({
      ...port,
      deviceChannelMessages: (request) =>
        request.withText === true
          ? Promise.reject(new Error('the text is not readable'))
          : port.deviceChannelMessages(request)
    }))
    const line = await screen.findByTestId('kept-drafts-entry')
    await person.click(within(line).getByRole('button'))
    expect(await screen.findByTestId('channel-message-text-unavailable')).toHaveTextContent(
      'This device could not read the text of this message now.'
    )
    expect(screen.queryByTestId('channel-message-text')).toBeNull()
    expect(screen.getByTestId('channel-message')).toBeVisible()
  })

  it('K16 asks the host for no listing while the page is open until the first read of the drafts has answered', async () => {
    const of = world()
    keepMessage(of, { text: 'read after the drafts' })
    let answer: () => void = () => undefined
    const held = new Promise<void>((resolve) => {
      answer = resolve
    })
    startOver(of, KEPT_PAGE, (port) => ({
      ...port,
      deviceDrafts: async () => {
        await held
        return port.deviceDrafts()
      }
    }))
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 40))
    })
    expect(asked(of, 'list')).toBe(0)
    answer()
    expect(await screen.findByTestId('channel-message-text')).toHaveTextContent('read after the drafts')
    expect(asked(of, 'list')).toBeGreaterThan(0)
  })

  it('K6 reads every mix of drafts, messages, records and what could not be read (pure)', () => {
    const none = { ...NO_BOOK }
    const forms: readonly [string, ReturnType<typeof keptEntry>][] = [
      ['nothing', keptEntry(none, shelf({}))],
      ['ledger', keptEntry({ ...none, ledger: 'damaged' }, shelf({ messages: [message] }))],
      ['ledger and read', keptEntry({ ...none, ledger: 'unreadable' }, shelf({ status: 'failed' }))],
      ['failed read', keptEntry({ ...none, kept: [kept] }, shelf({ status: 'failed' }))],
      [
        'drafts and messages unreadable',
        keptEntry({ ...none, unreadable: 1 }, shelf({ unreadableMessages: { layout: 0, now: 1 } }))
      ],
      [
        'drafts and holds unreadable',
        keptEntry({ ...none, unreadable: 2 }, shelf({ damagedHolds: ['x'] }))
      ],
      ['messages unreadable', keptEntry(none, shelf({ unreadableMessages: { layout: 1, now: 0 }, holds: [hold] }))],
      ['holds unreadable', keptEntry(none, shelf({ unreadableHolds: { layout: 0, now: 1 } }))],
      ['one hold', keptEntry(none, shelf({ holds: [hold] }))],
      ['holds', keptEntry(none, shelf({ holds: [hold, { ...hold, holdId: 'h2' }] }))],
      ['one hold that waits', keptEntry(none, shelf({ holds: [hold] }), 1)],
      ['holds, one that waits', keptEntry(none, shelf({ holds: [hold, { ...hold, holdId: 'h2' }] }), 1)],
      ['holds that wait', keptEntry(none, shelf({ holds: [hold, { ...hold, holdId: 'h2' }] }), 2)],
      ['one message', keptEntry(none, shelf({ messages: [message] }))],
      ['messages', keptEntry(none, shelf({ messages: [message, { ...message, actionId: 'b' }] }))],
      ['draft and message', keptEntry({ ...none, kept: [kept] }, shelf({ messages: [message] }))],
      ['drafts unreadable only', keptEntry({ ...none, unreadable: 1 }, shelf({}))]
    ]
    expect(forms.map(([name, entry]) => [name, entry?.label ?? null, entry?.rest ?? null])).toEqual([
      ['nothing', null, null],
      ['ledger', 'The list of removals for drafts', 'could not be read.'],
      ['ledger and read', 'The list of removals for drafts', 'could not be read.'],
      ['failed read', 'Channel messages', 'could not be read now.'],
      ['drafts and messages unreadable', 'Some drafts and channel messages', 'could not be read.'],
      ['drafts and holds unreadable', 'Some drafts and records of messages being sent', 'could not be read.'],
      ['messages unreadable', 'Some channel messages', 'could not be read.'],
      ['holds unreadable', 'Some records of messages being sent', 'could not be read.'],
      ['one hold', 'One record of a message being sent', 'can be removed on this page.'],
      ['holds', '2 records of messages being sent', 'can be removed on this page.'],
      ['one hold that waits', 'One record of a message being sent', 'is kept on this device.'],
      ['holds, one that waits', '2 records of messages being sent', 'are kept on this device.'],
      ['holds that wait', '2 records of messages being sent', 'are kept on this device.'],
      ['one message', 'One channel message', 'is not in a composer.'],
      ['messages', '2 channel messages', 'are not in a composer.'],
      ['draft and message', 'One kept draft and one channel message', 'are not in a composer.'],
      ['drafts unreadable only', 'Some drafts', 'could not be read.']
    ])
  })

  it('K6b shows the warning that a draft can be a message that was sent beside every reason it is listed, while sources are unknown', async () => {
    const of = world()
    const draftFor = (sessionId: string, state: 'orphaned' | 'conflicted', text: string) =>
      of.drafts.save({
        id: null,
        expectedRevision: null,
        sessionId,
        applicationInstanceId: null,
        agentBindingRevision: null,
        state,
        text,
        attachments: []
      })
    draftFor(MAIN, 'orphaned', 'its session has gone')
    draftFor(BUILD, 'conflicted', 'its conversation changed')
    of.messages.leaveUnreadable('messages', { now: 1 })
    startOver(of)
    const rows = await screen.findAllByTestId('kept-draft')
    expect(rows.map((row) => row.getAttribute('data-why')).sort()).toEqual(['conflicted', 'orphaned'])
    for (const row of rows) {
      expect(within(row).getByTestId('kept-draft-unread')).toHaveTextContent(
        'This device could not read its channel messages, so this draft is not put in a composer by itself. It can be a message that was sent.'
      )
    }
    cleanup()
    const readable = world()
    leaveDraft(readable, MAIN, 'a draft that was never sent')
    leaveDraft(readable, MAIN, 'another draft of the same session')
    startOver(readable)
    expect(await screen.findByTestId('kept-draft')).toHaveAttribute('data-why', 'other')
    expect(screen.queryByTestId('kept-draft-unread')).toBeNull()
  })

  it('K7 shows the line when another window keeps the first message, and the line opens the page', async () => {
    const of = world()
    const person = userEvent.setup()
    startOver(of, { view: 'sessions' })
    await screen.findByText('Sessions', { selector: 'h1' })
    await waitFor(() => {
      expect(of.messages.calls.some((call) => call.kind === 'list')).toBe(true)
    })
    expect(screen.queryByTestId('kept-drafts-entry')).toBeNull()
    keepMessage(of, { text: 'kept by another window' })
    await act(async () => {
      document.dispatchEvent(new Event('visibilitychange'))
      await Promise.resolve()
    })
    const line = await screen.findByTestId('kept-drafts-entry')
    expect(line).toHaveTextContent('One channel message is not in a composer.')
    await person.click(within(line).getByRole('button'))
    expect(await screen.findByTestId('channel-message-text')).toHaveTextContent('kept by another window')
  })

  it('K7b shows the line for each kind alone, and for a failed first read', async () => {
    const holds = world()
    keepHold(holds)
    startOver(holds, { view: 'sessions' })
    expect(await screen.findByTestId('kept-drafts-entry')).toHaveTextContent(
      'One record of a message being sent can be removed on this page.'
    )
    cleanup()
    const unreadable = world()
    unreadable.messages.leaveUnreadable('holds', { layout: 1 })
    startOver(unreadable, { view: 'sessions' })
    expect(await screen.findByTestId('kept-drafts-entry')).toHaveTextContent(
      'Some records of messages being sent could not be read.'
    )
    cleanup()
    const damaged = world()
    damaged.messages.damageLedger('damaged')
    startOver(damaged, { view: 'sessions' })
    expect(await screen.findByTestId('kept-drafts-entry')).toHaveTextContent(
      'The list of removals for drafts could not be read.'
    )
    cleanup()
    const failed = world()
    failed.messages.refuseListings({ code: 'STORAGE_UNAVAILABLE', message: 'refused' })
    const person = userEvent.setup()
    startOver(failed, { view: 'sessions' })
    const line = await screen.findByTestId('kept-drafts-entry')
    expect(line).toHaveTextContent('Channel messages could not be read now.')
    await person.click(within(line).getByRole('button'))
    expect(await screen.findByText('The messages kept on this device could not be read now.')).toBeVisible()
  })

  it('K8 says the group is nearly full from 90% of either bound, and not before', async () => {
    const entries = world()
    entries.messages.lowerLimits({ entries: 10 })
    for (let index = 0; index < 8; index += 1) keepMessage(entries)
    startOver(entries)
    await screen.findAllByTestId('channel-message')
    expect(screen.queryByTestId('channel-messages-full')).toBeNull()
    cleanup()
    keepMessage(entries)
    startOver(entries)
    expect(await screen.findByTestId('channel-messages-full')).toHaveTextContent(
      'Channel messages is nearly full. Remove the messages you do not need.'
    )
    cleanup()
    const bytes = world()
    keepMessage(bytes)
    const used = bytes.messages.list(false).used.bytes
    bytes.messages.lowerLimits({ bytes: Math.ceil(used / 0.89) })
    startOver(bytes)
    await screen.findByTestId('channel-message')
    expect(screen.queryByTestId('channel-messages-full')).toBeNull()
    cleanup()
    bytes.messages.lowerLimits({ bytes: Math.floor(used / 0.9) })
    startOver(bytes)
    expect(await screen.findByTestId('channel-messages-full')).toBeVisible()
  })

  it('K9 resolves a keep on the host’s answer when the listing after it fails', async () => {
    const of = world()
    const { port } = fakeHost({ drafts: of.drafts, channelMessages: of.messages })
    const store = new ChannelShelf(port)
    store.after(Promise.resolve())
    of.messages.refuseListings({ code: 'STORAGE_UNAVAILABLE', message: 'refused' })
    const request = {
      actionId: '6a7b6c50-22bb-4c3d-8e4f-0000000000aa',
      holdId: null,
      localId: 's-k9',
      sessionId: MAIN,
      applicationInstanceId: null,
      agentBindingRevision: null,
      environmentId: null,
      hostName: 'studio',
      text: 'kept',
      sentAtMs: SENT_AT,
      drafts: []
    }
    await expect(store.keep(request)).resolves.toBeUndefined()
    expect(of.messages.all()).toHaveLength(1)
    await store.refresh()
    expect(store.snapshot().status).toBe('failed')
    // A listing that failed after one worked leaves the shelf as it was and marks it stale.
    of.messages.refuseListings(null)
    await store.refresh()
    expect(store.snapshot().messages).toHaveLength(1)
    of.messages.refuseListings({ code: 'STORAGE_UNAVAILABLE', message: 'refused' })
    await store.refresh()
    expect(store.snapshot()).toMatchObject({ status: 'ready', stale: true })
    expect(store.snapshot().messages).toHaveLength(1)
  })

  it('K10 lists a record of a send with N26 and removes it, for a session that went as well', async () => {
    const of = world()
    const person = userEvent.setup()
    keepHold(of, GONE, 'hold-gone')
    keepHold(of, MAIN, 'hold-main')
    startOver(of)
    const records = await screen.findAllByTestId('channel-hold')
    expect(records).toHaveLength(2)
    expect(screen.getByRole('heading', { name: 'Records of messages being sent' })).toBeVisible()
    expect(screen.queryByTestId('channel-holds-many')).toBeNull()
    expect(records[0]).toHaveTextContent(
      'This device has not settled what became of it. Removing this record sends nothing.'
    )
    expect(screen.getByText(/A message to a session that studio no longer lists, pressed at /)).toBeVisible()
    const remove = within(screen.getByText(/A message to a session that studio no longer lists/).closest('li')!).getByTestId(
      'channel-hold-remove'
    )
    await person.click(remove)
    expect(asked(of, 'hold-clear')).toBe(0)
    expect(of.messages.allHolds()).toHaveLength(2)
    expect(remove).toHaveTextContent('Press again to remove')
    await person.click(remove)
    await waitFor(() => {
      expect(of.messages.allHolds().map((each) => each.holdId)).toEqual(['hold-main'])
    })
  })

  it('K10e offers Remove on a record only for a row that is unknown or gone, and removing it drops the row', async () => {
    const of = world()
    const person = userEvent.setup()
    keepHold(of, MAIN, 'hold-waits')
    keepHold(of, MAIN, 'hold-unknown')
    keepHold(of, MAIN, 'hold-no-row')
    const { states } = startOver(of)
    expect(await screen.findAllByTestId('channel-hold')).toHaveLength(3)
    // The first record's row is still waiting for its answer, as a queued or a sent one is.
    act(() => {
      states().update(MAIN, (current) => ({
        ...current,
        submissions: [rowFor('hold-waits', 'queued'), rowFor('hold-unknown', 'unknown')]
      }))
    })
    await waitFor(() => {
      expect(screen.getAllByTestId('channel-hold-remove')).toHaveLength(2)
    })
    let records = screen.getAllByTestId('channel-hold')
    expect(within(records[0]).queryByTestId('channel-hold-remove')).toBeNull()
    act(() => {
      states().update(MAIN, (current) => ({
        ...current,
        submissions: [rowFor('hold-waits', 'sent'), rowFor('hold-unknown', 'unknown')]
      }))
    })
    records = screen.getAllByTestId('channel-hold')
    expect(within(records[0]).queryByTestId('channel-hold-remove')).toBeNull()
    expect(within(records[1]).getByTestId('channel-hold-remove')).toBeVisible()
    expect(within(records[2]).getByTestId('channel-hold-remove')).toBeVisible()
    // A press on an unknown row's record: nothing at the first, then the record and the row go.
    const remove = within(records[1]).getByTestId('channel-hold-remove')
    await person.click(remove)
    expect(asked(of, 'hold-clear')).toBe(0)
    expect(states().submissionsOf(MAIN).map((row) => row.holdId)).toEqual(['hold-waits', 'hold-unknown'])
    await person.click(remove)
    await waitFor(() => {
      expect(of.messages.allHolds().map((each) => each.holdId)).toEqual(['hold-waits', 'hold-no-row'])
    })
    expect(states().submissionsOf(MAIN).map((row) => row.holdId)).toEqual(['hold-waits'])
    // The waiting row is unknown at last: its record can go.
    act(() => {
      states().update(MAIN, (current) => ({ ...current, submissions: [rowFor('hold-waits', 'unknown')] }))
    })
    records = screen.getAllByTestId('channel-hold')
    expect(within(records[0]).getByTestId('channel-hold-remove')).toBeVisible()
  })

  it('K10b keeps a record whose removal the device refused, and says so', async () => {
    const of = world()
    const person = userEvent.setup()
    keepHold(of, MAIN, 'hold-stays')
    startOver(of)
    const record = await screen.findByTestId('channel-hold')
    of.messages.refuseHoldWrites({ code: 'STORAGE_UNAVAILABLE', message: 'refused' })
    await person.click(within(record).getByTestId('channel-hold-remove'))
    await person.click(within(record).getByTestId('channel-hold-remove'))
    expect(await screen.findByText(/This device could not remove this record now\. It may still be in place\. /)).toBeVisible()
    expect(of.messages.allHolds().map((each) => each.holdId)).toEqual(['hold-stays'])
    expect(screen.getByTestId('channel-hold')).toBeVisible()
  })

  it('K10d names the failure of a refused removal in the ruled words, and a record whose session cannot be listed', async () => {
    const of = world()
    const person = userEvent.setup()
    keepMessage(of, { text: 'one' })
    keepMessage(of, { text: 'two' })
    keepHold(of, MAIN, 'hold-main')
    startOver(of, KEPT_PAGE, (port) => ({
      ...port,
      sessionList: () => Promise.reject(new Error('out of reach')),
      deviceChannelMessageRemove: () => Promise.reject(new Error('refused'))
    }))
    expect(await screen.findByText(/A message to a session on studio, which this device cannot reach now, pressed at /)).toBeVisible()
    const first = (await screen.findAllByTestId('channel-message'))[0]
    await person.click(within(first).getByTestId('channel-message-remove'))
    await person.click(within(first).getByTestId('channel-message-remove'))
    expect(await screen.findByText(/This device could not remove this message now\. It may still be in place\. /)).toBeVisible()
    const all = screen.getByTestId('channel-session-remove-all')
    await person.click(all)
    await person.click(all)
    expect(
      await screen.findByText(/This device could not remove all of these messages now\. Some of them may still be in place\. /)
    ).toBeVisible()
    expect(of.messages.all()).toHaveLength(2)
  })

  it('K10f says a removal that failed after the file went may still be in place, and reads the list again', async () => {
    const of = world()
    const person = userEvent.setup()
    keepMessage(of, { text: 'gone before the flush failed' })
    startOver(of)
    const message = await screen.findByTestId('channel-message')
    of.messages.refuseRemovals({ code: 'RESOURCE_UNAVAILABLE', message: 'the folder could not be flushed' }, true)
    const listed = asked(of, 'list')
    await person.click(within(message).getByTestId('channel-message-remove'))
    await person.click(within(message).getByTestId('channel-message-remove'))
    await waitFor(() => {
      expect(
        screen.queryByText(
          'This device could not remove this message now. It may still be in place. the folder could not be flushed'
        )
      ).not.toBeNull()
    })
    // The file went before the flush failed: nothing is left, and the page read the list again and shows that.
    expect(of.messages.all()).toHaveLength(0)
    await waitFor(() => {
      expect(screen.queryByTestId('channel-message')).toBeNull()
    })
    expect(asked(of, 'list')).toBeGreaterThan(listed)
    expect(asked(of, 'remove')).toBe(1)
  })

  it('K10g says a record removed before its flush failed may still be in place, keeps the row, and reads the list again', async () => {
    const of = world()
    const person = userEvent.setup()
    keepHold(of, MAIN, 'hold-unknown')
    const { states } = startOver(of)
    const record = await screen.findByTestId('channel-hold')
    act(() => {
      states().update(MAIN, (current) => ({ ...current, submissions: [rowFor('hold-unknown', 'unknown')] }))
    })
    of.messages.refuseRemovals({ code: 'RESOURCE_UNAVAILABLE', message: 'the folder could not be flushed' }, true)
    const listed = asked(of, 'list')
    await person.click(within(record).getByTestId('channel-hold-remove'))
    await person.click(within(record).getByTestId('channel-hold-remove'))
    await waitFor(() => {
      expect(
        screen.queryByText(
          'This device could not remove this record now. It may still be in place. the folder could not be flushed'
        )
      ).not.toBeNull()
    })
    expect(of.messages.allHolds()).toHaveLength(0)
    await waitFor(() => {
      expect(screen.queryByTestId('channel-hold')).toBeNull()
    })
    expect(asked(of, 'list')).toBeGreaterThan(listed)
    // A list that no longer shows the record is not the answer of a removal that was refused: the row stays.
    expect(states().submissionsOf(MAIN).map((row) => row.holdId)).toEqual(['hold-unknown'])
  })

  it('K10h tells a session list that is still being read from one that failed, in the words of each', async () => {
    const of = world()
    keepHold(of, MAIN, 'hold-main')
    let fail: (failure: Error) => void = () => undefined
    startOver(of, KEPT_PAGE, (port) => ({
      ...port,
      sessionList: () =>
        new Promise((_resolve, reject) => {
          fail = reject
        })
    }))
    const record = await screen.findByTestId('channel-hold')
    expect(record.querySelector('p')?.textContent).toMatch(
      /^A message to a session on studio, pressed at [^]+\. This device has not settled what became of it\. Removing this record sends nothing\.$/
    )
    expect(record.querySelector('p')?.textContent).not.toContain('cannot reach now')
    act(() => {
      fail(new Error('out of reach'))
    })
    await waitFor(() => {
      expect(screen.getByTestId('channel-hold').querySelector('p')?.textContent).toMatch(
        /^A message to a session on studio, which this device cannot reach now, pressed at [^]+\. This device has not settled/
      )
    })
  })

  it('K10i gives the entry line no promise of a control for a record whose row waits, and the removable one keeps its Remove', async () => {
    const of = world()
    const person = userEvent.setup()
    keepHold(of, MAIN, 'hold-waits')
    keepHold(of, MAIN, 'hold-free')
    const { states } = startOver(of, { view: 'sessions' })
    const line = await screen.findByTestId('kept-drafts-entry')
    expect(line).toHaveTextContent('2 records of messages being sent can be removed on this page.')
    act(() => {
      states().update(MAIN, (current) => ({ ...current, submissions: [rowFor('hold-waits', 'queued')] }))
    })
    await waitFor(() => {
      expect(screen.getByTestId('kept-drafts-entry')).toHaveTextContent(
        '2 records of messages being sent are kept on this device.'
      )
    })
    expect(screen.getByTestId('kept-drafts-entry')).not.toHaveTextContent('can be removed on this page.')
    await person.click(within(screen.getByTestId('kept-drafts-entry')).getByRole('button'))
    const records = await screen.findAllByTestId('channel-hold')
    expect(records).toHaveLength(2)
    expect(within(records[0]).queryByTestId('channel-hold-remove')).toBeNull()
    expect(within(records[1]).queryByTestId('channel-hold-remove')).not.toBeNull()
  })

  it('K10c shows the warning from 900 records and not at 899', async () => {
    const below = world()
    for (let index = 0; index < MANY_HOLDS - 1; index += 1) keepHold(below, GONE, `h-${String(index)}`)
    startOver(below)
    await screen.findAllByTestId('channel-hold')
    expect(screen.queryByTestId('channel-holds-many')).toBeNull()
    cleanup()
    keepHold(below, GONE, 'h-last')
    startOver(below)
    expect(await screen.findByTestId('channel-holds-many')).toHaveTextContent(
      'This device keeps many records of messages it has not settled. Each one can hold the next message to its session. Remove the records of sessions you no longer use.'
    )
  }, 60_000)

  it('K11 reads without the text until the page opens, and with it while the page is open', async () => {
    const of = world()
    keepMessage(of, { text: 'secret words' })
    startOver(of, { view: 'sessions' })
    await waitFor(() => {
      expect(of.messages.calls.some((call) => call.kind === 'list')).toBe(true)
    })
    expect(of.messages.calls.filter((call) => call.kind === 'list').every((call) => call.withText === false)).toBe(true)
    cleanup()
    const page = world()
    keepMessage(page, { text: 'secret words' })
    startOver(page)
    expect(await screen.findByTestId('channel-message-text')).toHaveTextContent('secret words')
    expect(page.messages.calls.some((call) => call.kind === 'list' && call.withText === true)).toBe(true)
  })

  it('K12 lists a record that cannot be read by its name, and removes it at its press', async () => {
    const of = world()
    const person = userEvent.setup()
    of.messages.leaveDamagedHolds(['damaged-one'])
    startOver(of)
    const record = await screen.findByTestId('channel-hold-damaged')
    expect(record).toHaveTextContent('damaged-one')
    expect(record).toHaveTextContent(
      'This device cannot read this record of a message that was being sent. It holds every message to a channel session. Removing it sends nothing.'
    )
    await person.click(within(record).getByTestId('channel-hold-damaged-remove'))
    expect(asked(of, 'hold-clear')).toBe(0)
    expect(screen.getByTestId('channel-hold-damaged')).toBeVisible()
    expect(within(record).getByTestId('channel-hold-damaged-remove')).toHaveTextContent('Press again to remove')
    await person.click(within(record).getByTestId('channel-hold-damaged-remove'))
    await waitFor(() => {
      expect(screen.queryByTestId('channel-hold-damaged')).toBeNull()
    })
    expect(asked(of, 'hold-clear')).toBe(1)
  })

  it('K13 shows the set-aside control for a damaged list only, and a set-aside list is read again', async () => {
    const of = world()
    const person = userEvent.setup()
    leaveDraft(of, MAIN, 'a draft the list held back')
    of.messages.damageLedger('damaged')
    const started = startOver(of, { view: 'drafts' })
    const control = await screen.findByTestId('ledger-set-aside')
    expect(within(control).getByTestId('ledger-set-aside-why')).toHaveTextContent(
      'The list of removals this device keeps for drafts is damaged and cannot be read. If you set it aside, this device stops reading it and rebuilds the removals that your kept channel messages name. The other removals in it are lost, so the text of a message that was sent or kept can come back as a draft, in its session’s composer or on this page. Nothing sends it by itself. The old list is kept in a file of its own, not deleted.'
    )
    expect(of.messages.calls.some((call) => call.kind === 'set-aside')).toBe(false)
    await person.click(within(control).getByTestId('ledger-set-aside-button'))
    expect(asked(of, 'set-aside')).toBe(0)
    expect(within(control).getByTestId('ledger-set-aside-button')).toHaveTextContent('Press again to set the list aside')
    await person.click(within(control).getByTestId('ledger-set-aside-button'))
    await waitFor(() => {
      expect(of.messages.calls.filter((call) => call.kind === 'set-aside')).toHaveLength(1)
    })
    await waitFor(() => {
      expect(screen.queryByTestId('ledger-set-aside')).toBeNull()
    })
    // The list is read again: the draft that was held apart is in its composer, and nothing was sent.
    await waitFor(() => {
      expect(screen.getByTestId('kept-drafts-empty')).toBeVisible()
    })
    expect([started.counts.submit, started.counts.queue]).toEqual([0, 0])
  })

  it('K13c says the list is not damaged when another window set it aside, and reads it again', async () => {
    const of = world()
    const person = userEvent.setup()
    of.messages.damageLedger('damaged')
    startOver(of)
    const control = await screen.findByTestId('ledger-set-aside')
    of.messages.damageLedger('ok')
    await person.click(within(control).getByTestId('ledger-set-aside-button'))
    await person.click(within(control).getByTestId('ledger-set-aside-button'))
    expect(await screen.findByText('The list of removals is not damaged, so it was not set aside.')).toBeVisible()
    await waitFor(() => {
      expect(screen.queryByTestId('ledger-set-aside-button')).toBeNull()
    })
  })

  it('K13b offers no set-aside for an unreadable list, and says N30 when the set-aside fails or is not confirmed', async () => {
    const unreadable = world()
    unreadable.messages.damageLedger('unreadable')
    startOver(unreadable)
    expect(await screen.findByText('The list of removals for drafts could not be read')).toBeVisible()
    expect(screen.queryByTestId('ledger-set-aside')).toBeNull()
    cleanup()
    const person = userEvent.setup()
    const failing = world()
    failing.messages.damageLedger('damaged')
    failing.messages.refuseSetAside({ code: 'STORAGE_UNAVAILABLE', message: 'refused' })
    startOver(failing)
    await person.click(await screen.findByTestId('ledger-set-aside-button'))
    await person.click(await screen.findByTestId('ledger-set-aside-button'))
    expect(await screen.findByTestId('ledger-set-aside-note')).toHaveTextContent(
      'This device could not set the list aside. The original list is still in place.'
    )
    cleanup()
    const unconfirmed = world()
    unconfirmed.messages.damageLedger('damaged')
    unconfirmed.messages.leaveSetAsideUnconfirmed()
    startOver(unconfirmed)
    await person.click(await screen.findByTestId('ledger-set-aside-button'))
    await person.click(await screen.findByTestId('ledger-set-aside-button'))
    expect(await screen.findByTestId('ledger-set-aside-note')).toHaveTextContent(
      'The list was set aside, but this device could not yet confirm that on disk. It will try again.'
    )
    expect(unconfirmed.messages.calls.filter((call) => call.kind === 'set-aside')).toHaveLength(1)
  })
})
